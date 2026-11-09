//! The real transport over russh: one lazy connection per node, kept alive and closed when idle.
//! Guests get a connection of their own for each call: their credentials and host keys are not
//! those of the node, and nothing is gained by keeping them open.

use super::known_hosts::{HostKeyCheck, host_key_algorithms, parse_public_key_lines, verify_host_key};
use super::quote::sh_quote;
use super::sftp::Sftp;
use super::{ExecOptions, ExecResult, GuestEndpoint, HostKeyInfo, ShellChannel, ShellCommand, ShellEvent, ShellInput, ShellOptions, SftpSession, SshTarget, SshTransport};
use crate::config::{HostKeyPolicy, InstanceConfig};
use crate::errors::{PveError, Result, kind};
use crate::proxmox::nodes::NodeResolver;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelStream, Disconnect, Sig};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::{CancellationToken, DropGuard};

#[derive(Debug, Clone, Copy)]
pub struct TransportOptions {
    /// A node connection with no channel open is closed after this long.
    pub idle_ms: u64,
    /// Channels at a time on one connection. OpenSSH allows 10 by default.
    pub max_channels: usize,
    pub keepalive_ms: u64,
    pub connect_timeout_ms: u64,
    /// Between the signal to a timed out command and closing its channel.
    pub kill_grace_ms: u64,
}

impl Default for TransportOptions {
    fn default() -> Self {
        TransportOptions { idle_ms: 60_000, max_channels: 8, keepalive_ms: 15_000, connect_timeout_ms: 20_000, kill_grace_ms: 2_000 }
    }
}

/// A command past its cap goes on, so that its effect and exit code are not lost. Past this, it is stopped.
const DRAIN_FACTOR: u64 = 16;
const MIN_DRAIN_BYTES: u64 = 64 * 1024 * 1024;

/// The host said no to a new channel. sshd frees a session slot some time after the channel has
/// closed, so that a burst can go over MaxSessions with fewer commands than that running. Nothing
/// ran, so it is worth waiting a moment. These add up to 3 seconds.
const CHANNEL_RETRY_MS: [u64; 6] = [50, 150, 300, 500, 1000, 1000];

const OFF_WARNING: &str = "[pvemcp] warning: PROXMOX_SSH_HOST_KEY_POLICY=off: SSH host keys are not verified, so a host in the middle would go unnoticed.";

/// Why a run did not give a result.
enum RunError {
    /// The channel never opened and the connection is gone: nothing ran, trying again is safe.
    NotStarted(String),
    /// The host refused the channel: nothing ran.
    Refused(String),
    Failed(PveError),
}

impl From<PveError> for RunError {
    fn from(e: PveError) -> Self {
        RunError::Failed(e)
    }
}

/// Called once per instance, on first use.
pub fn create_ssh_transport(instance: Arc<InstanceConfig>, nodes: Arc<NodeResolver>) -> Arc<dyn SshTransport> {
    Arc::new(PooledSshTransport::new(instance, nodes, options_from_env(std::env::var("PVEMCP_TEST_SSH_TRANSPORT").ok().as_deref())))
}

/// Timings and limits for the black-box tests, which drive the binary: they need a pool that goes
/// idle in 50 ms rather than a minute. A JSON object of idleMs, maxChannels, keepaliveMs,
/// connectTimeoutMs and killGraceMs; anything missing or unreadable keeps its default. Not
/// documented for operators on purpose.
fn options_from_env(text: Option<&str>) -> TransportOptions {
    let mut options = TransportOptions::default();
    let Some(Value::Object(given)) = text.and_then(|t| serde_json::from_str::<Value>(t).ok()) else { return options };
    let number = |key: &str| given.get(key).and_then(Value::as_u64);
    if let Some(n) = number("idleMs") {
        options.idle_ms = n;
    }
    if let Some(n) = number("maxChannels").filter(|n| *n > 0) {
        options.max_channels = n as usize;
    }
    if let Some(n) = number("keepaliveMs") {
        options.keepalive_ms = n;
    }
    if let Some(n) = number("connectTimeoutMs") {
        options.connect_timeout_ms = n;
    }
    if let Some(n) = number("killGraceMs") {
        options.kill_grace_ms = n;
    }
    options
}

// ---------------------------------------------------------------------------------------------
// One connection.

/// The russh side of a connection: the verdict on the host key, and the end of the session.
struct ClientHandler {
    check: HostKeyCheck,
    verdict: Arc<Mutex<Option<PveError>>>,
    host_key: Arc<Mutex<Option<HostKeyInfo>>>,
    /// The session task owns the handler: when it ends, for whatever reason, this fires.
    _closed: DropGuard,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, presented: &PublicKeyOrCertificate) -> std::result::Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
            // Never asked for: certificates are not advertised.
            *self.verdict.lock().unwrap() = Some(PveError::new(kind::HOST_KEY_UNKNOWN, format!("{} ({}:{}) presented a host certificate, which this server does not check.", self.check.label, self.check.host, self.check.port)));
            return Ok(false);
        };
        let blob = match key.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                *self.verdict.lock().unwrap() = Some(PveError::new(kind::HOST_KEY_UNKNOWN, format!("The host key of {} cannot be read: {e}", self.check.label)));
                return Ok(false);
            }
        };
        match verify_host_key(&self.check, &blob) {
            Ok(info) => {
                *self.host_key.lock().unwrap() = Some(info);
                Ok(true)
            }
            Err(e) => {
                *self.verdict.lock().unwrap() = Some(e);
                Ok(false)
            }
        }
    }
}

struct Slots {
    active: usize,
    idle: Option<tokio::task::JoinHandle<()>>,
}

struct Connection {
    id: u64,
    handle: Handle<ClientHandler>,
    host_key: HostKeyInfo,
    /// Cancelled when the session ends, or when this side ends it.
    closed: CancellationToken,
    slots: Mutex<Slots>,
    wake: Notify,
    max_channels: usize,
    idle_ms: u64,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.closed.is_cancelled() || self.handle.is_closed()
    }

    async fn acquire(self: &Arc<Self>) {
        loop {
            let woken = self.wake.notified();
            {
                let mut slots = self.slots.lock().unwrap();
                if let Some(timer) = slots.idle.take() {
                    timer.abort();
                }
                if slots.active < self.max_channels || self.is_closed() {
                    slots.active += 1;
                    return;
                }
            }
            tokio::select! {
                _ = woken => {}
                _ = self.closed.cancelled() => {}
            }
        }
    }

    /// Keeps one more slot than the caller took with acquire: for what outlives its opening, such as SFTP.
    fn acquire_held(&self) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(timer) = slots.idle.take() {
            timer.abort();
        }
        slots.active += 1;
    }

    fn release(self: &Arc<Self>) {
        let idle = {
            let mut slots = self.slots.lock().unwrap();
            slots.active = slots.active.saturating_sub(1);
            slots.active == 0
        };
        self.wake.notify_one();
        if idle {
            self.arm_idle();
        }
    }

    fn arm_idle(self: &Arc<Self>) {
        if self.is_closed() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let weak = Arc::downgrade(self);
        let idle_ms = self.idle_ms;
        let timer = runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(idle_ms)).await;
            if let Some(conn) = weak.upgrade() {
                conn.end().await;
            }
        });
        let mut slots = self.slots.lock().unwrap();
        if let Some(old) = slots.idle.replace(timer) {
            old.abort();
        }
    }

    /// Ends the session: whatever runs on it is cut.
    async fn end(&self) {
        self.closed.cancel();
        self.wake.notify_waiters();
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }

    /// end() for where nothing can be awaited.
    fn end_soon(self: &Arc<Self>) {
        self.closed.cancel();
        self.wake.notify_waiters();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let conn = self.clone();
            runtime.spawn(async move { conn.end().await });
        }
    }
}

/// A slot of a connection, given back when dropped, whatever ended the call.
struct SlotGuard(Arc<Connection>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

// ---------------------------------------------------------------------------------------------
// Connecting.

struct ConnectSpec {
    label: String,
    host: String,
    port: u16,
    username: String,
    /// The text of the key file, already read.
    key: Option<String>,
    passphrase: Option<String>,
    /// For password and keyboard-interactive.
    password: Option<String>,
    /// Socket path, or "pageant".
    agent: Option<String>,
    check: HostKeyCheck,
}

enum Failure {
    /// The name did not resolve.
    NotFound,
    Io(std::io::Error),
    Ssh(russh::Error),
    AuthRefused,
}

impl From<russh::Error> for Failure {
    fn from(e: russh::Error) -> Self {
        Failure::Ssh(e)
    }
}

/// The code Node gave an error of the socket, which the messages used to show.
fn errno(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    let code = match e.kind() {
        ConnectionRefused => "ECONNREFUSED",
        ConnectionReset => "ECONNRESET",
        ConnectionAborted => "ECONNABORTED",
        TimedOut => "ETIMEDOUT",
        HostUnreachable => "EHOSTUNREACH",
        NetworkUnreachable => "ENETUNREACH",
        AddrNotAvailable => "EADDRNOTAVAIL",
        BrokenPipe => "EPIPE",
        NotFound => "ENOENT",
        PermissionDenied => "EACCES",
        IsADirectory => "EISDIR",
        _ => return e.to_string(),
    };
    code.to_string()
}

fn map_connect_error(failure: Failure, spec: &ConnectSpec) -> PveError {
    let place = format!("{} ({}:{})", spec.label, spec.host, spec.port);
    let auth_refused = || {
        PveError::new(kind::SSH_AUTH_FAILED, format!("SSH login as {} to {place} was refused.", spec.username))
            .hint("Do not retry with the same credentials. The operator has to check the SSH key or password configured here.")
    };
    let timed_out = || PveError::new(kind::SSH_TIMEOUT, format!("No SSH handshake from {place} in time.")).hint("The host may be down, or a firewall may be dropping the SSH port.");
    let unreachable = |what: String| {
        PveError::new(kind::SSH_UNREACHABLE, format!("Could not reach {place} over SSH: {what}.")).hint("Check that the host is up and, for a node, that PROXMOX_SSH_NODES gives the right address.")
    };
    let closed = || PveError::new(kind::SSH_UNREACHABLE, format!("{place} closed the connection during the SSH handshake."));
    match failure {
        Failure::AuthRefused => auth_refused(),
        Failure::NotFound => unreachable("ENOTFOUND".into()),
        Failure::Io(e) | Failure::Ssh(russh::Error::IO(e)) => match e.kind() {
            std::io::ErrorKind::TimedOut => timed_out(),
            std::io::ErrorKind::UnexpectedEof => closed(),
            _ => unreachable(errno(&e)),
        },
        Failure::Ssh(russh::Error::HUP | russh::Error::Disconnect | russh::Error::SendError) => closed(),
        Failure::Ssh(russh::Error::ConnectionTimeout) => timed_out(),
        Failure::Ssh(e) => unreachable(e.to_string()),
    }
}

/// A key that cannot be used is a matter of configuration, whatever the server would say.
fn read_key(path: &str, label: &str) -> Result<String> {
    std::fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).map_err(|e| PveError::config(format!("The SSH key file for {label} cannot be read: {}.", errno(&e))))
}

async fn tcp_connect(host: &str, port: u16) -> std::result::Result<tokio::net::TcpStream, Failure> {
    let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await.map_err(|_| Failure::NotFound)?.collect();
    let mut last = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.map(Failure::Io).unwrap_or(Failure::NotFound))
}

async fn rsa_hash(handle: &Handle<ClientHandler>, algorithm: Algorithm) -> Option<russh::keys::HashAlg> {
    if !algorithm.is_rsa() {
        return None;
    }
    handle.best_supported_rsa_hash().await.ok().flatten().flatten()
}

async fn agent_signs<S>(handle: &mut Handle<ClientHandler>, user: &str, mut agent: AgentClient<S>) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(identities) = agent.request_identities().await else { return false };
    for identity in identities {
        let AgentIdentity::PublicKey { key, .. } = identity else { continue };
        let hash = rsa_hash(handle, key.algorithm()).await;
        if let Ok(AuthResult::Success) = handle.authenticate_publickey_with(user, key, hash, &mut agent).await {
            return true;
        }
    }
    false
}

/// An agent that cannot be reached is a method that did not work: the others are still tried.
async fn agent_auth(handle: &mut Handle<ClientHandler>, user: &str, path: &str) -> bool {
    #[cfg(unix)]
    {
        match AgentClient::connect_uds(path).await {
            Ok(agent) => agent_signs(handle, user, agent).await,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        if path.eq_ignore_ascii_case("pageant") {
            match AgentClient::connect_pageant().await {
                Ok(agent) => agent_signs(handle, user, agent).await,
                Err(_) => false,
            }
        } else {
            match AgentClient::connect_named_pipe(path).await {
                Ok(agent) => agent_signs(handle, user, agent).await,
                Err(_) => false,
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, user, path);
        false
    }
}

/// In the order of ssh2: none, password, publickey, agent, keyboard-interactive.
async fn authenticate(handle: &mut Handle<ClientHandler>, spec: &ConnectSpec, key: Option<PrivateKey>) -> std::result::Result<(), Failure> {
    let user = spec.username.as_str();
    if let AuthResult::Success = handle.authenticate_none(user).await? {
        return Ok(());
    }
    if let Some(password) = &spec.password
        && let AuthResult::Success = handle.authenticate_password(user, password).await?
    {
        return Ok(());
    }
    if let Some(key) = key {
        let hash = rsa_hash(handle, key.algorithm()).await;
        if let AuthResult::Success = handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await? {
            return Ok(());
        }
    }
    if let Some(agent) = &spec.agent
        && agent_auth(handle, user, agent).await
    {
        return Ok(());
    }
    if let Some(password) = &spec.password {
        let mut reply = handle.authenticate_keyboard_interactive_start(user, None::<String>).await?;
        // A password goes to a single prompt only: anything else is not a password prompt.
        for _ in 0..8 {
            match reply {
                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                KeyboardInteractiveAuthResponse::Failure { .. } => break,
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers = if prompts.len() == 1 { vec![password.clone()] } else { Vec::new() };
                    reply = handle.authenticate_keyboard_interactive_respond(answers).await?;
                }
            }
        }
    }
    Err(Failure::AuthRefused)
}

// ---------------------------------------------------------------------------------------------
// The transport.

#[derive(Default)]
struct State {
    pool: HashMap<String, Arc<Connection>>,
    connecting: HashMap<String, Shared<BoxFuture<'static, Result<Arc<Connection>>>>>,
    /// Dedicated to one session or one guest call.
    dedicated: HashMap<u64, Arc<Connection>>,
}

struct Inner {
    instance: Arc<InstanceConfig>,
    nodes: Arc<NodeResolver>,
    options: TransportOptions,
    state: Mutex<State>,
    closing: AtomicBool,
    warned_off: AtomicBool,
    next_id: AtomicU64,
}

pub struct PooledSshTransport {
    inner: Arc<Inner>,
}

impl PooledSshTransport {
    pub fn new(instance: Arc<InstanceConfig>, nodes: Arc<NodeResolver>, options: TransportOptions) -> Self {
        PooledSshTransport {
            inner: Arc::new(Inner {
                instance,
                nodes,
                options,
                state: Mutex::new(State::default()),
                closing: AtomicBool::new(false),
                warned_off: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
            }),
        }
    }
}

fn shutting_down() -> PveError {
    PveError::new(kind::SSH_UNREACHABLE, "This server is shutting down.")
}

impl Inner {
    fn with_sudo(&self, text: &str) -> Result<String> {
        let ssh = &self.instance.ssh;
        if ssh.sudo && ssh.user != "root" { Ok(format!("sudo -n sh -c {}", sh_quote(text)?)) } else { Ok(text.to_string()) }
    }

    fn add_dedicated(self: &Arc<Self>, conn: &Arc<Connection>) {
        self.state.lock().unwrap().dedicated.insert(conn.id, conn.clone());
        let (weak, token, id) = (Arc::downgrade(self), conn.closed.clone(), conn.id);
        tokio::spawn(async move {
            token.cancelled().await;
            if let Some(me) = weak.upgrade() {
                me.state.lock().unwrap().dedicated.remove(&id);
            }
        });
    }

    fn remove_dedicated(&self, id: u64) {
        self.state.lock().unwrap().dedicated.remove(&id);
    }

    async fn connection(self: &Arc<Self>, node: &str) -> Result<Arc<Connection>> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(shutting_down());
        }
        let pending = {
            let mut state = self.state.lock().unwrap();
            if let Some(live) = state.pool.get(node) {
                if !live.is_closed() {
                    return Ok(live.clone());
                }
                state.pool.remove(node);
            }
            match state.connecting.get(node) {
                Some(pending) => pending.clone(),
                None => {
                    let (me, name) = (self.clone(), node.to_string());
                    let pending = async move {
                        let result = me.connect_to_node(&name).await;
                        let mut state = me.state.lock().unwrap();
                        state.connecting.remove(&name);
                        let conn = result?;
                        if me.closing.load(Ordering::SeqCst) {
                            drop(state);
                            conn.end_soon();
                            return Err(shutting_down());
                        }
                        state.pool.insert(name.clone(), conn.clone());
                        let (weak, token, id) = (Arc::downgrade(&me), conn.closed.clone(), conn.id);
                        tokio::spawn(async move {
                            token.cancelled().await;
                            if let Some(me) = weak.upgrade() {
                                let mut state = me.state.lock().unwrap();
                                if state.pool.get(&name).is_some_and(|c| c.id == id) {
                                    state.pool.remove(&name);
                                }
                            }
                        });
                        Ok(conn)
                    }
                    .boxed()
                    .shared();
                    state.connecting.insert(node.to_string(), pending.clone());
                    pending
                }
            }
        };
        pending.await
    }

    /// A channel that did not open costs some more tries; once one has opened, nobody knows what ran.
    async fn with_channel<'a, T>(self: &'a Arc<Self>, node: &'a str, what: &str, run: impl Fn(Arc<Connection>) -> BoxFuture<'a, std::result::Result<T, RunError>>) -> Result<T> {
        let mut lost = 0;
        let mut refused = 0;
        loop {
            let conn = self.connection(node).await?;
            conn.acquire().await;
            let slot = SlotGuard(conn.clone());
            let outcome = run(conn.clone()).await;
            drop(slot);
            match outcome {
                Ok(value) => return Ok(value),
                Err(RunError::Failed(e)) => return Err(e),
                Err(RunError::NotStarted(message)) => {
                    {
                        let mut state = self.state.lock().unwrap();
                        if state.pool.get(node).is_some_and(|c| c.id == conn.id) {
                            state.pool.remove(node);
                        }
                    }
                    lost += 1;
                    if lost > 1 {
                        return Err(PveError::new(kind::SSH_UNREACHABLE, format!("Could not open {what} on {node}: {message}")).hint("Nothing was run."));
                    }
                }
                Err(RunError::Refused(message)) => {
                    let Some(wait) = CHANNEL_RETRY_MS.get(refused) else {
                        return Err(PveError::new(kind::SSH_UNREACHABLE, format!("The host refused {what}: {message}")).hint("Nothing was run. It may have reached its session limit (MaxSessions)."));
                    };
                    refused += 1;
                    tokio::time::sleep(Duration::from_millis(*wait)).await;
                }
            }
        }
    }

    async fn connect_to_node(self: &Arc<Self>, node: &str) -> Result<Arc<Connection>> {
        let ssh = &self.instance.ssh;
        let host = self.nodes.ssh_host(node).await?;
        if ssh.host_key_policy == HostKeyPolicy::Off && !self.warned_off.swap(true, Ordering::SeqCst) {
            eprintln!("{OFF_WARNING}");
        }
        let label = format!("node {node}");
        let key = ssh.key_file.as_deref().map(|path| read_key(path, &label)).transpose()?;
        let check = HostKeyCheck {
            label: label.clone(),
            host: host.clone(),
            port: ssh.port,
            policy: ssh.host_key_policy,
            known_hosts_file: ssh.known_hosts.clone(),
            pinned: ssh.fingerprints.get(node).cloned(),
            allowed_keys: None,
        };
        let spec = ConnectSpec {
            label,
            host,
            port: ssh.port,
            username: ssh.user.clone(),
            key,
            passphrase: ssh.key_passphrase.clone(),
            password: ssh.password.clone(),
            agent: ssh.agent.clone(),
            check,
        };
        self.connect(spec, None).await
    }

    fn config_for(&self, check: &HostKeyCheck) -> client::Config {
        let mut config = client::Config {
            keepalive_interval: Some(Duration::from_millis(self.options.keepalive_ms)),
            keepalive_max: 3,
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        };
        if let Some(names) = host_key_algorithms(check) {
            let algorithms: Vec<Algorithm> = names.iter().filter_map(|n| Algorithm::from_str(n).ok()).collect();
            if !algorithms.is_empty() {
                config.preferred.key = Cow::Owned(algorithms);
            }
        }
        config
    }

    async fn connect(self: &Arc<Self>, spec: ConnectSpec, through: Option<ChannelStream<Msg>>) -> Result<Arc<Connection>> {
        // Parsed before anything goes on the network: an encrypted key without its passphrase, or not a key at all.
        let key = match &spec.key {
            Some(text) => Some(russh::keys::decode_secret_key(text, spec.passphrase.as_deref()).map_err(|e| {
                PveError::new(kind::SSH_AUTH_FAILED, format!("The SSH credentials for {} cannot be used: {e}", spec.label)).hint("The operator has to check the key file and its passphrase.")
            })?),
            None => None,
        };
        let closed = CancellationToken::new();
        let verdict: Arc<Mutex<Option<PveError>>> = Arc::new(Mutex::new(None));
        let host_key: Arc<Mutex<Option<HostKeyInfo>>> = Arc::new(Mutex::new(None));
        let handler = ClientHandler { check: spec.check.clone(), verdict: verdict.clone(), host_key: host_key.clone(), _closed: closed.clone().drop_guard() };
        let config = Arc::new(self.config_for(&spec.check));
        let attempt = async {
            let mut handle = match through {
                Some(stream) => client::connect_stream(config, stream, handler).await?,
                None => {
                    let stream = tcp_connect(&spec.host, spec.port).await?;
                    client::connect_stream(config, stream, handler).await?
                }
            };
            if let Err(e) = authenticate(&mut handle, &spec, key).await {
                let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                return Err(e);
            }
            Ok(handle)
        };
        let outcome = tokio::time::timeout(Duration::from_millis(self.options.connect_timeout_ms), attempt).await;
        // The verdict on the host key comes first: it says why the host was left.
        let take_verdict = || verdict.lock().unwrap().take();
        let handle = match outcome {
            Ok(Ok(handle)) => handle,
            Ok(Err(failure)) => return Err(take_verdict().unwrap_or_else(|| map_connect_error(failure, &spec))),
            Err(_) => return Err(take_verdict().unwrap_or_else(|| map_connect_error(Failure::Io(std::io::ErrorKind::TimedOut.into()), &spec))),
        };
        let host_key = host_key.lock().unwrap().take().unwrap_or_else(|| HostKeyInfo { kind: "unknown".into(), fingerprint: "unknown".into() });
        let conn = Arc::new(Connection {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            handle,
            host_key,
            closed,
            slots: Mutex::new(Slots { active: 0, idle: None }),
            wake: Notify::new(),
            max_channels: self.options.max_channels,
            idle_ms: self.options.idle_ms,
        });
        conn.arm_idle();
        Ok(conn)
    }

    async fn open_session(conn: &Connection) -> std::result::Result<Channel<Msg>, RunError> {
        match conn.handle.channel_open_session().await {
            Ok(channel) => Ok(channel),
            Err(e) => {
                let gone = conn.is_closed() || matches!(e, russh::Error::SendError | russh::Error::Disconnect | russh::Error::HUP);
                if gone { Err(RunError::NotStarted(e.to_string())) } else { Err(RunError::Refused(e.to_string())) }
            }
        }
    }

    async fn run_command(&self, conn: Arc<Connection>, text: &str, stdin: Option<&[u8]>, opts: &ExecOptions) -> std::result::Result<ExecResult, RunError> {
        let ssh = &self.instance.ssh;
        let timeout_ms = opts.timeout_ms.unwrap_or(ssh.timeout_ms);
        let max_bytes = opts.max_bytes.unwrap_or(ssh.max_output_bytes);
        let kill_grace = Duration::from_millis(self.options.kill_grace_ms);
        let started = Instant::now();

        let channel = Self::open_session(&conn).await?;
        let (mut reader, writer) = channel.split();
        if let Err(e) = writer.exec(true, text.as_bytes().to_vec()).await {
            return Err(RunError::NotStarted(e.to_string()));
        }

        let mut out = CappedBuffer::new(max_bytes);
        let mut err_out = CappedBuffer::new(max_bytes);
        let mut exit_code: Option<i64> = None;
        let mut exit_signal: Option<String> = None;
        let mut saw_exit = false;
        let mut timed_out = false;
        let mut overflowed = false;
        let mut accepted = false;
        let mut stdin_done = false;
        let drain_limit = max_bytes.saturating_mul(DRAIN_FACTOR).max(MIN_DRAIN_BYTES);

        // Always an end of input: a command reading stdin would otherwise wait until the timeout.
        let send_input = async {
            if let Some(data) = stdin {
                let _ = writer.data(data).await;
            }
            let _ = writer.eof().await;
        };
        tokio::pin!(send_input);
        let deadline = tokio::time::sleep(Duration::from_millis(timeout_ms));
        tokio::pin!(deadline);
        // Signal first, for the command to end cleanly; then the channel goes, whatever it does.
        // 0: running, 1: signalled, 2: channel closed.
        let mut stage = 0u8;
        let grace = tokio::time::sleep(Duration::from_secs(0));
        tokio::pin!(grace);

        loop {
            tokio::select! {
                () = &mut send_input, if accepted && !stdin_done => stdin_done = true,
                () = &mut deadline, if stage == 0 => {
                    timed_out = true;
                    let _ = writer.signal(Sig::TERM).await;
                    stage = 1;
                    grace.as_mut().reset(tokio::time::Instant::now() + kill_grace);
                }
                () = &mut grace, if stage > 0 => {
                    if stage == 2 {
                        break;
                    }
                    let _ = writer.close().await;
                    stage = 2;
                    grace.as_mut().reset(tokio::time::Instant::now() + kill_grace);
                }
                msg = reader.wait() => match msg {
                    None | Some(ChannelMsg::Close) => break,
                    Some(ChannelMsg::Success) => accepted = true,
                    Some(ChannelMsg::Failure) if !accepted => return Err(RunError::Refused("Unable to exec".into())),
                    Some(msg @ (ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. })) => {
                        match msg {
                            ChannelMsg::Data { data } => out.push(&data),
                            ChannelMsg::ExtendedData { data, .. } => err_out.push(&data),
                            _ => {}
                        }
                        if !overflowed && !timed_out && stage == 0 && out.seen + err_out.seen > drain_limit {
                            overflowed = true;
                            let _ = writer.signal(Sig::TERM).await;
                            stage = 1;
                            grace.as_mut().reset(tokio::time::Instant::now() + kill_grace);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        saw_exit = true;
                        exit_code = Some(i64::from(exit_status));
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        saw_exit = true;
                        exit_code = None;
                        exit_signal = Some(format!("SIG{}", sig_name(&signal_name)));
                    }
                    Some(_) => {}
                },
            }
        }

        if !saw_exit && !timed_out && !overflowed && conn.is_closed() {
            return Err(RunError::Failed(
                PveError::new(kind::SSH_UNREACHABLE, "The SSH connection was lost while the command ran.")
                    .hint("It may or may not have finished. Check before running it again.")
                    .details(json!({ "stdout": last_chars(&out.text(), 2000), "stderr": last_chars(&err_out.text(), 2000) })),
            ));
        }
        Ok(ExecResult {
            stdout: out.text(),
            stderr: err_out.text(),
            exit_code,
            signal: exit_signal,
            truncated: out.truncated() || err_out.truncated(),
            duration_ms: started.elapsed().as_millis() as u64,
            timed_out,
            dry_run: false,
            host_key: Some(conn.host_key.clone()),
        })
    }

    async fn open_sftp(&self, conn: Arc<Connection>, node: &str) -> std::result::Result<Arc<dyn SftpSession>, RunError> {
        let mut channel = Self::open_session(&conn).await?;
        let refused = |message: String| RunError::Failed(PveError::new(kind::SSH_UNREACHABLE, format!("Could not open SFTP on {node}: {message}")).hint("The SFTP subsystem may be off on this host."));
        if let Err(e) = channel.request_subsystem(true, "sftp").await {
            return Err(RunError::NotStarted(e.to_string()));
        }
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => return Err(refused("the host refused the subsystem".into())),
                None | Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) => {
                    if conn.is_closed() {
                        return Err(RunError::NotStarted("the connection closed".into()));
                    }
                    return Err(refused("the channel closed".into()));
                }
                Some(_) => {}
            }
        }
        let raw = russh_sftp::client::SftpSession::new(channel.into_stream()).await.map_err(|e| refused(e.to_string()))?;
        // The session keeps its slot on the connection until it is closed.
        conn.acquire_held();
        let held = conn.clone();
        let session = Arc::new(Sftp::new(raw, self.instance.ssh.timeout_ms, Box::new(move || held.release())));
        // A connection that goes takes its sessions with it.
        let (token, weak): (CancellationToken, Weak<Sftp>) = (conn.closed.clone(), Arc::downgrade(&session));
        tokio::spawn(async move {
            token.cancelled().await;
            if let Some(session) = weak.upgrade() {
                session.close();
            }
        });
        Ok(session)
    }

    async fn open_pty(&self, conn: &Connection, opts: ShellOptions) -> Result<Channel<Msg>> {
        let failed = |message: String| PveError::new(kind::SSH_UNREACHABLE, format!("Could not open a terminal: {message}"));
        let (cols, rows) = (opts.cols.unwrap_or(120), opts.rows.unwrap_or(40));
        let term = opts.term.unwrap_or_else(|| "xterm".into());
        let ssh = &self.instance.ssh;
        let elevate = ssh.sudo && ssh.user != "root";
        let command = match opts.command {
            Some(c) if elevate => Some(format!("sudo -n {c}")),
            Some(c) => Some(c),
            None if elevate => Some("sudo -n -i".to_string()),
            None => None,
        };
        let mut channel = conn.handle.channel_open_session().await.map_err(|e| failed(e.to_string()))?;
        channel.request_pty(true, &term, cols, rows, 0, 0, &[]).await.map_err(|e| failed(e.to_string()))?;
        wait_reply(&mut channel, "the host refused the terminal").await.map_err(failed)?;
        match command {
            Some(c) => channel.exec(true, c.into_bytes()).await,
            None => channel.request_shell(true).await,
        }
        .map_err(|e| failed(e.to_string()))?;
        wait_reply(&mut channel, "the host refused the command").await.map_err(failed)?;
        Ok(channel)
    }

    async fn exec_on_guest(self: &Arc<Self>, guest: &GuestEndpoint, command: &ShellCommand, opts: &ExecOptions) -> Result<ExecResult> {
        let conn = self.connect_to_guest(guest).await?;
        self.add_dedicated(&conn);
        // Whatever ends the call, the connection goes with it.
        struct EndOnDrop(Arc<Connection>);
        impl Drop for EndOnDrop {
            fn drop(&mut self) {
                self.0.end_soon();
            }
        }
        let _end = EndOnDrop(conn.clone());
        conn.acquire().await;
        let slot = SlotGuard(conn.clone());
        let result = self.run_command(conn.clone(), &command.text, command.stdin.as_deref(), opts).await;
        drop(slot);
        self.remove_dedicated(conn.id);
        conn.end().await;
        match result {
            Ok(r) => Ok(r),
            Err(RunError::NotStarted(m) | RunError::Refused(m)) => Err(PveError::new(kind::SSH_UNREACHABLE, format!("Could not open a channel on guest {}: {m}", guest.vmid)).hint("Nothing was run.")),
            Err(RunError::Failed(e)) => Err(e),
        }
    }

    async fn connect_to_guest(self: &Arc<Self>, guest: &GuestEndpoint) -> Result<Arc<Connection>> {
        let ssh = &self.instance.ssh;
        let label = format!("guest {}", guest.vmid);
        // The credentials of the node never go to a guest: whoever runs that guest could collect them.
        let key = ssh.guest_key_file.as_deref().map(|path| read_key(path, &label)).transpose()?;
        if key.is_none() && ssh.guest_password.is_none() {
            return Err(PveError::new(kind::CONFIG_ERROR, "No credential is set for SSH to guests.")
                .hint("The operator can set PROXMOX_GUEST_SSH_KEY_FILE or PROXMOX_GUEST_SSH_PASSWORD. pve_lxc_exec reaches a container without one."));
        }
        let check = HostKeyCheck {
            label: label.clone(),
            host: guest.host.clone(),
            port: guest.port,
            policy: ssh.host_key_policy,
            known_hosts_file: ssh.known_hosts.clone(),
            pinned: guest.fingerprint.clone(),
            allowed_keys: guest.host_keys.as_ref().map(|keys| parse_public_key_lines(&keys.join("\n"))),
        };
        let spec = ConnectSpec {
            label,
            host: guest.host.clone(),
            port: guest.port,
            username: guest.user.clone(),
            key,
            passphrase: None,
            password: ssh.guest_password.clone(),
            agent: None,
            check,
        };
        let Some(via) = &guest.via_node else { return self.connect(spec, None).await };

        let jump = self.connection(via).await?;
        jump.acquire().await;
        let jump_slot = SlotGuard(jump.clone());
        let channel = jump.handle.channel_open_direct_tcpip(guest.host.clone(), u32::from(guest.port), "127.0.0.1", 0).await.map_err(|e| {
            PveError::new(kind::SSH_UNREACHABLE, format!("Node {via} could not reach {}:{}: {e}", guest.host, guest.port))
                .hint("The guest may be down, or the node may not allow TCP forwarding (AllowTcpForwarding).")
        })?;
        let conn = self.connect(spec, Some(channel.into_stream())).await?;
        // The slot on the node is held until the guest connection is gone.
        let token = conn.closed.clone();
        tokio::spawn(async move {
            token.cancelled().await;
            drop(jump_slot);
        });
        Ok(conn)
    }
}

/// Waits for the answer to a request sent with want_reply.
async fn wait_reply(channel: &mut Channel<Msg>, refusal: &str) -> std::result::Result<(), String> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => return Err(refusal.to_string()),
            None | Some(ChannelMsg::Close) => return Err("the channel closed".to_string()),
            Some(_) => {}
        }
    }
}

/// Each shell has its own connection, ended with it.
fn to_shell_channel(conn: Arc<Connection>, channel: Channel<Msg>) -> ShellChannel {
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<ShellInput>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<ShellEvent>();
    let (mut reader, writer) = channel.split();
    // Input on a task of its own: a write waiting on the window must not stop the output from being read.
    let writer_conn = conn.clone();
    let writing = tokio::spawn(async move {
        while let Some(input) = input_rx.recv().await {
            match input {
                ShellInput::Data(data) => {
                    let _ = writer.data(&data[..]).await;
                }
                ShellInput::Resize { cols, rows } => {
                    let _ = writer.window_change(cols, rows, 0, 0).await;
                }
                ShellInput::Close => break,
            }
        }
        // Closed by the caller, or every sender dropped.
        let _ = writer.close().await;
        writer_conn.end().await;
    });
    tokio::spawn(async move {
        let mut code: Option<i64> = None;
        let mut signal: Option<String> = None;
        loop {
            tokio::select! {
                msg = reader.wait() => match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = event_tx.send(ShellEvent::Data(data.to_vec()));
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(i64::from(exit_status)),
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        code = None;
                        signal = Some(format!("SIG{}", sig_name(&signal_name)));
                    }
                    None | Some(ChannelMsg::Close) => break,
                    Some(_) => {}
                },
                _ = conn.closed.cancelled() => break,
            }
        }
        let _ = event_tx.send(ShellEvent::Closed { code, signal });
        writing.abort();
        conn.release();
        conn.end().await;
    });
    ShellChannel { input: input_tx, events: event_rx }
}

fn sig_name(sig: &Sig) -> String {
    match sig {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => return name.clone(),
    }
    .to_string()
}

fn last_chars(text: &str, n: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(n)).collect()
}

/// Keeps the start of a stream up to a size, and counts the rest.
struct CappedBuffer {
    kept: Vec<u8>,
    max: u64,
    seen: u64,
}

impl CappedBuffer {
    fn new(max: u64) -> Self {
        CappedBuffer { kept: Vec::new(), max, seen: 0 }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.seen += chunk.len() as u64;
        let room = self.max.saturating_sub(self.kept.len() as u64) as usize;
        if room == 0 {
            return;
        }
        self.kept.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    fn truncated(&self) -> bool {
        self.seen > self.kept.len() as u64
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.kept).into_owned()
    }
}

impl SshTransport for PooledSshTransport {
    fn exec<'a>(&'a self, target: &'a SshTarget, command: &'a ShellCommand, opts: ExecOptions) -> BoxFuture<'a, Result<ExecResult>> {
        async move {
            let inner = &self.inner;
            if let Some(guest) = &target.guest {
                return inner.exec_on_guest(guest, command, &opts).await;
            }
            let text = inner.with_sudo(&command.text)?;
            let (text, opts) = (&text, &opts);
            inner.with_channel(&target.node, "a new channel", |conn| inner.run_command(conn, text, command.stdin.as_deref(), opts).boxed()).await
        }
        .boxed()
    }

    fn sftp<'a>(&'a self, target: &'a SshTarget) -> BoxFuture<'a, Result<Arc<dyn SftpSession>>> {
        async move {
            let inner = &self.inner;
            inner.with_channel(&target.node, "SFTP", |conn| inner.open_sftp(conn, &target.node).boxed()).await
        }
        .boxed()
    }

    /// Each session has its own connection: sessions last, and must not use up the channels of a node.
    fn shell<'a>(&'a self, target: &'a SshTarget, opts: ShellOptions) -> BoxFuture<'a, Result<ShellChannel>> {
        async move {
            let inner = &self.inner;
            if inner.closing.load(Ordering::SeqCst) {
                return Err(shutting_down());
            }
            let conn = inner.connect_to_node(&target.node).await?;
            inner.add_dedicated(&conn);
            // Held for as long as the shell is open, so that the idle timer leaves it alone.
            conn.acquire_held();
            match inner.open_pty(&conn, opts).await {
                Ok(channel) => Ok(to_shell_channel(conn, channel)),
                Err(e) => {
                    conn.release();
                    conn.end().await;
                    Err(e)
                }
            }
        }
        .boxed()
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        async move {
            self.inner.closing.store(true, Ordering::SeqCst);
            let connections: Vec<Arc<Connection>> = {
                let mut state = self.inner.state.lock().unwrap();
                let mut all: Vec<Arc<Connection>> = state.dedicated.drain().map(|(_, c)| c).collect();
                all.extend(state.pool.drain().map(|(_, c)| c));
                all
            };
            futures::future::join_all(connections.into_iter().map(|conn| async move {
                let _ = tokio::time::timeout(Duration::from_secs(1), conn.end()).await;
            }))
            .await;
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_buffer() {
        let mut b = CappedBuffer::new(5);
        b.push(b"abc");
        assert!(!b.truncated());
        b.push(b"defg");
        assert_eq!((b.text().as_str(), b.seen, b.truncated()), ("abcde", 7, true));
        b.push(b"h");
        assert_eq!(b.text(), "abcde");
        let mut empty = CappedBuffer::new(0);
        empty.push(b"x");
        assert_eq!((empty.text().as_str(), empty.truncated()), ("", true));
    }

    #[test]
    fn signals_and_tails() {
        assert_eq!(sig_name(&Sig::KILL), "KILL");
        assert_eq!(sig_name(&Sig::Custom("WINCH".into())), "WINCH");
        assert_eq!(last_chars("héllo", 3), "llo");
        assert_eq!(last_chars("ab", 3), "ab");
    }

    #[test]
    fn test_options_from_the_environment() {
        let o = options_from_env(Some(r#"{"idleMs":50,"maxChannels":1,"connectTimeoutMs":300,"killGraceMs":40,"keepaliveMs":7}"#));
        assert_eq!((o.idle_ms, o.max_channels, o.connect_timeout_ms, o.kill_grace_ms, o.keepalive_ms), (50, 1, 300, 40, 7));
        let d = TransportOptions::default();
        for text in [None, Some("not json"), Some("[1]"), Some(r#"{"maxChannels":0}"#)] {
            let o = options_from_env(text);
            assert_eq!((o.idle_ms, o.max_channels, o.connect_timeout_ms), (d.idle_ms, d.max_channels, d.connect_timeout_ms));
        }
    }

    #[test]
    fn socket_codes() {
        assert_eq!(errno(&std::io::ErrorKind::ConnectionRefused.into()), "ECONNREFUSED");
        assert_eq!(errno(&std::io::ErrorKind::NotFound.into()), "ENOENT");
    }
}

/// Against a russh server in the same process: the transport end to end, on 127.0.0.1.
#[cfg(test)]
mod e2e {
    use super::*;
    use crate::config::SshConfig;
    use crate::proxmox::nodes::NodeResolverOptions;
    use crate::proxmox::{Api, RequestOptions, UploadFile};
    use indexmap::IndexMap;
    use russh::ChannelId;
    use russh::server::{Auth, ChannelOpenHandle, Msg as ServerMsg, Session};
    use serde_json::{Map, Value};
    use std::sync::atomic::AtomicUsize;

    /// A throwaway key, made for this test only.
    const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAIUXFChIHeLDBMoquCwYNkC/ez55AIymq6Pd8NmWSKngAAAIge1RNXHtUT
VwAAAAtzc2gtZWQyNTUxOQAAACAIUXFChIHeLDBMoquCwYNkC/ez55AIymq6Pd8NmWSKng
AAAECahxLT5yaMxQzUDELNNsZ/kfE5iQXfpeqRktplFYad0AhRcUKEgd4sMEyiq4LBg2QL
97PnkAjKaro93w2ZZIqeAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";
    const HOST_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhRcUKEgd4sMEyiq4LBg2QL97PnkAjKaro93w2ZZIqe";

    struct NoApi;
    impl Api for NoApi {
        fn request(&self, _: &str, _: &str, _: RequestOptions) -> BoxFuture<'_, Result<Value>> {
            async { Err(PveError::internal("no API in this test")) }.boxed()
        }
        fn upload(&self, _: &str, _: Map<String, Value>, _: UploadFile, _: RequestOptions) -> BoxFuture<'_, Result<Value>> {
            async { Err(PveError::internal("no API in this test")) }.boxed()
        }
    }

    #[derive(Default)]
    struct Seen {
        connections: AtomicUsize,
        logins: AtomicUsize,
        commands: Mutex<Vec<String>>,
    }

    struct Server {
        seen: Arc<Seen>,
        commands: HashMap<ChannelId, String>,
        input: HashMap<ChannelId, Vec<u8>>,
    }

    fn finish(session: &mut Session, channel: ChannelId, code: u32) -> std::result::Result<(), russh::Error> {
        session.exit_status_request(channel, code)?;
        session.eof(channel)?;
        session.close(channel)
    }

    impl russh::server::Handler for Server {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> std::result::Result<Auth, Self::Error> {
            if user == "root" && password == "secret" {
                self.seen.logins.fetch_add(1, Ordering::SeqCst);
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(&mut self, _: russh::Channel<ServerMsg>, reply: ChannelOpenHandle, _: &mut Session) -> std::result::Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> std::result::Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).into_owned();
            self.seen.commands.lock().unwrap().push(command.clone());
            session.channel_success(channel)?;
            match command.as_str() {
                "status" => {
                    session.data(channel, b"out".to_vec())?;
                    session.extended_data(channel, 1, b"err".to_vec())?;
                    finish(session, channel, 3)?;
                }
                "big" => {
                    session.data(channel, vec![b'x'; 5000])?;
                    finish(session, channel, 0)?;
                }
                "hang" | "cat" => {}
                _ => finish(session, channel, 127)?,
            }
            self.commands.insert(channel, command);
            Ok(())
        }

        async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> std::result::Result<(), Self::Error> {
            if self.commands.get(&channel).map(String::as_str) == Some("shell") {
                // A terminal that echoes, and ends on exit.
                session.data(channel, data.to_vec())?;
                if data == b"exit\n" {
                    finish(session, channel, 0)?;
                }
                return Ok(());
            }
            self.input.entry(channel).or_default().extend_from_slice(data);
            Ok(())
        }

        async fn pty_request(
            &mut self,
            channel: ChannelId,
            term: &str,
            cols: u32,
            rows: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> std::result::Result<(), Self::Error> {
            self.seen.commands.lock().unwrap().push(format!("pty {term} {cols}x{rows}"));
            session.channel_success(channel)
        }

        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> std::result::Result<(), Self::Error> {
            self.seen.commands.lock().unwrap().push("shell".into());
            self.commands.insert(channel, "shell".into());
            session.channel_success(channel)?;
            session.data(channel, b"$ ".to_vec())
        }

        async fn window_change_request(&mut self, _: ChannelId, cols: u32, rows: u32, _: u32, _: u32, _: &mut Session) -> std::result::Result<(), Self::Error> {
            self.seen.commands.lock().unwrap().push(format!("resize {cols}x{rows}"));
            Ok(())
        }

        async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> std::result::Result<(), Self::Error> {
            if self.commands.get(&channel).map(String::as_str) == Some("cat") {
                let input = self.input.remove(&channel).unwrap_or_default();
                session.data(channel, input)?;
                finish(session, channel, 0)?;
            }
            Ok(())
        }

        async fn signal(&mut self, channel: ChannelId, signal: Sig, session: &mut Session) -> std::result::Result<(), Self::Error> {
            session.exit_signal_request(channel, signal, false, "", "en")?;
            session.eof(channel)?;
            session.close(channel)
        }
    }

    async fn start_server() -> (u16, Arc<Seen>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Seen::default());
        let config = Arc::new(russh::server::Config {
            keys: vec![russh::keys::decode_secret_key(HOST_KEY, None).unwrap()],
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let s = seen.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                s.connections.fetch_add(1, Ordering::SeqCst);
                let handler = Server { seen: s.clone(), commands: HashMap::new(), input: HashMap::new() };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, socket, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        (port, seen)
    }

    fn transport(port: u16, password: &str, policy: HostKeyPolicy, known_hosts: &std::path::Path) -> PooledSshTransport {
        let ssh = SshConfig {
            user: "root".into(),
            port,
            key_file: None,
            key_passphrase: None,
            password: Some(password.into()),
            agent: None,
            nodes: IndexMap::from([("pve1".to_string(), "127.0.0.1".to_string())]),
            sudo: false,
            known_hosts: known_hosts.to_string_lossy().into_owned(),
            host_key_policy: policy,
            fingerprints: IndexMap::new(),
            timeout_ms: 5_000,
            max_output_bytes: 1000,
            guest_user: None,
            guest_key_file: None,
            guest_password: None,
        };
        let instance = Arc::new(InstanceConfig {
            name: "test".into(),
            url: "https://127.0.0.1:8006".into(),
            token_id: None,
            token_secret: None,
            username: None,
            password: None,
            verify_ssl: true,
            ca: None,
            fingerprint: None,
            allow_writes: true,
            allow_elevated: true,
            allow_guest_exec: true,
            allow_ssh: true,
            allow_sensitive: false,
            dry_run: false,
            default_node: None,
            protected_vmids: Default::default(),
            description: None,
            timeout_ms: 5_000,
            local_dir: None,
            ssh: ssh.clone(),
        });
        let nodes = Arc::new(NodeResolver::new(
            Arc::new(NoApi) as Arc<dyn Api>,
            NodeResolverOptions { default_node: None, api_host: "127.0.0.1".into(), ssh_nodes: ssh.nodes.clone(), cache_ms: None },
        ));
        PooledSshTransport::new(instance, nodes, TransportOptions { kill_grace_ms: 100, ..TransportOptions::default() })
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pvemcp-transport-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn runs_commands_on_one_connection() {
        let (port, seen) = start_server().await;
        let dir = temp_dir("run");
        let known = dir.join("known_hosts");
        let t = transport(port, "secret", HostKeyPolicy::AcceptNew, &known);
        let target = SshTarget::node("pve1");

        let res = t.exec(&target, &ShellCommand::read("status"), ExecOptions::default()).await.unwrap();
        assert_eq!((res.stdout.as_str(), res.stderr.as_str(), res.exit_code, res.timed_out, res.truncated), ("out", "err", Some(3), false, false));
        let host_key = res.host_key.unwrap();
        assert_eq!(host_key.kind, "ssh-ed25519");
        assert_eq!(host_key.fingerprint, super::super::known_hosts::fingerprint_of(&parse_public_key_lines(HOST_PUB)[0]));
        // accept-new wrote the key down.
        let written = std::fs::read_to_string(&known).unwrap();
        assert!(written.contains(&format!("[127.0.0.1]:{port} {HOST_PUB}")), "{written}");

        let res = t.exec(&target, &ShellCommand::read("cat").stdin(b"hello".to_vec()), ExecOptions::default()).await.unwrap();
        assert_eq!((res.stdout.as_str(), res.exit_code), ("hello", Some(0)));

        let res = t.exec(&target, &ShellCommand::read("big"), ExecOptions::default()).await.unwrap();
        assert_eq!((res.stdout.len(), res.truncated), (1000, true));

        let res = t.exec(&target, &ShellCommand::read("hang"), ExecOptions { timeout_ms: Some(200), max_bytes: None }).await.unwrap();
        assert_eq!((res.timed_out, res.exit_code, res.signal.as_deref()), (true, None, Some("SIGTERM")));

        assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
        assert_eq!(seen.logins.load(Ordering::SeqCst), 1);
        t.close().await;
        let err = t.exec(&target, &ShellCommand::read("status"), ExecOptions::default()).await.unwrap_err();
        assert_eq!((err.kind, err.message.as_str()), (kind::SSH_UNREACHABLE, "This server is shutting down."));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn refuses_unknown_keys_before_logging_in() {
        let (port, seen) = start_server().await;
        let dir = temp_dir("strict");
        let t = transport(port, "secret", HostKeyPolicy::Strict, &dir.join("known_hosts"));
        let err = t.exec(&SshTarget::node("pve1"), &ShellCommand::read("status"), ExecOptions::default()).await.unwrap_err();
        assert_eq!(err.kind, kind::HOST_KEY_UNKNOWN, "{err:?}");
        assert_eq!(seen.logins.load(Ordering::SeqCst), 0);
        assert!(seen.commands.lock().unwrap().is_empty());

        // A changed key is a mismatch.
        std::fs::write(dir.join("known_hosts"), format!("[127.0.0.1]:{port} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n")).unwrap();
        let t = transport(port, "secret", HostKeyPolicy::Strict, &dir.join("known_hosts"));
        let err = t.exec(&SshTarget::node("pve1"), &ShellCommand::read("status"), ExecOptions::default()).await.unwrap_err();
        assert_eq!(err.kind, kind::HOST_KEY_MISMATCH, "{err:?}");
        assert_eq!(seen.logins.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn opens_a_terminal_on_its_own_connection() {
        let (port, seen) = start_server().await;
        let dir = temp_dir("shell");
        let t = transport(port, "secret", HostKeyPolicy::Off, &dir.join("known_hosts"));
        let mut shell = t.shell(&SshTarget::node("pve1"), ShellOptions { cols: Some(90), rows: Some(30), term: Some("vt100".into()), command: None }).await.unwrap();
        let mut output = Vec::new();
        async fn next(events: &mut mpsc::UnboundedReceiver<ShellEvent>) -> ShellEvent {
            tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("an event in time").expect("the channel is open")
        }
        match next(&mut shell.events).await {
            ShellEvent::Data(d) => output.extend(d),
            other => panic!("{other:?}"),
        }
        shell.input.send(ShellInput::Resize { cols: 100, rows: 50 }).unwrap();
        shell.input.send(ShellInput::Data(b"exit\n".to_vec())).unwrap();
        let closed = loop {
            match next(&mut shell.events).await {
                ShellEvent::Data(d) => output.extend(d),
                ShellEvent::Closed { code, signal } => break (code, signal),
            }
        };
        assert_eq!(String::from_utf8_lossy(&output), "$ exit\n");
        assert_eq!(closed, (Some(0), None));
        assert_eq!(*seen.commands.lock().unwrap(), vec!["pty vt100 90x30".to_string(), "shell".into(), "resize 100x50".into()]);
        // A node command afterwards uses a connection of its own.
        t.exec(&SshTarget::node("pve1"), &ShellCommand::read("status"), ExecOptions::default()).await.unwrap();
        assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
        t.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn maps_login_and_socket_failures() {
        let (port, _) = start_server().await;
        let dir = temp_dir("fail");
        let t = transport(port, "wrong", HostKeyPolicy::Off, &dir.join("known_hosts"));
        let err = t.exec(&SshTarget::node("pve1"), &ShellCommand::read("status"), ExecOptions::default()).await.unwrap_err();
        assert_eq!((err.kind, err.message.as_str()), (kind::SSH_AUTH_FAILED, format!("SSH login as root to node pve1 (127.0.0.1:{port}) was refused.").as_str()));

        // A port nobody listens on.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let t = transport(closed, "secret", HostKeyPolicy::Off, &dir.join("known_hosts"));
        let err = t.exec(&SshTarget::node("pve1"), &ShellCommand::read("status"), ExecOptions::default()).await.unwrap_err();
        assert_eq!((err.kind, err.message.as_str()), (kind::SSH_UNREACHABLE, format!("Could not reach node pve1 (127.0.0.1:{closed}) over SSH: ECONNREFUSED.").as_str()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
