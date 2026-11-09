//! SSH to nodes and guests: the gate in front (ScopedSsh), the interfaces of the transport behind it.

pub mod known_hosts;
pub mod quote;
pub mod scripts;
pub mod sessions;
pub mod sftp;
pub mod transport;

pub use quote::{ShellArg, sh_quote};

use crate::config::InstanceConfig;
use crate::errors::{PveError, Result, kind};
use crate::obj;
use crate::proxmox::DryRunLog;
use crate::proxmox::policy::{Gate, gate_refusal};
use crate::proxmox::redact::scrub_text;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }
}

/// A shell command and what it is allowed to be. Build text with sh!, never by hand.
#[derive(Debug, Clone)]
pub struct ShellCommand {
    pub text: String,
    pub access: Access,
    pub stdin: Option<Vec<u8>>,
    /// Shown in audit and dry-run logs instead of text, when text holds something secret.
    pub display: Option<String>,
    /// A digest of a password can be attacked offline: stdin then leaves no trace at all in the logs.
    pub sensitive_stdin: bool,
}

impl ShellCommand {
    pub fn read(text: impl Into<String>) -> Self {
        ShellCommand { text: text.into(), access: Access::Read, stdin: None, display: None, sensitive_stdin: false }
    }

    pub fn write(text: impl Into<String>) -> Self {
        ShellCommand { text: text.into(), access: Access::Write, stdin: None, display: None, sensitive_stdin: false }
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn display(mut self, text: impl Into<String>) -> Self {
        self.display = Some(text.into());
        self
    }

    pub fn sensitive_stdin(mut self) -> Self {
        self.sensitive_stdin = true;
        self
    }
}

/// The key a host presented, once verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub kind: String,
    pub fingerprint: String,
}

impl HostKeyInfo {
    pub fn to_json(&self) -> Value {
        Value::Object(obj! { "type" => &self.kind, "fingerprint" => &self.fingerprint })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub truncated: bool,
    pub duration_ms: u64,
    pub timed_out: bool,
    /// Set when nothing ran, because this is a dry run.
    pub dry_run: bool,
    /// The key the host presented, once verified. Only the real transport gives this.
    pub host_key: Option<HostKeyInfo>,
}

impl ExecResult {
    /// As the TypeScript object was spread into answers: stdout, stderr, exit_code, signal?, truncated, duration_ms, timed_out, dry_run?, host_key?.
    pub fn to_json(&self) -> Map<String, Value> {
        obj! {
            "stdout" => &self.stdout,
            "stderr" => &self.stderr,
            "exit_code" => self.exit_code.map(Value::from).unwrap_or(Value::Null),
            "signal" => self.signal.clone(),
            "truncated" => self.truncated,
            "duration_ms" => self.duration_ms,
            "timed_out" => self.timed_out,
            "dry_run" => if self.dry_run { Some(true) } else { None },
            "host_key" => self.host_key.as_ref().map(HostKeyInfo::to_json),
        }
    }
}

/// A guest reached directly over SSH instead of the node.
#[derive(Debug, Clone)]
pub struct GuestEndpoint {
    pub vmid: i64,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Go through this node, for a guest the server cannot reach.
    pub via_node: Option<String>,
    /// The public key lines the guest must present, read through pct.
    pub host_keys: Option<Vec<String>>,
    /// SHA256:... given on the call.
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub node: String,
    pub guest: Option<GuestEndpoint>,
}

impl SshTarget {
    pub fn node(node: impl Into<String>) -> Self {
        SshTarget { node: node.into(), guest: None }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    pub timeout_ms: Option<u64>,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SftpStat {
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub is_directory: bool,
    pub is_file: bool,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub stat: SftpStat,
}

/// An SFTP channel. Paths are remote; local ones must have gone through resolve_local_path.
pub trait SftpSession: Send + Sync {
    fn read_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<u8>>>;
    fn write_file<'a>(&'a self, path: &'a str, data: Vec<u8>, mode: Option<u32>) -> BoxFuture<'a, Result<()>>;
    /// Streams a local file to the remote path.
    fn fast_put<'a>(&'a self, local_path: &'a str, remote_path: &'a str, mode: Option<u32>, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>>;
    /// Streams a remote file to the local path.
    fn fast_get<'a>(&'a self, remote_path: &'a str, local_path: &'a str, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>>;
    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<SftpStat>>;
    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>>>;
    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<()>>;
    fn rename<'a>(&'a self, from: &'a str, to: &'a str) -> BoxFuture<'a, Result<()>>;
    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<()>>;
    fn close(&self);
}

#[derive(Debug, Clone, Default)]
pub struct ShellOptions {
    pub cols: Option<u32>,
    pub rows: Option<u32>,
    pub term: Option<String>,
    /// Run this with a PTY instead of the login shell: pct enter 100.
    pub command: Option<String>,
}

pub enum ShellInput {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close,
}

#[derive(Debug, Clone)]
pub enum ShellEvent {
    Data(Vec<u8>),
    /// Sent once, whatever ended the channel.
    Closed { code: Option<i64>, signal: Option<String> },
}

/// An open PTY channel: send input, receive output until Closed.
pub struct ShellChannel {
    pub input: mpsc::UnboundedSender<ShellInput>,
    pub events: mpsc::UnboundedReceiver<ShellEvent>,
}

/// The seam between the gates and the actual SSH connections. An implementation owns the pool,
/// the host key checks and the timeouts; it has no policy of its own, and is only ever reached
/// through ScopedSsh.
pub trait SshTransport: Send + Sync {
    fn exec<'a>(&'a self, target: &'a SshTarget, command: &'a ShellCommand, opts: ExecOptions) -> BoxFuture<'a, Result<ExecResult>>;
    fn sftp<'a>(&'a self, target: &'a SshTarget) -> BoxFuture<'a, Result<Arc<dyn SftpSession>>>;
    fn shell<'a>(&'a self, target: &'a SshTarget, opts: ShellOptions) -> BoxFuture<'a, Result<ShellChannel>>;
    /// Closes every connection. Called at shutdown.
    fn close(&self) -> BoxFuture<'_, ()>;
}

/// Gives the transport of an instance, created on first use.
pub type TransportGetter = Arc<dyn Fn() -> Arc<dyn SshTransport> + Send + Sync>;
pub type OnCommand = Arc<dyn Fn(Map<String, Value>) + Send + Sync>;

#[derive(Clone)]
pub struct SshScope {
    /// Set for read tools: a command that may change something is refused.
    pub read_only: bool,
    pub dry_run: bool,
    pub dry_run_log: DryRunLog,
    /// Records what is about to run, for the audit log.
    pub on_command: Option<OnCommand>,
}

pub fn stdin_summary(data: &[u8]) -> Value {
    Value::Object(obj! { "bytes" => data.len(), "sha256" => hex::encode(Sha256::digest(data)) })
}

/// All SSH access for one tool call. Enforces the gates at the chokepoint, like the API client
/// does for HTTP: a tool cannot reach the transport any other way.
#[derive(Clone)]
pub struct ScopedSsh {
    instance: Arc<InstanceConfig>,
    transport: TransportGetter,
    scope: SshScope,
}

impl ScopedSsh {
    pub fn new(instance: Arc<InstanceConfig>, transport: TransportGetter, scope: SshScope) -> Self {
        ScopedSsh { instance, transport, scope }
    }

    fn assert_allowed(&self, access: Access, what: &str) -> Result<()> {
        let gate = if access == Access::Write { Gate::SshWrite } else { Gate::SshRead };
        if let Some(refusal) = gate_refusal(gate, &self.instance.subject(), self.scope.dry_run, false, what) {
            return Err(refusal);
        }
        if access == Access::Write && self.scope.read_only {
            return Err(PveError::new(kind::NOT_READ_ONLY, format!("{what} can change something, so a read tool refuses it: nothing was run.")).hint("A tool that writes is the way to do this, provided writes are enabled."));
        }
        Ok(())
    }

    fn record(&self, entry: Map<String, Value>) {
        if let Some(on_command) = &self.scope.on_command {
            on_command(entry);
        }
    }

    fn log(&self, entry: Value) {
        self.scope.dry_run_log.lock().unwrap().push(entry);
    }

    pub fn is_dry_run(&self) -> bool {
        self.scope.dry_run
    }

    pub async fn run(&self, target: &SshTarget, cmd: &ShellCommand, opts: ExecOptions) -> Result<ExecResult> {
        let what = match &target.guest {
            Some(g) => format!("SSH command on guest {}", g.vmid),
            None => format!("SSH command on {}", target.node),
        };
        self.assert_allowed(cmd.access, &what)?;
        if cmd.text.contains('\0') {
            return Err(PveError::invalid("The command holds a NUL character."));
        }
        let place = match &target.guest {
            Some(g) => format!("[guest {} {}@{}] ", g.vmid, g.user, g.host),
            None => String::new(),
        };
        let shown = format!("{place}{}", cmd.display.as_deref().unwrap_or(&cmd.text));
        let stdin = match (&cmd.stdin, cmd.sensitive_stdin) {
            (Some(data), false) => Some(stdin_summary(data)),
            _ => None,
        };
        if self.scope.dry_run {
            let ssh = obj! { "node" => &target.node, "command" => &shown, "access" => cmd.access.as_str(), "stdin" => stdin };
            self.log(Value::Object(obj! { "ssh" => ssh }));
            return Ok(ExecResult { exit_code: Some(0), dry_run: true, ..Default::default() });
        }
        if cmd.access == Access::Write {
            self.record(obj! { "status" => "sent", "ssh" => obj! { "node" => &target.node, "command" => &shown, "stdin" => stdin } });
        }
        let mut result = (self.transport)().exec(target, cmd, opts).await?;
        // Here and not in each tool: what comes back from a host is untrusted, whoever asked for it.
        result.stdout = scrub_text(&result.stdout);
        result.stderr = scrub_text(&result.stderr);
        Ok(result)
    }

    /// In a read scope only reads work. In a dry run, writes are logged and reads are refused: nothing connects.
    pub async fn sftp(&self, target: &SshTarget, access: Access) -> Result<Arc<dyn SftpSession>> {
        self.assert_allowed(access, &format!("SFTP on {}", target.node))?;
        if self.scope.dry_run {
            return Ok(Arc::new(DryRunSftp { node: target.node.clone(), log: self.scope.dry_run_log.clone() }));
        }
        let session = (self.transport)().sftp(target).await?;
        Ok(Arc::new(GuardedSftp { node: target.node.clone(), inner: session, access, on_command: self.scope.on_command.clone() }))
    }

    /// A PTY is arbitrary execution: there is no read-only version of it.
    pub async fn shell(&self, target: &SshTarget, opts: ShellOptions) -> Result<ShellChannel> {
        self.assert_allowed(Access::Write, &format!("SSH session on {}", target.node))?;
        let command = opts.command.clone().unwrap_or_else(|| "(login shell)".into());
        if self.scope.dry_run {
            self.log(Value::Object(obj! { "ssh" => obj! { "node" => &target.node, "command" => &command, "access" => "write" } }));
            return Err(PveError::invalid("An interactive session cannot be previewed: a dry run opens nothing.").hint("Run it without dry_run, or preview the commands one at a time."));
        }
        self.record(obj! { "status" => "sent", "ssh" => obj! { "node" => &target.node, "command" => &command, "pty" => true } });
        (self.transport)().shell(target, opts).await
    }
}

struct GuardedSftp {
    node: String,
    inner: Arc<dyn SftpSession>,
    access: Access,
    on_command: Option<OnCommand>,
}

impl GuardedSftp {
    fn allow(&self, operation: &str, path: &str) -> Result<()> {
        if self.access != Access::Write {
            return Err(PveError::new(kind::NOT_READ_ONLY, format!("SFTP {operation} on {path} was refused: this session is read-only.")));
        }
        if let Some(record) = &self.on_command {
            record(obj! { "status" => "sent", "ssh" => obj! { "node" => &self.node, "sftp" => operation, "path" => path } });
        }
        Ok(())
    }
}

impl SftpSession for GuardedSftp {
    fn read_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.inner.read_file(path)
    }
    fn fast_get<'a>(&'a self, remote: &'a str, local: &'a str, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.inner.fast_get(remote, local, timeout_ms)
    }
    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<SftpStat>> {
        self.inner.stat(path)
    }
    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>>> {
        self.inner.readdir(path)
    }
    fn close(&self) {
        self.inner.close()
    }
    fn write_file<'a>(&'a self, path: &'a str, data: Vec<u8>, mode: Option<u32>) -> BoxFuture<'a, Result<()>> {
        async move {
            self.allow("writeFile", path)?;
            self.inner.write_file(path, data, mode).await
        }
        .boxed()
    }
    fn fast_put<'a>(&'a self, local: &'a str, remote: &'a str, mode: Option<u32>, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>> {
        async move {
            self.allow("fastPut", remote)?;
            self.inner.fast_put(local, remote, mode, timeout_ms).await
        }
        .boxed()
    }
    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<()>> {
        async move {
            self.allow("unlink", path)?;
            self.inner.unlink(path).await
        }
        .boxed()
    }
    fn rename<'a>(&'a self, from: &'a str, to: &'a str) -> BoxFuture<'a, Result<()>> {
        async move {
            self.allow("rename", from)?;
            self.inner.rename(from, to).await
        }
        .boxed()
    }
    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<()>> {
        async move {
            self.allow("chmod", path)?;
            self.inner.chmod(path, mode).await
        }
        .boxed()
    }
}

struct DryRunSftp {
    node: String,
    log: DryRunLog,
}

impl DryRunSftp {
    fn log(&self, sftp: &str, path: &str, data: Option<&[u8]>) -> BoxFuture<'static, Result<()>> {
        let ssh = obj! { "node" => &self.node, "sftp" => sftp, "path" => path, "access" => "write", "stdin" => data.map(stdin_summary) };
        self.log.lock().unwrap().push(Value::Object(obj! { "ssh" => ssh }));
        futures::future::ready(Ok(())).boxed()
    }

    fn no_read<T: Send + 'static>() -> BoxFuture<'static, Result<T>> {
        futures::future::ready(Err(PveError::invalid("SFTP reads are not available in a dry run: nothing connects."))).boxed()
    }
}

impl SftpSession for DryRunSftp {
    fn read_file<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Self::no_read()
    }
    fn fast_get<'a>(&'a self, _: &'a str, _: &'a str, _: Option<u64>) -> BoxFuture<'a, Result<()>> {
        Self::no_read()
    }
    fn stat<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<SftpStat>> {
        Self::no_read()
    }
    fn readdir<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>>> {
        Self::no_read()
    }
    fn close(&self) {}
    fn write_file<'a>(&'a self, path: &'a str, data: Vec<u8>, _: Option<u32>) -> BoxFuture<'a, Result<()>> {
        self.log("writeFile", path, Some(&data))
    }
    fn fast_put<'a>(&'a self, _: &'a str, remote: &'a str, _: Option<u32>, _: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.log("fastPut", remote, None)
    }
    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<()>> {
        self.log("unlink", path, None)
    }
    fn rename<'a>(&'a self, from: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
        self.log("rename", from, None)
    }
    fn chmod<'a>(&'a self, path: &'a str, _: u32) -> BoxFuture<'a, Result<()>> {
        self.log("chmod", path, None)
    }
}

/// The gates of ScopedSsh at the chokepoint, over a recording stand-in for the transport.
#[cfg(test)]
mod gate_tests;
