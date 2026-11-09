//! What the SSH tools share: validated argument types, the refusals, and the turning of a
//! finished command into a tool result or a typed error.

use super::{Args, ArgsExt, ToolContext, node_name};
use crate::errors::{PveError, Result, kind};
use crate::js::{js_len, js_slice_end, js_slice_start, num, number_text};
use crate::obj;
use crate::proxmox::nodes::GuestLocation;
use crate::schema::{Schema, z};
use crate::ssh::known_hosts::{fingerprint_of, key_type_of};
use crate::ssh::scripts::{EXIT_NOT_A_FILE, EXIT_NOT_FOUND, EXIT_NOT_READABLE, file_stat_script, read_file_script};
use crate::ssh::{ExecOptions, ExecResult, ShellCommand, SshTarget};
use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::LazyLock;

/// Absolute, so that it cannot be taken for an option by any command it reaches.
pub fn remote_path() -> Schema {
    z::string().min(1).max(4096).regex(r"^\/[^\0]*$", "Expected an absolute path, with no NUL character").describe("An absolute path.")
}

/// The first character blocks option injection: none of these can start with a dash.
pub fn unit_name() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9][a-zA-Z0-9@._:+-]*$", "Expected a service name").max(256)
}
pub fn package_name() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9][a-zA-Z0-9+._:@=~-]*$", "Expected a package name").max(256)
}
pub fn user_name() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$", "Expected a user name").max(32)
}
pub fn file_mode() -> Schema {
    z::string().regex(r"^[0-7]{3,4}$", "Expected an octal mode such as 0644")
}
pub fn file_owner() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]*)?$", "Expected user or user:group").max(65)
}
/// JavaScript source of the pattern for environment variable names.
pub const ENV_NAME: &str = r"^[A-Za-z_][A-Za-z0-9_]*$";
pub fn timeout_seconds() -> Schema {
    z::int().min(1).max(86_400).optional().describe("Stop after this long. Default: PROXMOX_SSH_TIMEOUT_SECONDS. The command may go on running on the far side after the channel is closed.")
}
pub fn max_output_bytes() -> Schema {
    z::int().min(1024).optional().describe("Keep at most this much of stdout, and of stderr. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES.")
}
pub fn target_node() -> Schema {
    node_name().optional().describe("Node to connect to. Default: PROXMOX_DEFAULT_NODE, or the only node.")
}
pub fn guest_node() -> Schema {
    node_name().optional().describe("Node of the guest, checked if given. Found from the vmid otherwise.")
}

/// timeout_seconds and max_output_bytes of the arguments, the second capped by the server.
pub fn exec_options(args: &Args, ctx: &ToolContext) -> ExecOptions {
    ExecOptions {
        timeout_ms: args.u64("timeout_seconds").map(|s| s * 1000),
        max_bytes: args.u64("max_output_bytes").map(|b| b.min(ctx.instance.ssh.max_output_bytes)),
    }
}

pub async fn node_target(ctx: &ToolContext, node: Option<&str>) -> Result<SshTarget> {
    Ok(SshTarget::node(match node {
        Some(n) => n.to_string(),
        None => ctx.nodes.default_node().await?,
    }))
}

pub fn assert_writable(ctx: &ToolContext, vmid: i64) -> Result<()> {
    if ctx.instance.protected_vmids.contains(&vmid) {
        return Err(PveError::new(kind::PROTECTED_GUEST, format!("Guest {vmid} is protected on this server: nothing was run."))
            .hint("Do not retry and do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS."));
    }
    Ok(())
}

/// Where a container is. Only containers: pct has nothing to say about a VM.
pub async fn locate_lxc(ctx: &ToolContext, vmid: i64, node: Option<&str>) -> Result<GuestLocation> {
    let guest = ctx.nodes.resolve_guest(vmid).await?;
    if guest.kind != "lxc" {
        return Err(PveError::new(kind::INVALID_INPUT, format!("Guest {vmid} is a VM, not a container: pct cannot reach it."))
            .hint("pve_guest_ssh_exec reaches a VM over SSH, and the guest agent tools go through the API."));
    }
    if let Some(node) = node
        && node != guest.node
    {
        return Err(PveError::new(kind::INVALID_INPUT, format!("Container {vmid} is on node {}, not {node}.", guest.node)).hint("Leave node out: it is found from the vmid."));
    }
    Ok(guest)
}

/// String.prototype.trim: also the byte order mark, which Rust does not count as white space.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// The last of an output, for an error message.
pub fn tail(text: &str, chars: usize) -> String {
    if js_len(text) > chars { format!("...{}", js_slice_end(text, chars)) } else { text.to_string() }
}

fn exit_code_json(res: &ExecResult) -> Value {
    res.exit_code.map(Value::from).unwrap_or(Value::Null)
}

pub fn failure_details(res: &ExecResult) -> Value {
    json!({ "exit_code": exit_code_json(res), "stdout": tail(&res.stdout, 2000), "stderr": tail(&res.stderr, 2000), "untrusted": true })
}

/// Case-insensitive and by line, as the /im flags were. R: a line ends at \r too, as in JavaScript.
fn line_regex(source: &str) -> Regex {
    Regex::new(&format!("(?imR){source}")).expect("valid pattern")
}

/// Whole lines only: what a container prints on its own stderr should not read as a message from pct.
static NOT_RUNNING: LazyLock<Regex> = LazyLock::new(|| {
    line_regex(r"^(?:CT [0-9]+ not running|container '?[0-9]+'? (?:is )?not running!?|can only (?:push|pull) files (?:to|from) a running CT|.*\bFailed to get init pid\b.*)\.?$")
});
static NO_CONFIG: LazyLock<Regex> = LazyLock::new(|| line_regex(r"^Configuration file '[^']*' does not exist$"));
static LOCKED: LazyLock<Regex> = LazyLock::new(|| line_regex(r"^CT is locked(?: \([^)]*\))?\.?$"));
static MUST_BE_STOPPED: LazyLock<Regex> = LazyLock::new(|| line_regex(r"^Cannot run command on active container\.?$"));
static SUDO_REFUSED: LazyLock<Regex> = LazyLock::new(|| line_regex(r"^sudo: .*(?:password is required|a terminal is required|not allowed|not in the sudoers)"));
static PCT_MISSING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bpct\b.*(?:not found|No such file)").expect("valid pattern"));

/// Turns what pct and sudo answer into the errors an agent can act on. None when it is none of these.
pub fn pct_failure(res: &ExecResult, vmid: Option<i64>) -> Option<PveError> {
    if res.exit_code == Some(0) {
        return None;
    }
    let text = &res.stderr;
    if SUDO_REFUSED.is_match(text) {
        return Some(
            PveError::new(kind::SSH_AUTH_FAILED, "sudo -n was refused on the node.")
                .hint("The SSH user needs passwordless sudo for this, or the operator can connect as root.")
                .details(failure_details(res)),
        );
    }
    let vmid = vmid?;
    if NOT_RUNNING.is_match(text) {
        return Some(
            PveError::new(kind::GUEST_NOT_RUNNING, format!("Container {vmid} is not running: nothing was run in it."))
                .hint("pve_guest_power or pve_start_lxc starts it. Offline work has pve_lxc_mount and pve_lxc_fsck.")
                .details(failure_details(res)),
        );
    }
    if NO_CONFIG.is_match(text) {
        return Some(
            PveError::new(kind::NOT_FOUND, format!("Container {vmid} is not on this node."))
                .hint("It may have moved. Leave node out, so that it is found from the vmid.")
                .details(failure_details(res)),
        );
    }
    if LOCKED.is_match(text) {
        return Some(
            PveError::new(kind::GUEST_LOCKED, format!("Container {vmid} is locked: {}", js_trim(&tail(text, 200))))
                .hint("A backup or migration may be running. Check before trying again.")
                .details(failure_details(res)),
        );
    }
    if MUST_BE_STOPPED.is_match(text) {
        return Some(
            PveError::new(kind::INVALID_INPUT, format!("Container {vmid} is running, and this needs it stopped."))
                .hint("Stop it first, if that is acceptable, with pve_guest_power.")
                .details(failure_details(res)),
        );
    }
    None
}

/// A command that could not run its course: timed out, or stopped before starting properly.
pub fn assert_ran(res: &ExecResult, what: &str, vmid: Option<i64>) -> Result<()> {
    if res.timed_out {
        return Err(PveError::new(kind::SSH_TIMEOUT, format!("{what} did not finish in time, and its channel was closed."))
            .hint("It may still be running on the far side, and it may have done part of its work. Check before running it again, and give a larger timeout_seconds if needed.")
            .details(failure_details(res)));
    }
    if let Some(failure) = pct_failure(res, vmid) {
        return Err(failure);
    }
    if res.exit_code == Some(127) && PCT_MISSING.is_match(&res.stderr) {
        return Err(PveError::new(kind::NOT_SUPPORTED, "pct is not available on this host: it does not look like a Proxmox node.").details(failure_details(res)));
    }
    Ok(())
}

/// For commands of this server: a failure is an error. For arbitrary commands, the exit code is the answer.
pub fn assert_ok(res: &ExecResult, what: &str, vmid: Option<i64>) -> Result<()> {
    assert_ran(res, what, vmid)?;
    if res.dry_run || res.exit_code == Some(0) {
        return Ok(());
    }
    let reason = match js_trim(&res.stderr) {
        "" => js_trim(&res.stdout),
        s => s,
    };
    let code = res.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "null".into());
    let suffix = if reason.is_empty() { String::new() } else { format!(": {}", tail(reason, 500)) };
    Err(PveError::new(kind::UPSTREAM_ERROR, format!("{what} failed with exit code {code}{suffix}")).details(failure_details(res)))
}

/// The result of a command run for the agent.
pub fn present(res: &ExecResult, extra: Args) -> Value {
    let mut out = res.to_json();
    out.remove("host_key");
    if res.truncated {
        out.insert(
            "warning".into(),
            Value::String("Output over the cap was dropped: stdout and stderr hold only the start. Redirect to a file and read parts of it, or narrow the command.".into()),
        );
    }
    out.insert("untrusted".into(), Value::Bool(true));
    for (k, v) in extra {
        out.insert(k, v);
    }
    Value::Object(out)
}

/// Paths known to hold keys and password hashes, on a node as in a container.
static SECRET_PATHS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^/etc/pve/priv(?:/|$)",
        r"^/etc/pve/(?:local|nodes/[^/]+)/[^/]*\.key$",
        r"^/var/lib/pve-cluster/config\.db",
        r"^/etc/corosync/authkey$",
        r"^/etc/(?:shadow|gshadow)-?$",
        r"^/etc/security/opasswd$",
        r"^/etc/ssh/ssh_host_[^/]*_key$",
        r"^/(?:root|home/[^/]+)/\.ssh/id_[^/]*$",
        r"^/proc/[^/]+/environ$",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("valid pattern"))
    .collect()
});

/// path.posix.normalize of Node: . and .. resolved, slashes collapsed, a trailing slash kept.
pub fn posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let mut out = parts.join("/");
    if out.is_empty() && !absolute {
        out = ".".into();
    }
    if !out.is_empty() && trailing {
        out.push('/');
    }
    if absolute { format!("/{out}") } else { out }
}

pub fn is_secret_path(path: &str) -> bool {
    let normal = posix_normalize(path);
    if normal.ends_with(".pub") {
        return false;
    }
    SECRET_PATHS.iter().any(|p| p.is_match(&normal))
}

/// Both as asked and after links: a link in /tmp to /etc/shadow is /etc/shadow.
pub fn assert_not_secret(ctx: &ToolContext, paths: &[&str]) -> Result<()> {
    if ctx.instance.allow_sensitive {
        return Ok(());
    }
    for path in paths {
        if is_secret_path(path) {
            return Err(PveError::new(kind::SENSITIVE_DISABLED, format!("{path} holds key material or password hashes, and this server does not read those."))
                .hint("Do not retry and do not look for another route to the same file. The operator can allow it with PROXMOX_ALLOW_SENSITIVE=true."));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FileStat {
    /// Number() of what wc printed: NaN if it printed something else.
    pub size: f64,
    pub real: String,
}

/// How a script reaches where the file is: as it is on a node, or carried by pct exec.
pub type Wrap<'a> = &'a (dyn Fn(&str) -> Result<String> + Send + Sync);

/// Looks at a remote file through the given wrapper. None in a dry run, when nothing is known about it.
pub async fn stat_remote_file(ctx: &ToolContext, target: &SshTarget, wrap: Wrap<'_>, path: &str, vmid: Option<i64>) -> Result<Option<FileStat>> {
    assert_not_secret(ctx, &[path])?;
    let res = ctx.ssh.run(target, &ShellCommand::read(wrap(&file_stat_script(path)?)?), ExecOptions::default()).await?;
    if res.dry_run {
        return Ok(None);
    }
    let what = format!("Reading {path}");
    assert_ran(&res, &what, vmid)?;
    match res.exit_code {
        Some(EXIT_NOT_FOUND) => return Err(PveError::new(kind::NOT_FOUND, format!("{path} does not exist."))),
        Some(EXIT_NOT_A_FILE) => return Err(PveError::new(kind::INVALID_INPUT, format!("{path} is not a regular file.")).hint("The list_dir tools show directories.")),
        Some(EXIT_NOT_READABLE) => return Err(PveError::new(kind::FORBIDDEN, format!("{path} cannot be read by this user."))),
        _ => {}
    }
    assert_ok(&res, &what, vmid)?;
    let (size, rest) = res.stdout.split_once('\n').unwrap_or((res.stdout.as_str(), ""));
    // Only the one newline readlink adds: a file name can end with spaces, or with a newline of its own.
    let rest = rest.strip_suffix('\n').unwrap_or(rest);
    let real = if rest.is_empty() { path.to_string() } else { rest.to_string() };
    assert_not_secret(ctx, &[&real])?;
    Ok(Some(FileStat { size: crate::js::js_number_str(size).unwrap_or(f64::NAN), real }))
}

#[derive(Debug, Clone, Default)]
pub struct ReadFileArgs {
    pub path: String,
    pub max_bytes: Option<u64>,
    pub allow_partial: bool,
}

/// A file as text, refusing what is over the cap rather than returning less than was asked for.
pub async fn read_remote_file(ctx: &ToolContext, target: &SshTarget, wrap: Wrap<'_>, args: &ReadFileArgs, vmid: Option<i64>) -> Result<Value> {
    let stat = stat_remote_file(ctx, target, wrap, &args.path, vmid).await?;
    let limit = ctx.instance.ssh.max_output_bytes;
    let cap = args.max_bytes.unwrap_or(limit).min(limit);
    let Some(stat) = stat else { return Ok(Value::Object(obj! { "path" => &args.path })) };
    let partial = stat.size > cap as f64;
    if partial && !args.allow_partial {
        return Err(PveError::new(kind::SSH_OUTPUT_TOO_LARGE, format!("{} is {} bytes, over the limit of {cap}.", args.path, number_text(stat.size)))
            .hint("allow_partial returns the start of it. The pull_file and download tools copy a file of any size.")
            .details(json!({ "size": num(stat.size), "limit": cap })));
    }
    let script = read_file_script(&stat.real, if partial { Some(cap) } else { None })?;
    let res = ctx.ssh.run(target, &ShellCommand::read(wrap(&script)?), ExecOptions { timeout_ms: None, max_bytes: Some(cap) }).await?;
    assert_ok(&res, &format!("Reading {}", args.path), vmid)?;
    // Replacement characters mean this was not text: what came through is not the file.
    let binary = res.stdout.contains('\u{FFFD}');
    let mut out = obj! { "path" => &args.path };
    if stat.real != args.path {
        out.insert("resolved_path".into(), Value::String(stat.real.clone()));
    }
    out.insert("size".into(), num(stat.size));
    out.insert("content".into(), Value::String(res.stdout.clone()));
    out.insert("truncated".into(), Value::Bool(partial || res.truncated));
    if binary {
        out.insert("binary".into(), Value::Bool(true));
        out.insert("hint".into(), Value::String("This does not look like text, so content is not faithful. The pull_file and download tools copy it as it is.".into()));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

static LS_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([bcdlps-][rwxsStT-]{9}[.+@]?)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(?:[0-9]+,\s+)?([0-9]+)\s+(\S+\s+\S+\s+\S+)\s(.*)$").expect("valid pattern")
});
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("valid pattern"));

/// ls -la as GNU and BusyBox print it. Lines that are something else are left out.
/// Each row: mode, links, owner, group, size, modified, name, link_target?.
pub fn parse_ls(output: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in output.split('\n') {
        let Some(m) = LS_LINE.captures(line) else { continue };
        let mode = &m[1];
        let full = &m[7];
        let (name, target) = if mode.starts_with('l') {
            let mut parts = full.split(" -> ");
            (parts.next().unwrap_or(""), parts.next())
        } else {
            (full, None)
        };
        if name == "." || name == ".." {
            continue;
        }
        let number = |s: &str| num(s.parse::<f64>().unwrap_or(f64::NAN));
        let mut row = obj! {
            "mode" => mode,
            "links" => number(&m[2]),
            "owner" => &m[3],
            "group" => &m[4],
            "size" => number(&m[5]),
            "modified" => WHITESPACE.replace_all(&m[6], " ").into_owned(),
            "name" => name,
        };
        if let Some(t) = target.filter(|t| !t.is_empty()) {
            row.insert("link_target".into(), Value::String(t.to_string()));
        }
        rows.push(Value::Object(row));
    }
    rows
}

const PUBLIC_KEY_TYPES: [&str; 7] = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"];

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ParsedPublicKey {
    pub kind: String,
    pub blob: String,
    pub comment: Option<String>,
    pub fingerprint: String,
    /// The line to write: normalized, one line, no options.
    pub line: String,
}

const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true));

/// Buffer.from(text, 'base64'): characters outside the alphabet skipped, - and _ read as + and /,
/// decoding stops at padding, and a lone last character is dropped.
pub fn decode_base64(text: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(text.len());
    for b in text.bytes() {
        match b {
            b'=' => break,
            b'-' => data.push(b'+'),
            b'_' => data.push(b'/'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => data.push(b),
            _ => {}
        }
    }
    if data.len() % 4 == 1 {
        data.pop();
    }
    LENIENT_BASE64.decode(&data).unwrap_or_default()
}

static PUBLIC_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\S+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$").expect("valid pattern"));
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x00-\x1f\x7f]").expect("valid pattern"));
static SEVERAL_LINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\r\n\x00]").expect("valid pattern"));

/// One public key, with the blob checked against its declared type. An options prefix is not accepted here.
pub fn parse_public_key(text: &str) -> Result<ParsedPublicKey> {
    let refused = |why: String| {
        PveError::new(kind::INVALID_INPUT, format!("This is not an acceptable SSH public key: {why}."))
            .hint("Expected one line, such as: ssh-ed25519 AAAAC3Nza... user@host. Never pass a private key.")
    };
    let value = js_trim(text);
    if value.contains("PRIVATE KEY") {
        return Err(refused("it looks like a private key, which must not be sent anywhere".into()));
    }
    if SEVERAL_LINES.is_match(value) {
        return Err(refused("it spans several lines".into()));
    }
    let Some(m) = PUBLIC_KEY.captures(value) else { return Err(refused("it is not \"type base64 comment\"".into())) };
    let kind_name = m[1].to_string();
    let blob = m[2].to_string();
    let comment = m.get(3).map(|c| c.as_str().to_string()).filter(|c| !c.is_empty());
    if !PUBLIC_KEY_TYPES.contains(&kind_name.as_str()) {
        return Err(refused(format!("unknown key type \"{}\"", js_slice_start(&kind_name, 40))));
    }
    let key = decode_base64(&blob);
    if key_type_of(&key) != kind_name {
        return Err(refused("the key data does not match its declared type".into()));
    }
    if let Some(c) = &comment
        && CONTROL.is_match(c)
    {
        return Err(refused("the comment holds control characters".into()));
    }
    let line = match &comment {
        Some(c) => format!("{kind_name} {blob} {c}"),
        None => format!("{kind_name} {blob}"),
    };
    Ok(ParsedPublicKey { fingerprint: fingerprint_of(&key), kind: kind_name, blob, comment, line })
}

static AUTHORIZED_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:(.*?)\s+)?((?:ssh|ecdsa|sk)-[a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$").expect("valid pattern"));

#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeys {
    /// Each: type, fingerprint, blob, comment?, options?.
    pub keys: Vec<Map<String, Value>>,
    pub unparsed: usize,
}

impl AuthorizedKeys {
    /// keys, then unparsed, to spread into an answer.
    pub fn into_fields(self) -> Map<String, Value> {
        obj! { "keys" => Value::Array(self.keys.into_iter().map(Value::Object).collect()), "unparsed" => self.unparsed }
    }
}

/// authorized_keys lines, which may have options in front. Anything else is reported as unparsed.
pub fn parse_authorized_keys(output: &str) -> AuthorizedKeys {
    let mut out = AuthorizedKeys::default();
    for raw in output.split('\n') {
        let line = js_trim(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(m) = AUTHORIZED_KEY.captures(line).filter(|m| PUBLIC_KEY_TYPES.contains(&&m[2])) else {
            out.unparsed += 1;
            continue;
        };
        let key = decode_base64(&m[3]);
        let mut row = obj! { "type" => &m[2], "fingerprint" => fingerprint_of(&key), "blob" => &m[3] };
        if let Some(c) = m.get(4).map(|c| c.as_str()).filter(|c| !c.is_empty()) {
            row.insert("comment".into(), Value::String(c.to_string()));
        }
        if let Some(o) = m.get(1).map(|o| o.as_str()).filter(|o| !o.is_empty()) {
            row.insert("options".into(), Value::String(o.to_string()));
        }
        out.keys.push(row);
    }
    out
}

static SECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^@@([a-z-]+)$").expect("valid pattern"));
static HEADER_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-z_]+)=(.*)$").expect("valid pattern"));

/// Sections of a script that prints @@name lines.
pub fn parse_sections(output: &str) -> IndexMap<String, String> {
    let mut sections = IndexMap::new();
    let mut current = String::new();
    let mut body: Vec<&str> = Vec::new();
    for line in output.split('\n') {
        if let Some(m) = SECTION.captures(line) {
            if !current.is_empty() {
                sections.insert(current.clone(), js_trim(&body.join("\n")).to_string());
            }
            current = m[1].to_string();
            body.clear();
        } else {
            body.push(line);
        }
    }
    if !current.is_empty() {
        sections.insert(current, js_trim(&body.join("\n")).to_string());
    }
    sections
}

/// Splits leading key=value lines from what follows them.
pub fn parse_header(output: &str) -> (IndexMap<String, String>, String) {
    let mut header = IndexMap::new();
    let lines: Vec<&str> = output.split('\n').collect();
    let mut i = 0;
    while i < lines.len() {
        let Some(m) = HEADER_LINE.captures(lines[i]) else { break };
        header.insert(m[1].to_string(), m[2].to_string());
        i += 1;
    }
    (header, lines[i..].join("\n"))
}

/// A header as answer fields, in its order.
pub fn header_fields(header: &IndexMap<String, String>) -> Map<String, Value> {
    header.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_common_secret_paths() {
        assert!(is_secret_path("/etc/shadow"));
        assert!(is_secret_path("/etc/./shadow-"));
        assert!(is_secret_path("/tmp/../etc/pve/priv/authkey.key"));
        assert!(is_secret_path("/root/.ssh/id_ed25519"));
        assert!(!is_secret_path("/root/.ssh/id_ed25519.pub"));
        assert!(!is_secret_path("/etc/hostname"));
        assert_eq!(posix_normalize("//a/./b/../c/"), "/a/c/");
        assert_eq!(posix_normalize("/.."), "/");
    }

    #[test]
    fn ssh_common_parsers() {
        let ls = "total 8\ndrwxr-xr-x  2 root root 4096 Jan  1 00:00 .\n-rw-r--r--  1 root root   12 Jan  1  2024 a file\nlrwxrwxrwx  1 root root    7 Jan  1 00:00 l -> target\ncrw-rw-rw-  1 root root 1,   3 Jan  1 00:00 null\n";
        let rows = parse_ls(ls);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], json!({ "mode": "-rw-r--r--", "links": 1, "owner": "root", "group": "root", "size": 12, "modified": "Jan 1 2024", "name": "a file" }));
        assert_eq!(rows[1]["link_target"], "target");
        assert_eq!(rows[2]["size"], 3);
        let (header, rest) = parse_header("init=systemd\nmanager=apt\nrest\nx=y");
        assert_eq!(header.get("manager").map(String::as_str), Some("apt"));
        assert_eq!(rest, "rest\nx=y");
        let sections = parse_sections("ignored\n@@os\nNAME=x\n@@kernel\n Linux \n");
        assert_eq!(sections.keys().collect::<Vec<_>>(), ["os", "kernel"]);
        assert_eq!(sections["kernel"], "Linux");
    }

    #[test]
    fn ssh_common_public_keys() {
        // A real ed25519 public key blob: string "ssh-ed25519", then 32 bytes.
        let mut blob = vec![0, 0, 0, 11];
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&[0, 0, 0, 32]);
        blob.extend_from_slice(&[7u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let key = parse_public_key(&format!("  ssh-ed25519 {b64} me@host \n")).unwrap();
        assert_eq!(key.line, format!("ssh-ed25519 {b64} me@host"));
        assert_eq!(key.fingerprint, fingerprint_of(&blob));
        assert!(parse_public_key(&format!("ssh-rsa {b64}")).is_err());
        assert!(parse_public_key("-----BEGIN OPENSSH PRIVATE KEY-----").is_err());
        assert!(parse_public_key(&format!("ssh-ed25519 {b64}\nssh-ed25519 {b64}")).is_err());
        let listed = parse_authorized_keys(&format!("# c\nfrom=\"1.2.3.4\" ssh-ed25519 {b64} a b\nnonsense\n\nssh-ed25519 {b64}"));
        assert_eq!(listed.unparsed, 1);
        assert_eq!(listed.keys.len(), 2);
        assert_eq!(listed.keys[0]["options"], "from=\"1.2.3.4\"");
        assert_eq!(listed.keys[0]["comment"], "a b");
        assert!(!listed.keys[1].contains_key("comment"));
    }

    #[test]
    fn ssh_common_pct_failures() {
        let res = |code: i64, stderr: &str| ExecResult { exit_code: Some(code), stderr: stderr.into(), ..Default::default() };
        assert_eq!(pct_failure(&res(255, "CT 101 not running\n"), Some(101)).unwrap().kind, kind::GUEST_NOT_RUNNING);
        assert_eq!(pct_failure(&res(255, "Configuration file 'nodes/pve1/lxc/101.conf' does not exist\n"), Some(101)).unwrap().kind, kind::NOT_FOUND);
        assert_eq!(pct_failure(&res(255, "CT is locked (backup)\n"), Some(101)).unwrap().kind, kind::GUEST_LOCKED);
        assert_eq!(pct_failure(&res(1, "sudo: a password is required\n"), None).unwrap().kind, kind::SSH_AUTH_FAILED);
        assert!(pct_failure(&res(1, "my app: CT 101 not running, said the app\n"), Some(101)).is_none());
        assert!(pct_failure(&res(0, "CT 101 not running"), Some(101)).is_none());
        let err = assert_ok(&res(2, "  boom \n"), "Doing it", Some(101)).unwrap_err();
        assert_eq!(err.message, "Doing it failed with exit code 2: boom");
    }
}
