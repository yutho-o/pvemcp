//! Configuration: the environment, or PROXMOX_CONFIG for several clusters.

use crate::errors::{PveError, Result};
use crate::js::{js_number, js_string};
use crate::proxmox::policy::PolicySubject;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    Strict,
    AcceptNew,
    Off,
}

impl HostKeyPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            HostKeyPolicy::Strict => "strict",
            HostKeyPolicy::AcceptNew => "accept-new",
            HostKeyPolicy::Off => "off",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub user: String,
    pub port: u16,
    pub key_file: Option<String>,
    pub key_passphrase: Option<String>,
    pub password: Option<String>,
    /// Socket path, or "pageant".
    pub agent: Option<String>,
    /// Node name to host.
    pub nodes: IndexMap<String, String>,
    /// Prefixes commands with sudo -n when the user is not root.
    pub sudo: bool,
    pub known_hosts: String,
    pub host_key_policy: HostKeyPolicy,
    /// Node name to pinned SHA256:... fingerprint.
    pub fingerprints: IndexMap<String, String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub guest_user: Option<String>,
    pub guest_key_file: Option<String>,
    pub guest_password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub name: String,
    /// Base URL without trailing slash and without /api2/json. The port is always there.
    pub url: String,
    /// user@realm!tokenid
    pub token_id: Option<String>,
    pub token_secret: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub verify_ssl: bool,
    /// PEM bundle to trust, for a self-signed certificate with verification kept on.
    pub ca: Option<String>,
    /// sha256 of the server certificate, upper-case hex with colons.
    pub fingerprint: Option<String>,
    pub allow_writes: bool,
    pub allow_elevated: bool,
    pub allow_guest_exec: bool,
    pub allow_ssh: bool,
    pub allow_sensitive: bool,
    pub dry_run: bool,
    pub default_node: Option<String>,
    pub protected_vmids: BTreeSet<i64>,
    pub description: Option<String>,
    pub timeout_ms: u64,
    /// Root for local file transfers. None means they are refused.
    pub local_dir: Option<String>,
    pub ssh: SshConfig,
}

impl InstanceConfig {
    pub fn subject(&self) -> PolicySubject {
        PolicySubject {
            name: self.name.clone(),
            allow_writes: self.allow_writes,
            allow_elevated: self.allow_elevated,
            allow_guest_exec: self.allow_guest_exec,
            allow_sensitive: self.allow_sensitive,
            allow_ssh: self.allow_ssh,
            dry_run: self.dry_run,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub instances: IndexMap<String, InstanceConfig>,
    pub default_instance: String,
    /// None means the default toolsets.
    pub toolsets: Option<BTreeSet<String>>,
    pub task_wait_seconds: u64,
    pub audit_log: Option<String>,
    /// Endpoints the operator explicitly removed from the blocklist, as "METHOD /template" or "/template".
    pub unblocked: Vec<String>,
    pub elicit: bool,
    pub max_response_chars: usize,
}

pub type Env = HashMap<String, String>;

fn rx(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

static INSTANCE_NAME: LazyLock<Regex> = LazyLock::new(|| rx(r"^[A-Za-z0-9_-]{1,32}$"));
static FULL_TOKEN: LazyLock<Regex> = LazyLock::new(|| rx(r"^([^\s@!=]+@[^\s@!=]+![A-Za-z][A-Za-z0-9._-]*)=(\S+)$"));
static TOKEN_ID: LazyLock<Regex> = LazyLock::new(|| rx(r"^[^\s@!=]+@[^\s@!=]+![A-Za-z][A-Za-z0-9._-]*$"));
pub static NODE_NAME: LazyLock<Regex> = LazyLock::new(|| rx(r"^[A-Za-z0-9][A-Za-z0-9.-]*$"));
static SSH_FINGERPRINT: LazyLock<Regex> = LazyLock::new(|| rx(r"^SHA256:[A-Za-z0-9+/]{43}=?$"));
static CREDENTIAL_LINE: LazyLock<Regex> = LazyLock::new(|| rx(r"^(token|token_id|token_secret|username|password)\s*=\s*(.+)$"));
static TEMPLATE_VAR: LazyLock<Regex> = LazyLock::new(|| rx(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"));

fn config_error(message: impl Into<String>, hint: Option<&str>) -> PveError {
    let e = PveError::config(message);
    match hint {
        Some(h) => e.hint(h),
        None => e,
    }
}

/// A typo in a safety flag must stop the server, not silently fall back to a default.
fn parse_bool(name: &str, value: Option<&Value>, fallback: bool) -> Result<bool> {
    let v = match value {
        None | Some(Value::Null) => return Ok(fallback),
        Some(Value::Bool(b)) => return Ok(*b),
        Some(v) => v,
    };
    let text = js_string(v).trim().to_lowercase();
    match text.as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" | "" => Ok(false),
        _ => Err(config_error(format!("{name}: \"{}\" is not a boolean (use true or false).", js_string(v)), None)),
    }
}

fn parse_integer(name: &str, value: Option<&Value>, fallback: i64, min: i64, max: i64) -> Result<i64> {
    let v = match value {
        None | Some(Value::Null) => return Ok(fallback),
        Some(Value::String(s)) if s.is_empty() => return Ok(fallback),
        Some(v) => v,
    };
    match js_number(v) {
        Some(n) if n.is_finite() && n.fract() == 0.0 && n >= min as f64 && n <= max as f64 => Ok(n as i64),
        _ => Err(config_error(format!("{name}: \"{}\" must be an integer between {min} and {max}.", js_string(v)), None)),
    }
}

static HAS_SCHEME: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)^[a-z][a-z0-9+.-]*://"));
static AUTHORITY: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)^[a-z][a-z0-9+.-]*://([^/?#]*)"));
static HAS_PORT: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:\]|^[^\[\]]*):\d+$"));
static API_SUFFIX: LazyLock<Regex> = LazyLock::new(|| rx(r"/api2(?:/json)?$"));

fn normalize_url(raw: &str, label: &str) -> Result<String> {
    let with_scheme = if HAS_SCHEME.is_match(raw) { raw.to_string() } else { format!("https://{raw}") };
    let url = url::Url::parse(&with_scheme).map_err(|_| config_error(format!("{label}: \"{raw}\" is not a valid URL."), Some("Example: https://192.168.1.10:8006")))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(config_error(format!("{label}: only http and https URLs are supported."), None));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(config_error(format!("{label}: do not put credentials in the URL."), None));
    }
    // The URL parser drops :443 on https, so "no port given" has to be read from the text itself.
    let authority = AUTHORITY.captures(&with_scheme).map(|c| c[1].to_string()).unwrap_or_default();
    let host = if HAS_PORT.is_match(&authority) { authority } else { format!("{}:8006", url.host_str().unwrap_or("")) };
    let path = url.path().trim_end_matches('/');
    let path = API_SUFFIX.replace(path, "");
    Ok(format!("{}://{host}{path}", url.scheme()))
}

/// sha256 of a certificate, as Proxmox and openssl show it.
pub fn normalize_fingerprint(raw: &str, label: &str) -> Result<String> {
    let t = raw.trim();
    let t = if t.len() >= 7 && t[..6].eq_ignore_ascii_case("sha256") && matches!(&t[6..7], ":" | "=") { &t[7..] } else { t };
    let hex = t.replace(':', "").to_uppercase();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(config_error(
            format!("{label}: expected a sha256 fingerprint (64 hex digits, colons allowed)."),
            Some("On the node, pvenode cert info shows it. The web interface has it under Node > System > Certificates."),
        ));
    }
    Ok(hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":"))
}

#[derive(Default)]
struct Credentials {
    token: Option<String>,
    token_id: Option<String>,
    token_secret: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

/// key=value lines, or a single user@realm!id=secret line.
fn read_credentials_file(path: &str) -> Result<Credentials> {
    let text = std::fs::read_to_string(path).map_err(|e| config_error(format!("Cannot read credentials file {path}: {e}"), None))?;
    let mut out = Credentials::default();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if FULL_TOKEN.is_match(line) {
            out.token = Some(line.to_string());
            continue;
        }
        if let Some(m) = CREDENTIAL_LINE.captures(line) {
            let v = Some(m[2].to_string());
            match &m[1] {
                "token" => out.token = v,
                "token_id" => out.token_id = v,
                "token_secret" => out.token_secret = v,
                "username" => out.username = v,
                "password" => out.password = v,
                _ => {}
            }
        }
    }
    Ok(out)
}

fn read_text_file(path: &str, label: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| config_error(format!("Cannot read {label} {path}: {e}"), None))
}

/// Expands ${VAR} so instances.json never has to hold a secret in clear text.
fn expand(value: &Value, env: &Env, where_: &str) -> Result<Value> {
    Ok(match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| expand(v, env, where_)).collect::<Result<_>>()?),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| Ok((k.clone(), expand(v, env, where_)?))).collect::<Result<_>>()?),
        Value::String(s) => {
            let mut missing = None;
            let out = TEMPLATE_VAR.replace_all(s, |c: &regex::Captures| match env.get(&c[1]) {
                Some(v) => v.clone(),
                None => {
                    missing.get_or_insert_with(|| c[1].to_string());
                    String::new()
                }
            });
            if let Some(name) = missing {
                return Err(config_error(format!("{where_}: environment variable {name} is not set."), None));
            }
            Value::String(out.into_owned())
        }
        other => other.clone(),
    })
}

pub fn home_dir() -> PathBuf {
    #[allow(deprecated)]
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn expand_home(path: &str) -> String {
    if path == "~" {
        return home_dir().to_string_lossy().into_owned();
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return home_dir().join(rest).to_string_lossy().into_owned();
    }
    path.to_string()
}

/// JSON object, or a=1,b=2. Values may hold "=": an SSH fingerprint in base64 can.
pub fn parse_map(name: &str, value: Option<&Value>) -> Result<IndexMap<String, String>> {
    let mut out = IndexMap::new();
    let value = match value {
        None | Some(Value::Null) => return Ok(out),
        Some(Value::String(s)) if s.is_empty() => return Ok(out),
        Some(v) => v,
    };
    let mut put = |k: &str, v: &Value| -> Result<()> {
        match v {
            Value::String(s) if !s.is_empty() && NODE_NAME.is_match(k) => {
                out.insert(k.to_string(), s.clone());
                Ok(())
            }
            _ => Err(config_error(format!("{name}: invalid entry \"{k}\"."), Some("Use JSON or name=value,name=value."))),
        }
    };
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                put(k, v)?;
            }
        }
        Value::String(s) => {
            let text = s.trim();
            if text.starts_with('{') {
                let parsed: Value = serde_json::from_str(text).map_err(|e| config_error(format!("{name}: invalid JSON: {e}"), None))?;
                if let Value::Object(map) = parsed {
                    for (k, v) in &map {
                        put(k, v)?;
                    }
                }
            } else {
                for item in text.split(',') {
                    let at = item.find('=');
                    match at {
                        Some(at) if at > 0 => put(item[..at].trim(), &Value::String(item[at + 1..].trim().to_string()))?,
                        _ => return Err(config_error(format!("{name}: \"{item}\" is not name=value."), None)),
                    }
                }
            }
        }
        _ => return Err(config_error(format!("{name}: expected an object or name=value,name=value."), None)),
    }
    Ok(out)
}

fn parse_vmids(name: &str, value: Option<&Value>) -> Result<BTreeSet<i64>> {
    let mut out = BTreeSet::new();
    let items: Vec<Value> = match value {
        None | Some(Value::Null) => return Ok(out),
        Some(Value::String(s)) if s.is_empty() => return Ok(out),
        Some(Value::Array(a)) => a.clone(),
        Some(v) => js_string(v).split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string())).collect(),
    };
    for item in items {
        match js_number(&item) {
            Some(n) if n.fract() == 0.0 && (1.0..=999_999_999.0).contains(&n) => {
                out.insert(n as i64);
            }
            _ => return Err(config_error(format!("{name}: \"{}\" is not a vmid.", js_string(&item)), None)),
        }
    }
    Ok(out)
}

struct Defaults {
    allow_writes: bool,
    allow_elevated: bool,
    allow_guest_exec: bool,
    allow_ssh: bool,
    allow_sensitive: bool,
    dry_run: bool,
    verify_ssl: bool,
    timeout_ms: u64,
    default_node: Option<String>,
    protected_vmids: BTreeSet<i64>,
    local_dir: Option<String>,
    ca: Option<String>,
    fingerprint: Option<String>,
    ssh: Map<String, Value>,
}

fn env_value(env: &Env, name: &str) -> Option<Value> {
    env.get(name).map(|v| Value::String(v.clone()))
}

/// What was read from the environment: the instance values override it.
fn ssh_from_env(env: &Env) -> Map<String, Value> {
    let pairs = [
        ("user", "PROXMOX_SSH_USER"),
        ("port", "PROXMOX_SSH_PORT"),
        ("key_file", "PROXMOX_SSH_KEY_FILE"),
        ("key_passphrase", "PROXMOX_SSH_KEY_PASSPHRASE"),
        ("password", "PROXMOX_SSH_PASSWORD"),
        ("agent", "PROXMOX_SSH_AGENT"),
        ("nodes", "PROXMOX_SSH_NODES"),
        ("sudo", "PROXMOX_SSH_SUDO"),
        ("known_hosts", "PROXMOX_SSH_KNOWN_HOSTS"),
        ("host_key_policy", "PROXMOX_SSH_HOST_KEY_POLICY"),
        ("fingerprints", "PROXMOX_SSH_FINGERPRINTS"),
        ("timeout_seconds", "PROXMOX_SSH_TIMEOUT_SECONDS"),
        ("max_output_bytes", "PROXMOX_SSH_MAX_OUTPUT_BYTES"),
        ("guest_user", "PROXMOX_GUEST_SSH_USER"),
        ("guest_key_file", "PROXMOX_GUEST_SSH_KEY_FILE"),
        ("guest_password", "PROXMOX_GUEST_SSH_PASSWORD"),
    ];
    let mut out = Map::new();
    for (key, var) in pairs {
        if let Some(v) = env_value(env, var) {
            out.insert(key.into(), v);
        }
    }
    out
}

fn nonempty(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn build_ssh(where_: &str, raw_instance: Option<&Value>, defaults: &Map<String, Value>, env: Option<&Env>, allow_ssh: bool) -> Result<SshConfig> {
    let mut merged = defaults.clone();
    if let Some(Value::Object(raw)) = raw_instance {
        for (k, v) in raw {
            merged.insert(k.clone(), match env {
                Some(env) => expand(v, env, where_)?,
                None => v.clone(),
            });
        }
    }
    let policy = nonempty(merged.get("host_key_policy")).unwrap_or_else(|| "strict".into());
    let host_key_policy = match policy.as_str() {
        "strict" => HostKeyPolicy::Strict,
        "accept-new" => HostKeyPolicy::AcceptNew,
        "off" => HostKeyPolicy::Off,
        _ => return Err(config_error(format!("{where_} host_key_policy: \"{policy}\" must be strict, accept-new or off."), None)),
    };
    let ssh = SshConfig {
        user: nonempty(merged.get("user")).unwrap_or_else(|| "root".into()),
        port: parse_integer(&format!("{where_} ssh port"), merged.get("port"), 22, 1, 65_535)? as u16,
        nodes: parse_map(&format!("{where_} ssh nodes"), merged.get("nodes"))?,
        sudo: parse_bool(&format!("{where_} ssh sudo"), merged.get("sudo"), false)?,
        known_hosts: expand_home(&nonempty(merged.get("known_hosts")).unwrap_or_else(|| home_dir().join(".ssh").join("known_hosts").to_string_lossy().into_owned())),
        host_key_policy,
        fingerprints: parse_map(&format!("{where_} ssh fingerprints"), merged.get("fingerprints"))?,
        timeout_ms: parse_integer(&format!("{where_} ssh timeout_seconds"), merged.get("timeout_seconds"), 120, 1, 86_400)? as u64 * 1000,
        max_output_bytes: parse_integer(&format!("{where_} ssh max_output_bytes"), merged.get("max_output_bytes"), 1_048_576, 1024, 1_073_741_824)? as u64,
        key_file: nonempty(merged.get("key_file")).map(|p| expand_home(&p)),
        key_passphrase: nonempty(merged.get("key_passphrase")),
        password: nonempty(merged.get("password")),
        agent: nonempty(merged.get("agent")),
        guest_user: nonempty(merged.get("guest_user")),
        guest_key_file: nonempty(merged.get("guest_key_file")).map(|p| expand_home(&p)),
        guest_password: nonempty(merged.get("guest_password")),
    };
    for (node, fingerprint) in &ssh.fingerprints {
        if !SSH_FINGERPRINT.is_match(fingerprint) {
            return Err(config_error(format!("{where_} ssh fingerprints: \"{fingerprint}\" for {node} is not a SHA256:... fingerprint."), Some("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub shows it.")));
        }
    }
    // Only when SSH is on: a stale path is no reason to stop a server that will never use it.
    if allow_ssh {
        if let Some(k) = &ssh.key_file {
            read_text_file(k, &format!("{where_} SSH key file"))?;
        }
        if let Some(k) = &ssh.guest_key_file {
            read_text_file(k, &format!("{where_} guest SSH key file"))?;
        }
        if ssh.key_file.is_none() && ssh.password.is_none() && ssh.agent.is_none() {
            return Err(config_error(format!("{where_}: PROXMOX_ALLOW_SSH is on, but no SSH credential is set."), Some("Set PROXMOX_SSH_KEY_FILE, PROXMOX_SSH_AGENT or PROXMOX_SSH_PASSWORD.")));
        }
    }
    Ok(ssh)
}

/// Env is None when the values already come from the environment: they are not templates.
fn build_instance(name: &str, raw: &Map<String, Value>, env: Option<&Env>, defaults: &Defaults) -> Result<InstanceConfig> {
    if !INSTANCE_NAME.is_match(name) {
        return Err(config_error(format!("Invalid instance name \"{name}\": use letters, digits, - and _ (32 characters at most)."), None));
    }
    let where_ = format!("instance \"{name}\"");
    let value = |key: &str| -> Result<Option<Value>> {
        match (raw.get(key), env) {
            (None, _) => Ok(None),
            (Some(v), Some(env)) => Ok(Some(expand(v, env, &where_)?)),
            (Some(v), None) => Ok(Some(v.clone())),
        }
    };
    let str_ = |key: &str| -> Result<Option<String>> { Ok(nonempty(value(key)?.as_ref())) };
    let url_raw = str_("url")?.ok_or_else(|| config_error(format!("{where_}: url is required."), None))?;

    let from_file = match str_("credentials_file")? {
        Some(file) => read_credentials_file(&file)?,
        None => Credentials::default(),
    };
    let raw_token_id = str_("token_id")?;
    let token = str_("token")?.or(if raw_token_id.is_none() { from_file.token.clone() } else { None });
    let mut token_id = raw_token_id.or(from_file.token_id.clone());
    let mut token_secret = str_("token_secret")?.or(from_file.token_secret.clone());
    if let Some(token) = token {
        let stripped = token.strip_prefix("PVEAPIToken=").unwrap_or(&token);
        let m = FULL_TOKEN.captures(stripped).ok_or_else(|| config_error(format!("{where_}: the token must look like user@realm!tokenid=secret."), None))?;
        token_id = Some(m[1].to_string());
        token_secret = Some(m[2].to_string());
    }
    if token_id.is_some() != token_secret.is_some() {
        return Err(config_error(format!("{where_}: a token needs both its id and its secret."), Some("PROXMOX_TOKEN_ID is user@realm!tokenid, PROXMOX_TOKEN_SECRET is the UUID.")));
    }
    if let Some(id) = &token_id {
        if !TOKEN_ID.is_match(id) {
            return Err(config_error(format!("{where_}: the token id must look like user@realm!tokenid."), None));
        }
    }
    let username = str_("username")?.or(from_file.username.clone());
    let password = str_("password")?.or(from_file.password.clone());
    if token_id.is_none() {
        match (&username, &password) {
            (Some(u), Some(_)) => {
                if !u.contains('@') {
                    return Err(config_error(format!("{where_}: the username needs its realm, such as root@pam."), None));
                }
            }
            _ => {
                return Err(config_error(
                    format!("{where_}: no credentials."),
                    Some("Set PROXMOX_TOKEN (recommended), PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET, PROXMOX_CREDENTIALS_FILE, or PROXMOX_USERNAME and PROXMOX_PASSWORD."),
                ));
            }
        }
    }

    let allow_ssh = parse_bool(&format!("{where_} allow_ssh"), value("allow_ssh")?.as_ref(), defaults.allow_ssh)?;
    let has_token = token_id.is_some() && token_secret.is_some();
    let mut instance = InstanceConfig {
        name: name.to_string(),
        url: normalize_url(&url_raw, &where_)?,
        verify_ssl: parse_bool(&format!("{where_} verify_ssl"), value("verify_ssl")?.as_ref(), defaults.verify_ssl)?,
        allow_writes: parse_bool(&format!("{where_} allow_writes"), value("allow_writes")?.as_ref(), defaults.allow_writes)?,
        allow_elevated: parse_bool(&format!("{where_} allow_elevated"), value("allow_elevated")?.as_ref(), defaults.allow_elevated)?,
        allow_guest_exec: parse_bool(&format!("{where_} allow_guest_exec"), value("allow_guest_exec")?.as_ref(), defaults.allow_guest_exec)?,
        allow_ssh,
        allow_sensitive: parse_bool(&format!("{where_} allow_sensitive"), value("allow_sensitive")?.as_ref(), defaults.allow_sensitive)?,
        dry_run: parse_bool(&format!("{where_} dry_run"), value("dry_run")?.as_ref(), defaults.dry_run)?,
        protected_vmids: if raw.contains_key("protected_vmids") { parse_vmids(&format!("{where_} protected_vmids"), value("protected_vmids")?.as_ref())? } else { defaults.protected_vmids.clone() },
        timeout_ms: if raw.contains_key("timeout_seconds") { parse_integer(&format!("{where_} timeout_seconds"), value("timeout_seconds")?.as_ref(), 30, 1, 3600)? as u64 * 1000 } else { defaults.timeout_ms },
        ssh: build_ssh(&where_, raw.get("ssh"), &defaults.ssh, env, allow_ssh)?,
        token_id: None,
        token_secret: None,
        username: None,
        password: None,
        ca: None,
        fingerprint: None,
        default_node: None,
        description: None,
        local_dir: None,
    };
    if has_token {
        instance.token_id = token_id;
        instance.token_secret = token_secret;
    } else {
        instance.username = username;
        instance.password = password;
    }
    instance.ca = match str_("ca_file")? {
        Some(file) => Some(read_text_file(&file, "CA file")?),
        None => defaults.ca.clone(),
    };
    instance.fingerprint = match str_("fingerprint")? {
        Some(fp) => Some(normalize_fingerprint(&fp, &format!("{where_} fingerprint"))?),
        None => defaults.fingerprint.clone(),
    };
    instance.description = str_("description")?;
    if let Some(node) = str_("default_node")?.or(defaults.default_node.clone()) {
        if !NODE_NAME.is_match(&node) {
            return Err(config_error(format!("{where_}: \"{node}\" is not a node name."), None));
        }
        instance.default_node = Some(node);
    }
    instance.local_dir = str_("local_dir")?.or(defaults.local_dir.clone()).map(|d| expand_home(&d));
    Ok(instance)
}

fn env_nonempty<'a>(env: &'a Env, name: &str) -> Option<&'a str> {
    env.get(name).map(String::as_str).filter(|s| !s.is_empty())
}

pub fn load_config(env: &Env) -> Result<ServerConfig> {
    let ev = |name: &str| env_value(env, name);
    let mut defaults = Defaults {
        allow_writes: parse_bool("PROXMOX_ALLOW_WRITES", ev("PROXMOX_ALLOW_WRITES").as_ref(), false)?,
        allow_elevated: parse_bool("PROXMOX_ALLOW_ELEVATED", ev("PROXMOX_ALLOW_ELEVATED").as_ref(), false)?,
        allow_guest_exec: parse_bool("PROXMOX_ALLOW_GUEST_EXEC", ev("PROXMOX_ALLOW_GUEST_EXEC").as_ref(), false)?,
        allow_ssh: parse_bool("PROXMOX_ALLOW_SSH", ev("PROXMOX_ALLOW_SSH").as_ref(), false)?,
        allow_sensitive: parse_bool("PROXMOX_ALLOW_SENSITIVE", ev("PROXMOX_ALLOW_SENSITIVE").as_ref(), false)?,
        dry_run: parse_bool("PROXMOX_DRY_RUN", ev("PROXMOX_DRY_RUN").as_ref(), false)?,
        verify_ssl: parse_bool("PROXMOX_VERIFY_SSL", ev("PROXMOX_VERIFY_SSL").as_ref(), true)?,
        timeout_ms: parse_integer("PROXMOX_TIMEOUT_SECONDS", ev("PROXMOX_TIMEOUT_SECONDS").as_ref(), 30, 1, 3600)? as u64 * 1000,
        protected_vmids: parse_vmids("PROXMOX_PROTECTED_VMIDS", ev("PROXMOX_PROTECTED_VMIDS").as_ref())?,
        ssh: ssh_from_env(env),
        default_node: env_nonempty(env, "PROXMOX_DEFAULT_NODE").map(str::to_string),
        local_dir: env_nonempty(env, "PROXMOX_LOCAL_DIR").map(str::to_string),
        ca: None,
        fingerprint: None,
    };
    if let Some(ca) = env_nonempty(env, "PROXMOX_CA_FILE") {
        defaults.ca = Some(read_text_file(ca, "PROXMOX_CA_FILE")?);
    }
    if let Some(fp) = env_nonempty(env, "PROXMOX_FINGERPRINT") {
        defaults.fingerprint = Some(normalize_fingerprint(fp, "PROXMOX_FINGERPRINT")?);
    }

    let mut instances = IndexMap::new();
    let mut default_instance = None;

    if let Some(path) = env_nonempty(env, "PROXMOX_CONFIG") {
        let parsed: Value = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            .map_err(|e| config_error(format!("Cannot read PROXMOX_CONFIG ({path}): {e}"), None))?;
        if let Some(Value::Object(raw_instances)) = parsed.get("instances") {
            for (name, raw) in raw_instances {
                let empty = Map::new();
                let raw = raw.as_object().unwrap_or(&empty);
                instances.insert(name.clone(), build_instance(name, raw, Some(env), &defaults)?);
            }
        }
        if instances.is_empty() {
            return Err(config_error("PROXMOX_CONFIG defines no instances.", None));
        }
        if let Some(Value::String(d)) = parsed.get("default") {
            if !instances.contains_key(d) {
                return Err(config_error(format!("Default instance \"{d}\" is not defined."), None));
            }
            default_instance = Some(d.clone());
        }
    } else {
        if env_nonempty(env, "PROXMOX_URL").is_none() {
            return Err(config_error("PROXMOX_URL is not set.", Some("Set PROXMOX_URL and PROXMOX_TOKEN, or PROXMOX_CONFIG for several clusters.")));
        }
        let mut raw = Map::new();
        for (key, var) in [("url", "PROXMOX_URL"), ("token", "PROXMOX_TOKEN"), ("token_id", "PROXMOX_TOKEN_ID"), ("token_secret", "PROXMOX_TOKEN_SECRET"), ("credentials_file", "PROXMOX_CREDENTIALS_FILE"), ("username", "PROXMOX_USERNAME"), ("password", "PROXMOX_PASSWORD")] {
            if let Some(v) = ev(var) {
                raw.insert(key.into(), v);
            }
        }
        instances.insert("default".to_string(), build_instance("default", &raw, None, &defaults)?);
    }

    let toolsets = env_nonempty(env, "PROXMOX_TOOLSETS").map(|t| t.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect());
    let default_instance = default_instance.unwrap_or_else(|| instances.keys().next().unwrap().clone());
    Ok(ServerConfig {
        instances,
        default_instance,
        toolsets,
        task_wait_seconds: parse_integer("PROXMOX_TASK_WAIT_SECONDS", ev("PROXMOX_TASK_WAIT_SECONDS").as_ref(), 30, 0, 3600)? as u64,
        unblocked: env.get("PROXMOX_UNBLOCK").map(|u| u.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        elicit: parse_bool("PROXMOX_ELICIT", ev("PROXMOX_ELICIT").as_ref(), true)?,
        max_response_chars: parse_integer("PROXMOX_MAX_RESPONSE_CHARS", ev("PROXMOX_MAX_RESPONSE_CHARS").as_ref(), 120_000, 2_000, 5_000_000)? as usize,
        audit_log: env_nonempty(env, "PROXMOX_AUDIT_LOG").map(str::to_string),
    })
}

pub fn process_env() -> Env {
    std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn loads() {
        let c = load_config(&env(&[("PROXMOX_URL", "pve.lan"), ("PROXMOX_TOKEN", "root@pam!mcp=abc")])).unwrap();
        let i = &c.instances["default"];
        assert_eq!(i.url, "https://pve.lan:8006");
        assert_eq!(i.token_id.as_deref(), Some("root@pam!mcp"));
        let c = load_config(&env(&[("PROXMOX_URL", "https://h:443/api2/json/"), ("PROXMOX_TOKEN", "root@pam!mcp=abc")])).unwrap();
        assert_eq!(c.instances["default"].url, "https://h:443");
        assert!(load_config(&env(&[("PROXMOX_URL", "h"), ("PROXMOX_TOKEN", "x"), ("PROXMOX_ALLOW_WRITES", "maybe")])).is_err());
        assert_eq!(normalize_fingerprint("sha256:aabb".repeat(1).as_str(), "x").is_err(), true);
    }

    // Ported from test/config.test.ts.

    use serde_json::json;
    use std::path::Path;

    const TLS_FINGERPRINT: &str = "5A:3B:45:BD:1E:03:2C:27:8D:40:93:AE:FB:CA:69:BB:D4:57:6F:AD:F7:09:BD:04:6A:C9:34:D2:B9:00:C9:2B";

    /// A directory of its own for each test, removed at the end.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> TempDir {
            let dir = std::env::temp_dir().join(format!("pvemcp-config-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn file(&self, name: &str, content: &str) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, content).unwrap();
            path.to_string_lossy().into_owned()
        }
        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
        fn dir(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// BASE plus these. None removes a variable, as undefined did.
    fn env_with(over: &[(&str, Option<&str>)]) -> Env {
        let mut e = env(&[("PROXMOX_URL", "https://pve.example"), ("PROXMOX_TOKEN", "mcp@pve!t=secret")]);
        for (k, v) in over {
            match v {
                Some(v) => e.insert(k.to_string(), v.to_string()),
                None => e.remove(*k),
            };
        }
        e
    }

    fn load(over: &[(&str, Option<&str>)]) -> (ServerConfig, InstanceConfig) {
        let config = load_config(&env_with(over)).unwrap_or_else(|e| panic!("{}", e.message));
        let instance = config.instances[&config.default_instance].clone();
        (config, instance)
    }

    fn refusal(over: &[(&str, Option<&str>)]) -> PveError {
        match load_config(&env_with(over)) {
            Ok(_) => panic!("expected a config error for {over:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn normalizes_urls() {
        for (raw, want) in [
            ("https://pve.example", "https://pve.example:8006"),
            ("https://pve.example/", "https://pve.example:8006"),
            ("https://pve.example:8006", "https://pve.example:8006"),
            ("https://pve.example:443", "https://pve.example:443"),
            ("http://pve.example:80", "http://pve.example:80"),
            ("pve.example", "https://pve.example:8006"),
            ("https://pve.example:8006/api2/json", "https://pve.example:8006"),
            ("https://proxy.example/pve/", "https://proxy.example:8006/pve"),
            ("https://[fd00::1]", "https://[fd00::1]:8006"),
            ("https://[fd00::1]:9000", "https://[fd00::1]:9000"),
            ("https://10.0.0.1", "https://10.0.0.1:8006"),
        ] {
            assert_eq!(load(&[("PROXMOX_URL", Some(raw))]).1.url, want, "{raw}");
        }
    }

    #[test]
    fn refuses_credentials_in_the_url_other_schemes_and_nonsense() {
        assert_eq!(refusal(&[("PROXMOX_URL", Some("https://user:pw@pve.example"))]).kind, "config_error");
        assert_eq!(refusal(&[("PROXMOX_URL", Some("ftp://pve.example"))]).kind, "config_error");
        assert_eq!(refusal(&[("PROXMOX_URL", Some("http://"))]).kind, "config_error");
        assert!(refusal(&[("PROXMOX_URL", None)]).message.contains("PROXMOX_URL"));
    }

    #[test]
    fn reads_tokens() {
        let (_, i) = load(&[]);
        assert_eq!(i.token_id.as_deref(), Some("mcp@pve!t"));
        assert_eq!(i.token_secret.as_deref(), Some("secret"));
        assert!(i.password.is_none());
        assert_eq!(load(&[("PROXMOX_TOKEN", Some("PVEAPIToken=a@b!c=d"))]).1.token_id.as_deref(), Some("a@b!c"));
        let (_, i) = load(&[("PROXMOX_TOKEN", None), ("PROXMOX_TOKEN_ID", Some("a@b!c")), ("PROXMOX_TOKEN_SECRET", Some("d"))]);
        assert_eq!(i.token_id.as_deref(), Some("a@b!c"));
        assert_eq!(i.token_secret.as_deref(), Some("d"));
        let (_, i) = load(&[("PROXMOX_TOKEN", None), ("PROXMOX_USERNAME", Some("root@pam")), ("PROXMOX_PASSWORD", Some("p"))]);
        assert_eq!(i.username.as_deref(), Some("root@pam"));
        assert!(i.token_id.is_none());
    }

    #[test]
    fn reads_a_credentials_file_in_both_shapes() {
        let dir = TempDir::new();
        let a = dir.file("cred-a", "# my token\ntoken_id = a@b!c\ntoken_secret=d\n");
        assert_eq!(load(&[("PROXMOX_TOKEN", None), ("PROXMOX_CREDENTIALS_FILE", Some(&a))]).1.token_secret.as_deref(), Some("d"));
        let b = dir.file("cred-b", "x@y!z=w\r\n");
        assert_eq!(load(&[("PROXMOX_TOKEN", None), ("PROXMOX_CREDENTIALS_FILE", Some(&b))]).1.token_id.as_deref(), Some("x@y!z"));
        let c = dir.file("cred-c", "username=root@pam\npassword=a=b\n");
        assert_eq!(load(&[("PROXMOX_TOKEN", None), ("PROXMOX_CREDENTIALS_FILE", Some(&c))]).1.password.as_deref(), Some("a=b"));
    }

    #[test]
    fn refuses_credentials_that_cannot_work() {
        let dir = TempDir::new();
        assert!(refusal(&[("PROXMOX_TOKEN", Some("nonsense"))]).message.contains("user@realm!tokenid=secret"));
        assert!(refusal(&[("PROXMOX_TOKEN", None)]).message.contains("no credentials"));
        assert!(refusal(&[("PROXMOX_TOKEN", None), ("PROXMOX_TOKEN_ID", Some("a@b!c"))]).message.contains("both"));
        assert!(refusal(&[("PROXMOX_TOKEN", None), ("PROXMOX_TOKEN_SECRET", Some("x"))]).message.contains("both"));
        assert_eq!(refusal(&[("PROXMOX_TOKEN", None), ("PROXMOX_TOKEN_ID", Some("nope")), ("PROXMOX_TOKEN_SECRET", Some("x"))]).kind, "config_error");
        assert!(refusal(&[("PROXMOX_TOKEN", None), ("PROXMOX_USERNAME", Some("root")), ("PROXMOX_PASSWORD", Some("p"))]).message.contains("realm"));
        let missing = dir.path("missing");
        assert!(refusal(&[("PROXMOX_TOKEN", None), ("PROXMOX_CREDENTIALS_FILE", Some(&missing))]).message.contains("Cannot read"));
    }

    #[test]
    fn defaults_to_closed() {
        let (c, i) = load(&[]);
        assert!(!i.allow_writes && !i.allow_elevated && !i.allow_guest_exec && !i.allow_ssh && !i.allow_sensitive && !i.dry_run);
        assert!(i.verify_ssl);
        assert_eq!(c.task_wait_seconds, 30);
        assert!(c.elicit);
        assert_eq!(c.max_response_chars, 120_000);
        assert!(c.toolsets.is_none());
        assert!(c.unblocked.is_empty());
        assert!(i.protected_vmids.is_empty());
        assert_eq!(i.timeout_ms, 30_000);
    }

    #[test]
    fn a_typo_in_a_flag_stops_the_server() {
        for name in ["PROXMOX_ALLOW_WRITES", "PROXMOX_ALLOW_ELEVATED", "PROXMOX_ALLOW_GUEST_EXEC", "PROXMOX_ALLOW_SSH", "PROXMOX_ALLOW_SENSITIVE", "PROXMOX_DRY_RUN", "PROXMOX_VERIFY_SSL", "PROXMOX_ELICIT", "PROXMOX_SSH_SUDO"] {
            assert!(refusal(&[(name, Some("ture"))]).message.contains("not a boolean"), "{name}");
        }
    }

    #[test]
    fn a_bad_number_stops_the_server() {
        for (name, value) in [
            ("PROXMOX_TIMEOUT_SECONDS", "0"),
            ("PROXMOX_TIMEOUT_SECONDS", "abc"),
            ("PROXMOX_TASK_WAIT_SECONDS", "3601"),
            ("PROXMOX_MAX_RESPONSE_CHARS", "1"),
            ("PROXMOX_SSH_PORT", "70000"),
            ("PROXMOX_SSH_TIMEOUT_SECONDS", "-1"),
            ("PROXMOX_SSH_MAX_OUTPUT_BYTES", "1.5"),
        ] {
            assert!(refusal(&[(name, Some(value))]).message.contains("must be an integer"), "{name}={value}");
        }
    }

    #[test]
    fn reads_the_rest() {
        let dir = TempDir::new();
        let d = dir.dir();
        let (c, i) = load(&[
            ("PROXMOX_ALLOW_WRITES", Some("yes")),
            ("PROXMOX_ALLOW_ELEVATED", Some("1")),
            ("PROXMOX_VERIFY_SSL", Some("false")),
            ("PROXMOX_DEFAULT_NODE", Some("pve2")),
            ("PROXMOX_PROTECTED_VMIDS", Some("100, 101")),
            ("PROXMOX_UNBLOCK", Some("POST /nodes/{node}/execute, /access/ticket")),
            ("PROXMOX_TASK_WAIT_SECONDS", Some("5")),
            ("PROXMOX_ELICIT", Some("off")),
            ("PROXMOX_TOOLSETS", Some("VM, lxc")),
            ("PROXMOX_LOCAL_DIR", Some(&d)),
        ]);
        assert!(i.allow_writes && i.allow_elevated && !i.verify_ssl);
        assert_eq!(i.default_node.as_deref(), Some("pve2"));
        assert_eq!(i.local_dir.as_deref(), Some(d.as_str()));
        assert_eq!(i.protected_vmids.iter().copied().collect::<Vec<_>>(), vec![100, 101]);
        assert_eq!(c.unblocked, vec!["POST /nodes/{node}/execute", "/access/ticket"]);
        assert_eq!(c.task_wait_seconds, 5);
        assert!(!c.elicit);
        let toolsets = c.toolsets.unwrap();
        assert_eq!(toolsets.len(), 2);
        assert!(toolsets.contains("vm") && toolsets.contains("lxc"));
    }

    #[test]
    fn refuses_a_bad_vmid_or_node_name() {
        assert!(refusal(&[("PROXMOX_PROTECTED_VMIDS", Some("100,abc"))]).message.contains("not a vmid"));
        assert!(refusal(&[("PROXMOX_DEFAULT_NODE", Some("a/b"))]).message.contains("not a node name"));
    }

    #[test]
    fn tls_settings() {
        let lower = TLS_FINGERPRINT.replace(':', "").to_lowercase();
        assert_eq!(normalize_fingerprint(&lower, "x").unwrap(), TLS_FINGERPRINT);
        assert_eq!(normalize_fingerprint(&format!("sha256:{TLS_FINGERPRINT}"), "x").unwrap(), TLS_FINGERPRINT);
        assert_eq!(load(&[("PROXMOX_FINGERPRINT", Some(TLS_FINGERPRINT))]).1.fingerprint.as_deref(), Some(TLS_FINGERPRINT));
        assert!(normalize_fingerprint("AA:BB", "x").unwrap_err().message.contains("sha256"));

        let dir = TempDir::new();
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUWgAwIBAgIUNkfR8CJTUAp\n-----END CERTIFICATE-----\n";
        let file = dir.file("ca.pem", pem);
        assert_eq!(load(&[("PROXMOX_CA_FILE", Some(&file))]).1.ca.as_deref(), Some(pem));
        let nope = dir.path("nope");
        assert!(refusal(&[("PROXMOX_CA_FILE", Some(&nope))]).message.contains("Cannot read"));
    }

    #[test]
    fn ssh_has_fail_closed_defaults() {
        let ssh = load(&[]).1.ssh;
        assert_eq!(ssh.user, "root");
        assert_eq!(ssh.port, 22);
        assert!(!ssh.sudo);
        assert_eq!(ssh.host_key_policy, HostKeyPolicy::Strict);
        assert_eq!(ssh.timeout_ms, 120_000);
        assert_eq!(ssh.max_output_bytes, 1_048_576);
        assert!(ssh.nodes.is_empty() && ssh.fingerprints.is_empty());
        assert_eq!(Path::new(&ssh.known_hosts), home_dir().join(".ssh").join("known_hosts"));
    }

    #[test]
    fn ssh_reads_every_setting() {
        let dir = TempDir::new();
        let key = dir.file("id_test", "not really a key");
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        let fps = format!("pve1={fingerprint}");
        let (_, i) = load(&[
            ("PROXMOX_ALLOW_SSH", Some("true")),
            ("PROXMOX_SSH_USER", Some("ops")),
            ("PROXMOX_SSH_PORT", Some("2222")),
            ("PROXMOX_SSH_KEY_FILE", Some(&key)),
            ("PROXMOX_SSH_KEY_PASSPHRASE", Some("pp")),
            ("PROXMOX_SSH_PASSWORD", Some("pw")),
            ("PROXMOX_SSH_AGENT", Some("pageant")),
            ("PROXMOX_SSH_NODES", Some("pve1=10.0.0.1,pve2=10.0.0.2")),
            ("PROXMOX_SSH_SUDO", Some("true")),
            ("PROXMOX_SSH_KNOWN_HOSTS", Some("~/custom_known_hosts")),
            ("PROXMOX_SSH_HOST_KEY_POLICY", Some("accept-new")),
            ("PROXMOX_SSH_FINGERPRINTS", Some(&fps)),
            ("PROXMOX_SSH_TIMEOUT_SECONDS", Some("10")),
            ("PROXMOX_SSH_MAX_OUTPUT_BYTES", Some("2048")),
            ("PROXMOX_GUEST_SSH_USER", Some("admin")),
            ("PROXMOX_GUEST_SSH_KEY_FILE", Some(&key)),
            ("PROXMOX_GUEST_SSH_PASSWORD", Some("gpw")),
        ]);
        assert!(i.allow_ssh);
        let s = i.ssh;
        assert_eq!(s.user, "ops");
        assert_eq!(s.port, 2222);
        assert_eq!(s.key_file.as_deref(), Some(key.as_str()));
        assert_eq!(s.key_passphrase.as_deref(), Some("pp"));
        assert_eq!(s.password.as_deref(), Some("pw"));
        assert_eq!(s.agent.as_deref(), Some("pageant"));
        assert_eq!(s.nodes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>(), vec![("pve1", "10.0.0.1"), ("pve2", "10.0.0.2")]);
        assert!(s.sudo);
        assert_eq!(Path::new(&s.known_hosts), home_dir().join("custom_known_hosts"));
        assert_eq!(s.host_key_policy, HostKeyPolicy::AcceptNew);
        assert_eq!(s.fingerprints.get("pve1"), Some(&fingerprint));
        assert_eq!(s.fingerprints.len(), 1);
        assert_eq!(s.timeout_ms, 10_000);
        assert_eq!(s.max_output_bytes, 2048);
        assert_eq!(s.guest_user.as_deref(), Some("admin"));
        assert_eq!(s.guest_key_file.as_deref(), Some(key.as_str()));
        assert_eq!(s.guest_password.as_deref(), Some("gpw"));
    }

    #[test]
    fn reads_maps_as_json_or_as_a_list() {
        let pairs = |m: IndexMap<String, String>| m.into_iter().collect::<Vec<_>>();
        let s = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(pairs(parse_map("x", Some(&json!(r#"{"a": "1", "b": "2"}"#))).unwrap()), vec![s("a", "1"), s("b", "2")]);
        assert_eq!(pairs(parse_map("x", Some(&json!("a=1, b=c=d"))).unwrap()), vec![s("a", "1"), s("b", "c=d")]);
        assert_eq!(pairs(parse_map("x", Some(&json!({ "a": "1" }))).unwrap()), vec![s("a", "1")]);
        assert!(parse_map("x", None).unwrap().is_empty());
        assert!(parse_map("x", Some(&json!("nope"))).unwrap_err().message.contains("name=value"));
        assert!(parse_map("x", Some(&json!("{bad json"))).unwrap_err().message.contains("invalid JSON"));
        assert!(parse_map("x", Some(&json!({ "a/b": "1" }))).unwrap_err().message.contains("invalid entry"));
    }

    #[test]
    fn refuses_a_bad_policy_or_fingerprint() {
        assert!(refusal(&[("PROXMOX_SSH_HOST_KEY_POLICY", Some("yolo"))]).message.contains("strict"));
        assert!(refusal(&[("PROXMOX_SSH_FINGERPRINTS", Some("pve1=MD5:aa"))]).message.contains("SHA256"));
    }

    #[test]
    fn only_checks_ssh_credentials_and_key_files_when_ssh_is_on() {
        let dir = TempDir::new();
        let missing = dir.path("missing");
        assert_eq!(load(&[("PROXMOX_SSH_KEY_FILE", Some(&missing))]).1.ssh.key_file.as_deref(), Some(missing.as_str()));
        assert!(refusal(&[("PROXMOX_ALLOW_SSH", Some("true")), ("PROXMOX_SSH_KEY_FILE", Some(&missing))]).message.contains("Cannot read"));
        assert!(refusal(&[("PROXMOX_ALLOW_SSH", Some("true"))]).message.contains("no SSH credential"));
        assert!(load(&[("PROXMOX_ALLOW_SSH", Some("true")), ("PROXMOX_SSH_AGENT", Some("pageant"))]).1.allow_ssh);
    }

    fn instances_file(dir: &TempDir, content: &Value) -> String {
        let text = match content {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        dir.file(&format!("instances-{}.json", uuid::Uuid::new_v4()), &text)
    }

    #[test]
    fn several_clusters() {
        let dir = TempDir::new();
        let d = dir.dir();
        let file = instances_file(
            &dir,
            &json!({
                "default": "lab",
                "instances": {
                    "prod": { "url": "https://prod", "token": "${PROD_TOKEN}", "allow_writes": false, "protected_vmids": [100], "ssh": { "user": "ops", "nodes": { "p1": "10.0.0.1" } } },
                    "lab": { "url": "https://lab:8007", "token_id": "a@b!c", "token_secret": "${LAB_SECRET}", "fingerprint": TLS_FINGERPRINT, "description": "Lab", "default_node": "n1", "timeout_seconds": 5, "local_dir": d },
                },
            }),
        );
        let c = load_config(&env(&[("PROXMOX_CONFIG", &file), ("PROD_TOKEN", "x@y!z=w"), ("LAB_SECRET", "s"), ("PROXMOX_ALLOW_WRITES", "true"), ("PROXMOX_SSH_PORT", "2200")])).unwrap();
        assert_eq!(c.default_instance, "lab");
        let prod = &c.instances["prod"];
        let lab = &c.instances["lab"];
        assert_eq!(prod.url, "https://prod:8006");
        assert_eq!(prod.token_id.as_deref(), Some("x@y!z"));
        assert!(!prod.allow_writes);
        assert_eq!(prod.protected_vmids.iter().copied().collect::<Vec<_>>(), vec![100]);
        assert_eq!(prod.ssh.user, "ops");
        assert_eq!(prod.ssh.port, 2200);
        assert_eq!(prod.ssh.nodes.get("p1").map(String::as_str), Some("10.0.0.1"));
        assert_eq!(lab.url, "https://lab:8007");
        assert_eq!(lab.token_secret.as_deref(), Some("s"));
        assert!(lab.allow_writes);
        assert_eq!(lab.fingerprint.as_deref(), Some(TLS_FINGERPRINT));
        assert_eq!(lab.description.as_deref(), Some("Lab"));
        assert_eq!(lab.default_node.as_deref(), Some("n1"));
        assert_eq!(lab.timeout_ms, 5000);
        assert_eq!(lab.local_dir.as_deref(), Some(d.as_str()));
    }

    #[test]
    fn several_clusters_refuses_what_is_wrong() {
        let dir = TempDir::new();
        let msg = |content: Value| match load_config(&env(&[("PROXMOX_CONFIG", &instances_file(&dir, &content))])) {
            Ok(_) => panic!("expected an error for {content}"),
            Err(e) => e.message,
        };
        assert!(msg(json!("{not json")).contains("Cannot read PROXMOX_CONFIG"));
        assert!(msg(json!({ "instances": {} })).contains("defines no instances"));
        assert!(msg(json!({ "default": "x", "instances": { "a": { "url": "https://a", "token": "a@b!c=d" } } })).contains("Default instance"));
        assert!(msg(json!({ "instances": { "bad name": { "url": "https://a", "token": "a@b!c=d" } } })).contains("Invalid instance name"));
        assert!(msg(json!({ "instances": { "a": { "token": "a@b!c=d" } } })).contains("url is required"));
        assert!(msg(json!({ "instances": { "a": { "url": "https://a", "token": "${MISSING}" } } })).contains("MISSING is not set"));
        assert!(msg(json!({ "instances": { "a": { "url": "https://a", "token": "a@b!c=d", "allow_writes": "maybe" } } })).contains("not a boolean"));
    }

    /// Ported from test/readme.test.ts: the example in examples/ loads as it is, nested ${VARIABLE}s too.
    #[test]
    fn the_instances_example_loads_as_it_is() {
        let dir = TempDir::new();
        let key = dir.file("key", "unused");
        let pin = format!("SHA256:{}", "A".repeat(43));
        let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join("instances.json").to_string_lossy().into_owned();
        let fingerprint = format!("{}AA", "AA:".repeat(31));
        let local = dir.dir();
        let config = load_config(&env(&[
            ("PROXMOX_CONFIG", example.as_str()),
            ("PVE_LAB_TOKEN", "mcp@pve!pvemcp=secret"),
            ("PVE_LAB_FINGERPRINT", fingerprint.as_str()),
            ("PVE_LAB_LOCAL_DIR", local.as_str()),
            ("PVE_LAB_SSH_KEY_FILE", key.as_str()),
            ("PVE1_HOST_KEY", pin.as_str()),
            ("PVE_PROD_TOKEN_SECRET", "secret"),
        ]))
        .unwrap_or_else(|e| panic!("{}", e.message));
        assert_eq!(config.instances.keys().collect::<Vec<_>>(), ["lab", "prod"]);
        assert_eq!(config.default_instance, "lab");
        let lab = &config.instances["lab"];
        assert!(lab.allow_ssh);
        assert_eq!(lab.ssh.fingerprints["pve1"], pin);
        assert_eq!(lab.ssh.nodes["pve2"], "10.0.0.12");
        let prod = &config.instances["prod"];
        assert!(!prod.allow_writes);
        assert!(prod.dry_run);
        assert_eq!(prod.protected_vmids.iter().copied().collect::<Vec<_>>(), [100, 101]);
    }
}
