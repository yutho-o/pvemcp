//! Access policy, enforced by the HTTP client so that no tool can get around it.
//!
//! Classification works on the catalog template when the path is known, and on the concrete
//! path otherwise, so that a route missing from the catalog can still hit a block rule.
//! An unknown path fails closed: a GET counts as sensitive, anything else as elevated.

use crate::catalog::match_path;
use crate::errors::{PveError, Result, kind};
use crate::js::{encode_uri_component, js_number, js_number_str, js_string};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gate {
    Read,
    Sensitive,
    Write,
    Elevated,
    GuestExec,
    Console,
    Blocked,
    SshRead,
    SshWrite,
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Gate::Read => "read",
            Gate::Sensitive => "sensitive",
            Gate::Write => "write",
            Gate::Elevated => "elevated",
            Gate::GuestExec => "guest_exec",
            Gate::Console => "console",
            Gate::Blocked => "blocked",
            Gate::SshRead => "ssh_read",
            Gate::SshWrite => "ssh_write",
        }
    }

    pub const ALL: [Gate; 9] = [Gate::Read, Gate::Sensitive, Gate::Write, Gate::Elevated, Gate::GuestExec, Gate::Console, Gate::Blocked, Gate::SshRead, Gate::SshWrite];
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub gate: Gate,
    pub destructive: bool,
    /// Absent when the path is not in the catalog.
    pub template: Option<String>,
    pub path_params: IndexMap<String, String>,
    pub reason: Option<String>,
    /// Canonical path with decoded values, for logs.
    pub path: String,
    /// The same path, percent-encoded segment by segment, ready to go after /api2/json.
    pub url_path: String,
    /// The answer's only purpose is a secret: it is kept when allowSensitive is on.
    pub returns_secret: bool,
}

#[derive(Debug, Clone)]
pub struct PolicySubject {
    pub name: String,
    pub allow_writes: bool,
    pub allow_elevated: bool,
    pub allow_guest_exec: bool,
    pub allow_sensitive: bool,
    pub allow_ssh: bool,
    pub dry_run: bool,
}

#[derive(Default, Clone)]
pub struct AuthorizeOptions<'a> {
    /// Set for tools announced as read-only: anything that changes state is refused.
    pub read_only: bool,
    /// Nothing will be sent, which is what opens the write gates on a read-only instance.
    pub dry_run: bool,
    /// Fills {placeholders} in the path. Values may hold characters that a raw path may not.
    pub path_params: Option<&'a Map<String, Value>>,
    /// What the call would send: a few arguments raise its gate, see host_access_arg.
    pub params: Option<&'a Map<String, Value>>,
}

fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid policy regex")
}

static CONTROL_CHARS: LazyLock<Regex> = LazyLock::new(|| rx(r"[\x00-\x1f\x7f-\u{9f}]"));
static RAW_FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| rx(r"[?#\\{}]"));
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| rx(r"^\{([^{}/]+)\}$"));

/// Values that legitimately hold a slash once encoded (local:iso/x.iso, 10.0.0.0/24).
/// Anywhere else a slash is refused: a node name must never be able to add path segments.
const SLASH_ALLOWED: &[&str] = &["volume", "cidr", "subnet"];

fn scrub(text: &str) -> String {
    let replaced = CONTROL_CHARS.replace_all(text, "?");
    crate::js::js_slice_start(&replaced, 300).to_string()
}

fn invalid_path(path: &str, why: &str, hint: Option<&str>) -> PveError {
    let e = PveError::new(kind::INVALID_PATH, format!("\"{}\" is not a valid API path: {why}.", scrub(path)));
    match hint {
        Some(h) => e.hint(h),
        None => e,
    }
}

const RAW_PATH_HINT: &str = "Give the plain path, such as /nodes/pve/qemu/100/config, without encoding. For a value with special characters, use a {placeholder} in the path and pass the value in path_params: it is encoded for you.";

fn assert_raw_segment(path: &str, segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(invalid_path(path, "empty segment (double or leading slash)", None));
    }
    if segment == "." || segment == ".." {
        return Err(invalid_path(path, "dot segments are not allowed", None));
    }
    if CONTROL_CHARS.is_match(segment) {
        return Err(invalid_path(path, "control characters are not allowed", None));
    }
    if RAW_FORBIDDEN.is_match(segment) {
        return Err(invalid_path(path, "query strings, fragments, backslashes and braces are not allowed in a path", Some(RAW_PATH_HINT)));
    }
    // All of it rather than %2f and friends: %74 for "t" would get "agent/exec" past the rules below.
    if segment.contains('%') {
        return Err(invalid_path(path, "percent-encoding is not allowed", Some(RAW_PATH_HINT)));
    }
    Ok(())
}

fn assert_value(path: &str, name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_path(path, &format!("path parameter \"{name}\" is empty"), None));
    }
    if crate::js::js_len(value) > 1024 {
        return Err(invalid_path(path, &format!("path parameter \"{name}\" is too long"), None));
    }
    if CONTROL_CHARS.is_match(value) || value.contains('\\') {
        return Err(invalid_path(path, &format!("path parameter \"{name}\" holds control characters or a backslash"), None));
    }
    let pieces: Vec<&str> = value.split('/').collect();
    if pieces.len() > 1 && !SLASH_ALLOWED.contains(&name) {
        return Err(invalid_path(path, &format!("path parameter \"{name}\" may not contain a slash"), None));
    }
    if pieces.iter().any(|p| *p == "." || *p == ".." || p.is_empty()) {
        return Err(invalid_path(path, &format!("path parameter \"{name}\" holds a dot or empty segment"), None));
    }
    Ok(())
}

/// Splits a path into decoded segments, or refuses it. A trailing slash is dropped.
pub fn normalize_path(path: &str, values: Option<&Map<String, Value>>) -> Result<Vec<String>> {
    if !path.starts_with('/') {
        return Err(invalid_path(path, "it must start with /", None));
    }
    if crate::js::js_len(path) > 4096 {
        return Err(invalid_path(path, "too long", None));
    }
    let trimmed = if path.len() > 1 && path.ends_with('/') { &path[..path.len() - 1] } else { path };
    if trimmed == "/" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for segment in trimmed[1..].split('/') {
        let name = PLACEHOLDER.captures(segment).map(|c| c[1].to_string());
        if let (Some(name), Some(values)) = (name, values) {
            let value = match values.get(&name) {
                None | Some(Value::Null) => return Err(PveError::new(kind::INVALID_INPUT, format!("Missing value for path parameter \"{name}\" of {}.", scrub(path)))),
                Some(v) => js_string(v),
            };
            assert_value(path, &name, &value)?;
            out.push(value);
            continue;
        }
        assert_raw_segment(path, segment)?;
        out.push(segment.to_string());
    }
    Ok(out)
}

/// The characters left readable are the ones the Proxmox API itself shows in UPIDs and ids.
pub fn encode_segment(segment: &str) -> String {
    encode_uri_component(segment).replace("%3A", ":").replace("%40", "@").replace("%2C", ",").replace("%3D", "=")
}

const NODE: &str = "/nodes/[^/]+";

fn guest() -> String {
    format!("{NODE}/(?:qemu|lxc)/[^/]+")
}
fn qemu() -> String {
    format!("{NODE}/qemu/[^/]+")
}

fn any_of(patterns: &[String]) -> Regex {
    rx(&format!("^(?:{})$", patterns.join("|")))
}

macro_rules! pats {
    ($($p:expr),* $(,)?) => { any_of(&[$(String::from($p)),*]) };
}

struct Rule {
    methods: Option<&'static [&'static str]>,
    pattern: Regex,
    reason: Option<&'static str>,
}

impl Rule {
    fn applies(&self, method: &str, subject: &str) -> bool {
        self.methods.is_none_or(|m| m.contains(&method)) && self.pattern.is_match(subject)
    }
}

static BLOCKED: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let g = guest();
    vec![
        Rule { methods: None, pattern: pats!(format!("{NODE}/execute")), reason: Some("It runs a batch of API calls on the node, which would bypass this policy.") },
        Rule { methods: None, pattern: pats!(format!("{g}/vncwebsocket"), format!("{NODE}/vncwebsocket")), reason: Some("A websocket console cannot be driven by a tool call.") },
        Rule { methods: None, pattern: pats!(format!("{g}/mtunnelwebsocket"), format!("{g}/mtunnel")), reason: Some("Migration tunnels are internal to remote_migrate.") },
        Rule { methods: None, pattern: pats!("/access/ticket"), reason: Some("This server handles authentication itself.") },
        Rule { methods: Some(&["POST"]), pattern: pats!("/access/openid/login"), reason: Some("OpenID login is an interactive browser flow.") },
    ]
});

static CONSOLE: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{}/(?:vncproxy|termproxy|spiceproxy)", guest()), format!("{NODE}/(?:vncshell|termproxy|spiceshell)"), "/access/vncticket"));

static GUEST_EXEC: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let q = qemu();
    vec![
        Rule { methods: Some(&["POST"]), pattern: pats!(format!("{q}/agent"), format!("{q}/agent/(?:exec|file-write|set-user-password)"), format!("{q}/monitor")), reason: None },
        Rule { methods: Some(&["GET"]), pattern: pats!(format!("{q}/agent/exec-status")), reason: None },
        // Typing on the console of a logged-in guest is running commands in it.
        Rule { methods: Some(&["PUT"]), pattern: pats!(format!("{q}/sendkey")), reason: None },
    ]
});

static SENSITIVE_GET: LazyLock<Regex> = LazyLock::new(|| {
    let q = qemu();
    pats!(
        "/cluster/metrics/export",
        "/cluster/config/join",
        format!("{q}/agent/file-read"),
        format!("{q}/cloudinit/dump"),
        format!("{NODE}/vzdump/extractconfig"),
        format!("{NODE}/storage/[^/]+/file-restore/download"),
        // Not a plain read: it starts a restore VM on the node, and shows what is inside a backup.
        format!("{NODE}/storage/[^/]+/file-restore/list"),
        format!("{NODE}/report"),
        "/cluster/acme/plugins(?:/.*)?",
        format!("{NODE}/ceph/cfg/(?:raw|db|value)"),
        // These make the node connect to a host of the caller's choice, some with credentials.
        format!("{NODE}/scan/(?:cifs|iscsi|nfs|pbs)"),
        format!("{NODE}/query-url-metadata"),
        format!("{NODE}/query-oci-repo-tags"),
        "/cluster/acme/(?:meta|tos)",
    )
});

static ELEVATED_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    pats!(
        "/access(?:/.*)?",
        "/storage(?:/.*)?",
        "/cluster/config(?:/.*)?",
        "/cluster/options",
        "/cluster/ceph(?:/.*)?",
        format!("{NODE}/ceph(?:/.*)?"),
        "/cluster/acme(?:/.*)?",
        format!("{NODE}/certificates(?:/.*)?"),
        "/cluster/sdn(?:/.*)?",
        format!("{NODE}/sdn(?:/.*)?"),
        "/cluster/firewall(?:/.*)?",
        format!("{NODE}/firewall(?:/.*)?"),
        "/cluster/bulk-action(?:/.*)?",
        "/cluster/jobs/realm-sync(?:/.*)?",
        "/cluster/ha/status/(?:arm-ha|disarm-ha)",
        "/cluster/mapping(?:/.*)?",
        "/cluster/metrics/server(?:/.*)?",
        "/cluster/notifications(?:/.*)?",
        "/cluster/qemu/custom-cpu-models(?:/.*)?",
        format!("{NODE}/status"),
        format!("{NODE}/(?:startall|stopall|suspendall|migrateall|wakeonlan)"),
        format!("{NODE}/apt(?:/.*)?"),
        format!("{NODE}/network(?:/.*)?"),
        format!("{NODE}/(?:dns|hosts|time|config)"),
        format!("{NODE}/services(?:/.*)?"),
        format!("{NODE}/subscription"),
        format!("{NODE}/disks(?:/.*)?"),
        format!("{}/remote_migrate", guest()),
    )
});

static DESTRUCTIVE_WRITE: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let g = guest();
    let q = qemu();
    vec![
        Rule {
            methods: None,
            pattern: pats!(
                format!("{g}/status/(?:stop|reset|shutdown|reboot|suspend)"),
                format!("{g}/snapshot/[^/]+/rollback"),
                format!("{g}/template"),
                format!("{NODE}/status"),
                format!("{NODE}/(?:stopall|suspendall|migrateall)"),
                format!("{NODE}/disks/(?:wipedisk|initgpt)"),
                "/cluster/bulk-action/guest/(?:shutdown|suspend|migrate)",
                format!("{q}/agent/(?:shutdown|suspend-disk|suspend-hybrid|suspend-ram|fsfreeze-freeze|exec|file-write|set-user-password)"),
                format!("{q}/agent"),
                format!("{q}/monitor"),
                format!("{q}/sendkey"),
                format!("{q}/unlink"),
                format!("{NODE}/services/[^/]+/(?:stop|restart)"),
                format!("{NODE}/ceph/(?:stop|restart|restart-bulk)"),
                "/cluster/ceph/restart-bulk",
                format!("{NODE}/ceph/osd/[^/]+/out"),
                "/cluster/sdn",
                "/cluster/sdn/rollback",
                "/cluster/ha/status/disarm-ha",
                "/cluster/ha/resources/[^/]+/relocate",
                "/cluster/config",
                "/cluster/config/join",
                "/cluster/config/nodes/[^/]+",
                format!("{NODE}/hosts"),
                "/access/password",
            ),
            reason: None,
        },
        // Only the reload: POST on this path adds an interface, which stays pending until then.
        Rule { methods: Some(&["PUT"]), pattern: pats!(format!("{NODE}/network")), reason: None },
        // POST formats the disk it is given.
        Rule { methods: Some(&["POST"]), pattern: pats!(format!("{NODE}/disks/(?:directory|lvm|lvmthin|zfs)"), format!("{NODE}/ceph/osd")), reason: None },
    ]
});

static TRUTHY_TEXT: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)^(?:1|true|yes|on)$"));
static DIGITS: LazyLock<Regex> = LazyLock::new(|| rx(r"^\d+$"));

pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(true)) => true,
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(s)) => TRUTHY_TEXT.is_match(s),
        _ => false,
    }
}

pub fn given(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null)) && v != Some(&Value::String(String::new()))
}

/// The values of a numbered parameter, however it is spelled: hostpci0 on the API,
/// hostpci: {"0": "..."} or hostpci_n: {"0": "..."} as a tool argument.
fn indexed_values<'a>(args: &'a Map<String, Value>, base: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    let with_n = format!("{base}_n");
    for (key, value) in args {
        if key == base || *key == with_n {
            match value {
                Value::Object(map) => out.extend(map.values()),
                Value::Array(items) => out.extend(items.iter()),
                _ => {}
            }
        } else if let Some(rest) = key.strip_prefix(base) {
            if DIGITS.is_match(rest) {
                out.push(value);
            }
        }
    }
    out.into_iter().filter(|v| given(Some(v))).collect()
}

static VM_CONFIG: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{NODE}/qemu"), format!("{}/config", qemu())));
static CT_CONFIG: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{NODE}/lxc"), format!("{NODE}/lxc/[^/]+/config")));
static CT_CREATE: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{NODE}/lxc")));
static BACKUP_RUN: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{NODE}/vzdump"), "/cluster/backup", "/cluster/backup/[^/]+"));
/// A mount point on a path of the host rather than on a volume: /srv/x,mp=/mnt or volume=/srv/x.
static BIND_SOURCE: LazyLock<Regex> = LazyLock::new(|| rx(r"^(?:volume=)?/|,volume=/"));
static USB_HOST: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:^|,)host="));

struct HostAccess {
    pattern: &'static LazyLock<Regex>,
    params: &'static [&'static str],
}

static HOST_ACCESS: [HostAccess; 3] = [
    HostAccess { pattern: &VM_CONFIG, params: &["hookscript", "args", "hostpci[n]", "parallel[n]", "usb[n]", "serial[n]"] },
    HostAccess { pattern: &CT_CONFIG, params: &["hookscript", "dev[n]", "mp[n]", "rootfs", "unprivileged"] },
    HostAccess { pattern: &BACKUP_RUN, params: &["script", "dumpdir", "tmpdir"] },
];

/// The parameters of this endpoint that host_access_arg looks at, for a tool to announce them.
pub fn host_access_params(has_param: impl Fn(&str) -> bool, method: &str, template: &str) -> Vec<&'static str> {
    if method != "POST" && method != "PUT" {
        return Vec::new();
    }
    HOST_ACCESS.iter().find(|h| h.pattern.is_match(template)).map(|h| h.params.iter().copied().filter(|p| has_param(p)).collect()).unwrap_or_default()
}

/// Arguments that reach the hypervisor itself: a hook script runs as root on the node, and kvm
/// arguments, host devices and bind mounts all get past the walls of the guest. On a tool of gate
/// write they need PROXMOX_ALLOW_ELEVATED. Returns the name of the first one found.
pub fn host_access_arg(method: &str, template: Option<&str>, args: Option<&Map<String, Value>>) -> Option<&'static str> {
    if method != "POST" && method != "PUT" {
        return None;
    }
    let (template, args) = (template?, args?);
    if VM_CONFIG.is_match(template) {
        if given(args.get("hookscript")) {
            return Some("hookscript");
        }
        if given(args.get("args")) {
            return Some("args");
        }
        if !indexed_values(args, "hostpci").is_empty() {
            return Some("hostpci");
        }
        if !indexed_values(args, "parallel").is_empty() {
            return Some("parallel");
        }
        // These two also name harmless things: usb0=spice, serial0=socket.
        if indexed_values(args, "usb").iter().any(|v| USB_HOST.is_match(&js_string(v))) {
            return Some("usb");
        }
        if indexed_values(args, "serial").iter().any(|v| js_string(v) != "socket") {
            return Some("serial");
        }
        return None;
    }
    if CT_CONFIG.is_match(template) {
        if given(args.get("hookscript")) {
            return Some("hookscript");
        }
        if !indexed_values(args, "dev").is_empty() {
            return Some("dev");
        }
        if indexed_values(args, "mp").iter().any(|v| BIND_SOURCE.is_match(&js_string(v))) {
            return Some("mp");
        }
        if let Some(Value::String(rootfs)) = args.get("rootfs") {
            if BIND_SOURCE.is_match(rootfs) {
                return Some("rootfs");
            }
        }
        // Root inside a privileged container is root on the node, as far as the kernel can tell.
        let unprivileged = args.get("unprivileged");
        let privileged = if method == "POST" && CT_CREATE.is_match(template) { !truthy(unprivileged) } else { given(unprivileged) && !truthy(unprivileged) };
        if privileged {
            return Some("unprivileged");
        }
        return None;
    }
    if BACKUP_RUN.is_match(template) {
        for name in ["script", "dumpdir", "tmpdir"] {
            if given(args.get(name)) {
                return Some(name);
            }
        }
    }
    None
}

/// What a refusal says about an argument host_access_arg found.
pub fn describe_host_access(what: &str, arg: &str) -> String {
    if arg == "unprivileged" { format!("{what} without unprivileged=1 (a privileged container)") } else { format!("{what} with \"{arg}\"") }
}

type When = fn(&Map<String, Value>, &str, &str) -> bool;

struct ArgRule {
    methods: Option<&'static [&'static str]>,
    pattern: Regex,
    /// Parameters of the endpoint that can trigger the rule: having one is what makes a tool check.
    params: &'static [&'static str],
    when: When,
}

static UNUSED_DELETE: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:^|[,;\s])unused\d"));

fn str_eq(v: Option<&Value>, s: &str) -> bool {
    matches!(v, Some(Value::String(x)) if x == s)
}

/// Arguments that turn an ordinary call into a destructive one. They read tool arguments and API parameters alike.
static DESTRUCTIVE_ARGS: LazyLock<Vec<ArgRule>> = LazyLock::new(|| {
    let q = qemu();
    let g = guest();
    let mut rules = vec![
        ArgRule { methods: None, pattern: rx("."), params: &["purge"], when: |a, _, _| truthy(a.get("purge")) },
        // Created with force, a guest replaces the one that had this vmid.
        ArgRule { methods: Some(&["POST"]), pattern: pats!(format!("{NODE}/(?:qemu|lxc)")), params: &["force"], when: |a, _, _| truthy(a.get("force")) },
        // unused[n] is a real volume: taking it out of the configuration takes it off the storage.
        ArgRule {
            methods: None,
            pattern: pats!(format!("{q}/config"), format!("{NODE}/lxc/[^/]+/config")),
            params: &["delete", "force"],
            when: |a, _, _| {
                let delete = match a.get("delete") {
                    None | Some(Value::Null) => String::new(),
                    Some(v) => js_string(v),
                };
                truthy(a.get("force")) || UNUSED_DELETE.is_match(&delete)
            },
        },
        ArgRule { methods: None, pattern: pats!(format!("{q}/move_disk"), format!("{NODE}/lxc/[^/]+/move_volume"), format!("{g}/remote_migrate")), params: &["delete"], when: |a, _, _| truthy(a.get("delete")) },
        ArgRule { methods: None, pattern: pats!(format!("{NODE}/lxc/[^/]+/(?:migrate|remote_migrate)")), params: &["restart"], when: |a, _, _| truthy(a.get("restart")) },
        // The old secret stops working at once.
        ArgRule { methods: Some(&["PUT"]), pattern: pats!("/access/users/[^/]+/token/[^/]+"), params: &["regenerate"], when: |a, _, _| truthy(a.get("regenerate")) },
        ArgRule { methods: None, pattern: pats!("/access/acl"), params: &["delete"], when: |a, _, _| truthy(a.get("delete")) },
        // Takes users, groups or ACLs away, unless it is only the preview.
        ArgRule {
            methods: None,
            pattern: pats!("/access/domains/[^/]+/sync", "/cluster/jobs/realm-sync/[^/]+"),
            params: &["remove-vanished", "full"],
            when: |a, _, _| !truthy(a.get("dry-run")) && (truthy(a.get("full")) || (given(a.get("remove-vanished")) && !str_eq(a.get("remove-vanished"), "none"))),
        },
        ArgRule { methods: None, pattern: pats!("/cluster/ha/resources", "/cluster/ha/resources/[^/]+"), params: &["state"], when: |a, _, _| str_eq(a.get("state"), "stopped") || str_eq(a.get("state"), "disabled") },
        // Also removes the replicated volumes on the target.
        ArgRule { methods: None, pattern: pats!("/cluster/replication", "/cluster/replication/[^/]+"), params: &["remove_job"], when: |a, _, _| given(a.get("remove_job")) },
        ArgRule { methods: None, pattern: pats!(format!("{NODE}/vzdump")), params: &["mode", "stop"], when: |a, _, _| str_eq(a.get("mode"), "stop") || truthy(a.get("stop")) },
        ArgRule { methods: None, pattern: pats!("/cluster/ceph/flags"), params: &["pause"], when: |a, _, _| truthy(a.get("pause")) },
        ArgRule { methods: None, pattern: pats!("/cluster/ceph/flags/[^/]+"), params: &["value"], when: |a, _, _| str_eq(a.get("flag"), "pause") && truthy(a.get("value")) },
        ArgRule { methods: None, pattern: pats!(format!("{NODE}/certificates/custom"), format!("{NODE}/certificates/acme/certificate")), params: &["force"], when: |a, _, _| truthy(a.get("force")) },
        // Switched on with the wrong rules, this can cut the API off. Switched off, it opens everything.
        ArgRule { methods: None, pattern: pats!("/cluster/firewall/options", format!("{NODE}/firewall/options")), params: &["enable"], when: |a, _, _| given(a.get("enable")) },
    ];
    for h in HOST_ACCESS.iter() {
        rules.push(ArgRule { methods: None, pattern: (**h.pattern).clone(), params: h.params, when: |a, method, template| host_access_arg(method, Some(template), Some(a)).is_some() });
    }
    rules
});

fn arg_rules_for<'a>(method: &'a str, template: &'a str) -> impl Iterator<Item = &'static ArgRule> + 'a {
    DESTRUCTIVE_ARGS.iter().filter(move |r| r.methods.is_none_or(|m| m.contains(&method)) && r.pattern.is_match(template))
}

fn first_rule<'a>(rules: &'a [Rule], method: &str, subject: &str) -> Option<&'a Rule> {
    rules.iter().find(|r| r.applies(method, subject))
}

fn assert_method(method: &str) -> Result<()> {
    match method {
        "GET" | "POST" | "PUT" | "DELETE" => Ok(()),
        _ => Err(PveError::new(kind::INVALID_INPUT, format!("Unsupported HTTP method \"{}\": use GET, POST, PUT or DELETE.", scrub(method)))),
    }
}

/// Secrets that a tool exists to hand over, as opposed to ones that travel with other data.
static SECRET_ANSWERS: LazyLock<Regex> = LazyLock::new(|| pats!("/access/users/[^/]+/token/[^/]+", "/access/tfa/[^/]+"));

fn classify_subject(method: &str, subject: &str, known: bool) -> (Gate, Option<String>) {
    if let Some(blocked) = first_rule(&BLOCKED, method, subject) {
        return (Gate::Blocked, Some(blocked.reason.unwrap_or("Blocked by policy.").to_string()));
    }
    if CONSOLE.is_match(subject) {
        return (Gate::Console, None);
    }
    if first_rule(&GUEST_EXEC, method, subject).is_some() {
        return (Gate::GuestExec, None);
    }
    if !known {
        return if method == "GET" {
            (Gate::Sensitive, Some("This path is not in the API catalog, so its answer cannot be assumed to be harmless.".into()))
        } else {
            (Gate::Elevated, Some("This path is not in the API catalog, so it is treated as the most privileged kind of write.".into()))
        };
    }
    if method == "GET" {
        return (if SENSITIVE_GET.is_match(subject) { Gate::Sensitive } else { Gate::Read }, None);
    }
    (if ELEVATED_WRITE.is_match(subject) { Gate::Elevated } else { Gate::Write }, None)
}

/// Fails with invalid_path on a path that cannot be trusted.
pub fn classify(method: &str, path: &str, path_params: Option<&Map<String, Value>>) -> Result<Decision> {
    assert_method(method)?;
    let segments = normalize_path(path, path_params)?;
    let matched = match_path(&segments);
    let known = matched.as_ref().is_some_and(|m| m.methods.contains_key(method));
    let joined = format!("/{}", segments.join("/"));
    let subject = if known { matched.as_ref().unwrap().template.clone() } else { joined.clone() };
    let (gate, reason) = classify_subject(method, &subject, known);
    let destructive = method == "DELETE" || (method != "GET" && first_rule(&DESTRUCTIVE_WRITE, method, &subject).is_some());
    let (template, path_params) = match (known, matched) {
        (true, Some(m)) => (Some(m.template), m.path_params),
        _ => (None, IndexMap::new()),
    };
    Ok(Decision {
        gate,
        destructive,
        template,
        path_params,
        reason,
        path: joined,
        url_path: format!("/{}", segments.iter().map(|s| encode_segment(s)).collect::<Vec<_>>().join("/")),
        returns_secret: method != "GET" && SECRET_ANSWERS.is_match(&subject),
    })
}

/// Arguments that turn an ordinary call into a destructive one.
pub fn destructive_args(method: &str, template: &str, args: &Map<String, Value>) -> bool {
    if method == "GET" {
        return false;
    }
    arg_rules_for(method, template).any(|rule| (rule.when)(args, method, template))
}

/// Whether some argument values can make this call destructive, from the parameters the endpoint has.
pub fn has_destructive_args(has_param: impl Fn(&str) -> bool, method: &str, template: &str) -> bool {
    if method == "GET" {
        return false;
    }
    arg_rules_for(method, template).any(|rule| rule.params.iter().any(|p| has_param(p)))
}

pub fn is_unblocked(unblocked: &[String], method: &str, decision: &Decision) -> bool {
    let target = decision.template.as_deref().unwrap_or(&decision.path);
    unblocked.iter().any(|entry| {
        let parts: Vec<&str> = entry.split_whitespace().collect();
        let (want_method, want_path) = if parts.len() == 2 { (Some(parts[0].to_uppercase()), parts[1]) } else { (None, parts.first().copied().unwrap_or("")) };
        want_method.is_none_or(|m| m == method) && want_path.strip_suffix('/').unwrap_or(want_path) == target
    })
}

const DRY_RUN_NOTE: &str = "or preview with PROXMOX_DRY_RUN=true";

fn writes_open(subject: &PolicySubject, dry_run: bool) -> bool {
    subject.allow_writes || subject.dry_run || dry_run
}

/// Whether a gate is open for this instance, without any path: this is what hides tools
/// and refuses them before anything is sent or anyone is asked. `read_only` marks the GET
/// half of guest_exec.
pub fn gate_refusal(gate: Gate, subject: &PolicySubject, dry_run: bool, read_only: bool, what: &str) -> Option<PveError> {
    let stop = "Do not retry.";
    let write_refusal = || {
        PveError::new(kind::WRITE_DISABLED, format!("Instance \"{}\" is read-only: {what} was not run and nothing was sent.", subject.name))
            .hint(format!("{stop} The operator can enable writes with PROXMOX_ALLOW_WRITES=true (or allow_writes on the instance), {DRY_RUN_NOTE}."))
    };
    match gate {
        Gate::Read => None,
        Gate::Sensitive => {
            if subject.allow_sensitive {
                return None;
            }
            Some(
                PveError::new(kind::SENSITIVE_DISABLED, format!("{what} can return secrets or raw exports, or makes the node reach out to another host or into a backup, which is off by default."))
                    .hint(format!("{stop} The operator can allow it with PROXMOX_ALLOW_SENSITIVE=true.")),
            )
        }
        Gate::Write => (!writes_open(subject, dry_run)).then(write_refusal),
        Gate::Elevated => {
            if !writes_open(subject, dry_run) {
                return Some(write_refusal());
            }
            if subject.allow_elevated {
                return None;
            }
            Some(
                PveError::new(kind::ELEVATED_DISABLED, format!("{what} changes the cluster itself or reaches the host (accounts, storage, network, firewall, node power, host devices, privileged containers...), which needs a separate permission."))
                    .hint(format!("{stop} The operator can allow it with PROXMOX_ALLOW_ELEVATED=true, on top of PROXMOX_ALLOW_WRITES.")),
            )
        }
        Gate::GuestExec => {
            if !subject.allow_guest_exec {
                return Some(PveError::new(kind::GUEST_EXEC_DISABLED, format!("{what} runs commands or touches files inside a guest, which is off by default.")).hint(format!("{stop} The operator can allow it with PROXMOX_ALLOW_GUEST_EXEC=true.")));
            }
            if read_only || writes_open(subject, dry_run) { None } else { Some(write_refusal()) }
        }
        Gate::Console => {
            if subject.allow_elevated && subject.allow_sensitive && subject.allow_writes {
                return None;
            }
            Some(PveError::new(kind::ELEVATED_DISABLED, format!("{what} opens a console, which hands out a login-equivalent ticket.")).hint(format!("{stop} The operator must set all of PROXMOX_ALLOW_WRITES, PROXMOX_ALLOW_ELEVATED and PROXMOX_ALLOW_SENSITIVE.")))
        }
        Gate::Blocked => Some(PveError::new(kind::BLOCKED_ENDPOINT, format!("{what} is blocked by this server.")).hint(format!("{stop} A human can do this in the Proxmox web interface, or the operator can list the endpoint in PROXMOX_UNBLOCK."))),
        Gate::SshRead => {
            if subject.allow_ssh {
                return None;
            }
            Some(PveError::new(kind::SSH_DISABLED, format!("{what} needs SSH access to the node, which is off by default.")).hint(format!("{stop} The operator can allow it with PROXMOX_ALLOW_SSH=true.")))
        }
        Gate::SshWrite => {
            if !subject.allow_ssh {
                return Some(PveError::new(kind::SSH_DISABLED, format!("{what} needs SSH access to the node, which is off by default.")).hint(format!("{stop} The operator can allow it with PROXMOX_ALLOW_SSH=true, along with PROXMOX_ALLOW_WRITES.")));
            }
            (!writes_open(subject, dry_run)).then(write_refusal)
        }
    }
}

/// Fails unless the call is allowed. Returns the decision for logging and dry-run handling.
pub fn authorize(subject: &PolicySubject, method: &str, path: &str, unblocked: &[String], opts: &AuthorizeOptions) -> Result<Decision> {
    let mut decision = classify(method, path, opts.path_params)?;
    let what = format!("{method} {}", decision.path);
    let mut gate = decision.gate;
    let host_arg = if gate == Gate::Write { host_access_arg(method, decision.template.as_deref(), opts.params) } else { None };
    if host_arg.is_some() {
        gate = Gate::Elevated;
    }
    if gate == Gate::Blocked {
        if !is_unblocked(unblocked, method, &decision) {
            return Err(PveError::new(kind::BLOCKED_ENDPOINT, format!("{what} is blocked: {}", decision.reason.as_deref().unwrap_or("blocked by policy.")))
                .hint("Do not retry. A human can do this in the Proxmox web interface, or the operator can list the endpoint in PROXMOX_UNBLOCK."));
        }
        gate = Gate::Elevated;
    }
    if opts.read_only && (method != "GET" || !matches!(gate, Gate::Read | Gate::Sensitive | Gate::GuestExec)) {
        return Err(PveError::new(kind::NOT_READ_ONLY, format!("{what} can change something, so a read tool refuses it: nothing was sent."))
            .hint("A tool that writes is the way to do this, provided writes are enabled. pve_api_describe gives the name of the tool for an endpoint."));
    }
    let described = match host_arg {
        Some(arg) => describe_host_access(&what, arg),
        None => what.clone(),
    };
    if let Some(refusal) = gate_refusal(gate, subject, opts.dry_run, method == "GET", &described) {
        return Err(refusal);
    }
    decision.gate = gate;
    Ok(decision)
}

/// The owner of a volume or a backup: local-lvm:vm-100-disk-0, local:backup/vzdump-qemu-100-..., pbs:backup/ct/100/...
static VOLUME_OWNER: LazyLock<Regex> = LazyLock::new(|| rx(r"(?:^|[:/])(?:vm|base|subvol)-(\d+)-|vzdump-(?:qemu|lxc|openvz)-(\d+)-|backup/(?:vm|ct)/(\d+)/"));

/// What acts on all the guests of a node or a cluster, or on those in its "vms" list.
static BULK_ACTION: LazyLock<Regex> = LazyLock::new(|| pats!(format!("{NODE}/(?:startall|stopall|suspendall|migrateall)"), "/cluster/bulk-action/guest/[^/]+"));
static LIST_SPLIT: LazyLock<Regex> = LazyLock::new(|| rx(r"[,;\s]+"));
static HA_PREFIX: LazyLock<Regex> = LazyLock::new(|| rx(r"^(?:vm|ct):"));

fn integer_of(v: &Value) -> Option<i64> {
    js_number(v).filter(|f| f.is_finite() && f.fract() == 0.0).map(|f| f as i64)
}

/// A value of a vmid list, as any of the Proxmox list parsers would read it.
fn vmids_in(list: Option<&Value>) -> Vec<i64> {
    match list {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().filter_map(integer_of).collect(),
        Some(Value::String(s)) => LIST_SPLIT.split(s).filter(|p| !p.is_empty()).filter_map(|p| js_number_str(p).filter(|f| f.fract() == 0.0 && f.is_finite()).map(|f| f as i64)).collect(),
        Some(other) => integer_of(other).into_iter().collect(),
    }
}

fn protected_refusal(message: String, hint: &str) -> PveError {
    PveError::new(kind::PROTECTED_GUEST, message).hint(format!("{hint} Do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS."))
}

/// A vmid in the path, or given to a create or clone, of a change, or named in the list of a bulk
/// action. Reaching everything counts as naming the protected guests.
pub fn assert_not_protected(protected: &BTreeSet<i64>, method: &str, decision: &Decision, params: Option<&Map<String, Value>>) -> Result<()> {
    if method == "GET" || protected.is_empty() {
        return Ok(());
    }
    let empty = Map::new();
    let params = params.unwrap_or(&empty);
    let path_value = |name: &str| decision.path_params.get(name).map(|s| Value::String(s.clone()));
    let mut candidates: Vec<Value> = Vec::new();
    if decision.template.is_some() {
        candidates.extend(path_value("vmid"));
    }
    // An HA resource is the guest under another name: vm:100, ct:100.
    candidates.extend(path_value("sid"));
    for key in ["vmid", "newid", "sid"] {
        candidates.extend(params.get(key).cloned());
    }
    let template = decision.template.as_deref().unwrap_or("");
    let all = protected.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
    if BULK_ACTION.is_match(template) && vmids_in(params.get("vms")).is_empty() {
        return Err(protected_refusal(format!("{method} {} without a \"vms\" list would reach every guest, and guests {all} are protected on this server: it was not sent.", decision.path), "Name the guests in \"vms\"."));
    }
    if BACKUP_RUN.is_match(template) && truthy(params.get("all")) {
        let excluded: BTreeSet<i64> = vmids_in(params.get("exclude")).into_iter().collect();
        let reached: Vec<String> = protected.iter().filter(|v| !excluded.contains(v)).map(|v| v.to_string()).collect();
        if !reached.is_empty() {
            return Err(protected_refusal(format!("{method} {} with \"all\" would reach protected guests {}: it was not sent.", decision.path, reached.join(", ")), "List them in \"exclude\", or name the guests in \"vmid\"."));
        }
    }
    // On a remote migration this names a guest of the other cluster.
    if !template.ends_with("/remote_migrate") {
        candidates.extend(params.get("target-vmid").cloned());
    }
    // Being in a pool or not changes nothing on the guest.
    if !template.starts_with("/pools") {
        match params.get("vms") {
            Some(Value::Array(items)) => candidates.extend(items.iter().cloned()),
            Some(v) => candidates.push(v.clone()),
            None => {}
        }
    }
    if let Some(volume) = decision.path_params.get("volume") {
        for caps in VOLUME_OWNER.captures_iter(volume) {
            if let Some(m) = caps.get(1).or(caps.get(2)).or(caps.get(3)) {
                candidates.push(Value::String(m.as_str().to_string()));
            }
        }
    }
    // A replication job is called <vmid>-<number>.
    if template.starts_with("/cluster/replication") {
        let id = decision.path_params.get("id").cloned().map(Value::String).or_else(|| params.get("id").cloned());
        let text = match id {
            None | Some(Value::Null) => String::new(),
            Some(v) => js_string(&v),
        };
        candidates.push(Value::String(text.split('-').next().unwrap_or("").to_string()));
    }
    // Not in the catalog, so no telling which segment is a vmid: any match counts.
    if decision.template.is_none() {
        candidates.extend(decision.path.split('/').map(|s| Value::String(s.to_string())));
    }
    for candidate in candidates {
        let numbers: Vec<Option<i64>> = match &candidate {
            Value::Null => continue,
            Value::String(s) if s.is_empty() => continue,
            Value::String(s) => LIST_SPLIT.split(&HA_PREFIX.replace(s, "")).map(|p| js_number_str(p).filter(|f| f.is_finite() && f.fract() == 0.0).map(|f| f as i64)).collect(),
            other => vec![integer_of(other)],
        };
        if let Some(n) = numbers.into_iter().flatten().find(|v| protected.contains(v)) {
            return Err(PveError::new(kind::PROTECTED_GUEST, format!("Guest {n} is protected on this server: {method} {} was not sent.", decision.path))
                .hint("Do not retry and do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject() -> PolicySubject {
        PolicySubject { name: "pve".into(), allow_writes: false, allow_elevated: false, allow_guest_exec: false, allow_sensitive: false, allow_ssh: false, dry_run: false }
    }

    #[test]
    fn classifies() {
        let d = classify("GET", "/nodes/pve/qemu/100/config", None).unwrap();
        assert_eq!(d.gate, Gate::Read);
        assert_eq!(d.template.as_deref(), Some("/nodes/{node}/qemu/{vmid}/config"));
        assert_eq!(classify("POST", "/nodes/pve/execute", None).unwrap().gate, Gate::Blocked);
        assert_eq!(classify("POST", "/nodes/pve/qemu/100/agent/exec", None).unwrap().gate, Gate::GuestExec);
        assert!(classify("POST", "/nodes/pve/qemu/100/status/stop", None).unwrap().destructive);
        assert!(classify("GET", "/nodes/%2e%2e", None).is_err());
        assert!(classify("GET", "/nodes//x", None).is_err());
        let e = authorize(&subject(), "POST", "/nodes/pve/qemu/100/status/start", &[], &AuthorizeOptions::default()).unwrap_err();
        assert_eq!(e.kind, "write_disabled");
        let args = json!({"hostpci0": "0000:01:00.0"});
        assert_eq!(host_access_arg("PUT", Some("/nodes/{node}/qemu/{vmid}/config"), args.as_object()), Some("hostpci"));
        let p: BTreeSet<i64> = [100].into_iter().collect();
        let d = classify("POST", "/nodes/pve/qemu/100/status/start", None).unwrap();
        assert_eq!(assert_not_protected(&p, "POST", &d, None).unwrap_err().kind, "protected_guest");
        let d = classify("POST", "/nodes/pve/vzdump", None).unwrap();
        assert!(assert_not_protected(&p, "POST", &d, json!({"vmid": "101,100"}).as_object()).is_err());
        assert!(assert_not_protected(&p, "POST", &d, json!({"vmid": "101"}).as_object()).is_ok());
    }

    // Ported from test/policy.test.ts.

    fn err_kind<T>(r: Result<T>) -> Option<&'static str> {
        r.err().map(|e| e.kind)
    }

    fn map(v: serde_json::Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    fn placeholders(path: &str) -> Map<String, Value> {
        let re = Regex::new(r"\{([^}]+)\}").unwrap();
        re.captures_iter(path).map(|m| (m[1].to_string(), Value::String("x".into()))).collect()
    }

    #[derive(Default)]
    struct Allow {
        writes: bool,
        elevated: bool,
        guest_exec: bool,
        sensitive: bool,
        ssh: bool,
        dry_run: bool,
    }

    fn subj(a: Allow) -> PolicySubject {
        PolicySubject { name: "test".into(), allow_writes: a.writes, allow_elevated: a.elevated, allow_guest_exec: a.guest_exec, allow_sensitive: a.sensitive, allow_ssh: a.ssh, dry_run: a.dry_run }
    }

    fn auth(s: &PolicySubject, method: &str, path: &str, unblocked: &[&str], opts: &AuthorizeOptions) -> Option<&'static str> {
        let unblocked: Vec<String> = unblocked.iter().map(|u| u.to_string()).collect();
        err_kind(authorize(s, method, path, &unblocked, opts))
    }

    #[test]
    fn accepts_plain_paths_and_drops_one_trailing_slash() {
        assert_eq!(normalize_path("/nodes/pve1/qemu/100/config", None).unwrap(), vec!["nodes", "pve1", "qemu", "100", "config"]);
        assert_eq!(normalize_path("/nodes/pve1/", None).unwrap(), vec!["nodes", "pve1"]);
        assert_eq!(normalize_path("/access/users/root@pam/token/mcp", None).unwrap(), vec!["access", "users", "root@pam", "token", "mcp"]);
        assert_eq!(normalize_path("/nodes/pve1/tasks/UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:/status", None).unwrap().len(), 5);
    }

    #[test]
    fn refuses_bad_paths() {
        for (label, path) in [
            ("no leading slash", "nodes/pve1"),
            ("empty string", ""),
            ("double slash", "/nodes//pve1"),
            ("two trailing slashes", "/nodes/pve1//"),
            ("dot segment", "/nodes/./pve1"),
            ("dot-dot segment", "/nodes/pve1/../../access/ticket"),
            ("query string", "/nodes/pve1?x=1"),
            ("fragment", "/nodes/pve1#x"),
            ("backslash", "/nodes\\pve1"),
            ("backslash traversal", "/nodes/..\\access"),
            ("newline", "/nodes/pve1\n/status"),
            ("carriage return", "/nodes/pve1\r\nX-Evil: 1"),
            ("NUL", "/nodes/pve1\0"),
            ("DEL", "/nodes/pve1\u{7f}"),
            ("C1 control", "/nodes/pve1\u{85}"),
            ("encoded slash", "/nodes/pve1%2fqemu"),
            ("encoded slash, upper case", "/nodes/pve1%2Fqemu"),
            ("encoded dot", "/nodes/%2e%2e/access"),
            ("encoded dot, upper case", "/nodes/%2E%2E/access"),
            ("encoded backslash", "/nodes/pve1%5cqemu"),
            ("encoded percent", "/nodes/pve1%252fqemu"),
            ("any other encoding, which could spell a literal", "/nodes/pve1/qemu/100/agen%74/exec"),
            ("braces with no values", "/nodes/{node}"),
        ] {
            assert_eq!(err_kind(normalize_path(path, None)), Some("invalid_path"), "{label}");
        }
    }

    #[test]
    fn refuses_dangerous_placeholder_values() {
        let fill = |node: &str| err_kind(normalize_path("/nodes/{node}/status", Some(&map(json!({ "node": node })))));
        for bad in ["", "..", ".", "a\nb", "a\\b", "pve1/qemu/100/agent/exec"] {
            assert_eq!(fill(bad), Some("invalid_path"), "{bad:?}");
        }
        assert_eq!(err_kind(normalize_path("/nodes/{node}/status", Some(&Map::new()))), Some("invalid_input"));
    }

    #[test]
    fn lets_a_volume_or_cidr_hold_its_slash_but_no_traversal() {
        let path = "/nodes/{node}/storage/{storage}/content/{volume}";
        let values = json!({ "node": "pve1", "storage": "local", "volume": "local:iso/debian.iso" });
        let d = classify("DELETE", path, Some(&map(values.clone()))).unwrap();
        assert_eq!(d.template.as_deref(), Some(path));
        assert_eq!(d.url_path, "/nodes/pve1/storage/local/content/local:iso%2Fdebian.iso");
        assert_eq!(d.path_params["volume"], "local:iso/debian.iso");
        for bad in ["local:iso/../../../access", "../x"] {
            let mut v = map(values.clone());
            v.insert("volume".into(), json!(bad));
            assert_eq!(err_kind(classify("DELETE", path, Some(&v))), Some("invalid_path"), "{bad}");
        }
        let d = classify("GET", "/cluster/firewall/ipset/{name}/{cidr}", Some(&map(json!({ "name": "a", "cidr": "10.0.0.0/24" })))).unwrap();
        assert_eq!(d.url_path, "/cluster/firewall/ipset/a/10.0.0.0%2F24");
    }

    #[test]
    fn encodes_each_segment_on_its_own() {
        assert_eq!(encode_segment("a b"), "a%20b");
        assert_eq!(encode_segment("root@pam!tok"), "root@pam!tok");
        assert_eq!(encode_segment("UPID:pve1:1:"), "UPID:pve1:1:");
        assert_eq!(encode_segment("a?b#c%d"), "a%3Fb%23c%25d");
    }

    #[test]
    fn pins_the_number_of_methods_per_gate() {
        let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
        let mut destructive = 0;
        for e in &crate::catalog::CATALOG.endpoints {
            let d = classify(&e.method, &e.path, Some(&placeholders(&e.path))).unwrap();
            *counts.entry(d.gate.as_str()).or_default() += 1;
            if d.destructive {
                destructive += 1;
            }
            assert_eq!(d.template.as_deref(), Some(e.path.as_str()), "{} {}", e.method, e.path);
        }
        let want: std::collections::BTreeMap<&str, usize> =
            [("blocked", 11), ("console", 10), ("elevated", 209), ("guest_exec", 7), ("read", 314), ("sensitive", 21), ("write", 108)].into_iter().collect();
        assert_eq!(counts, want);
        assert_eq!(destructive, 135);
        assert_eq!(crate::catalog::CATALOG.endpoints.len(), 680);
    }

    #[test]
    fn classifies_like_typescript() {
        use Gate::*;
        let cases: &[(&str, &str, Gate, bool)] = &[
            // read
            ("GET", "/version", Read, false),
            ("GET", "/nodes/pve1/qemu", Read, false),
            ("GET", "/nodes/pve1/qemu/100/config", Read, false),
            ("GET", "/nodes/pve1/qemu/100/agent", Read, false),
            ("GET", "/nodes/pve1/qemu/100/agent/get-osinfo", Read, false),
            ("GET", "/cluster/resources", Read, false),
            ("GET", "/access/users", Read, false),
            ("GET", "/nodes/pve1/journal", Read, false),
            // sensitive
            ("GET", "/cluster/metrics/export", Sensitive, false),
            ("GET", "/cluster/config/join", Sensitive, false),
            ("GET", "/nodes/pve1/qemu/100/agent/file-read", Sensitive, false),
            ("GET", "/nodes/pve1/qemu/100/cloudinit/dump", Sensitive, false),
            ("GET", "/nodes/pve1/vzdump/extractconfig", Sensitive, false),
            ("GET", "/nodes/pve1/storage/local/file-restore/download", Sensitive, false),
            ("GET", "/nodes/pve1/report", Sensitive, false),
            ("GET", "/cluster/acme/plugins", Sensitive, false),
            ("GET", "/cluster/acme/plugins/x", Sensitive, false),
            ("GET", "/nodes/pve1/ceph/cfg/raw", Sensitive, false),
            ("GET", "/nodes/pve1/ceph/cfg/db", Sensitive, false),
            ("GET", "/nodes/pve1/ceph/cfg/value", Sensitive, false),
            ("GET", "/nodes/pve1/scan/cifs", Sensitive, false),
            ("GET", "/nodes/pve1/scan/iscsi", Sensitive, false),
            ("GET", "/nodes/pve1/scan/nfs", Sensitive, false),
            ("GET", "/nodes/pve1/scan/pbs", Sensitive, false),
            ("GET", "/nodes/pve1/query-url-metadata", Sensitive, false),
            ("GET", "/nodes/pve1/query-oci-repo-tags", Sensitive, false),
            ("GET", "/cluster/acme/meta", Sensitive, false),
            ("GET", "/cluster/acme/tos", Sensitive, false),
            ("GET", "/nodes/pve1/storage/local/file-restore/list", Sensitive, false),
            ("GET", "/nodes/pve1/scan/lvm", Read, false),
            ("GET", "/nodes/pve1/scan/zfs", Read, false),
            ("GET", "/cluster/acme/directories", Read, false),
            // write
            ("POST", "/nodes/pve1/qemu", Write, false),
            ("POST", "/nodes/pve1/lxc/100/status/start", Write, false),
            ("PUT", "/nodes/pve1/qemu/100/config", Write, false),
            ("POST", "/nodes/pve1/vzdump", Write, false),
            ("POST", "/pools", Write, false),
            ("POST", "/cluster/ha/resources", Write, false),
            ("POST", "/nodes/pve1/qemu/100/agent/ping", Write, false),
            ("POST", "/nodes/pve1/storage/local/upload", Write, false),
            // write, destructive
            ("DELETE", "/nodes/pve1/qemu/100", Write, true),
            ("POST", "/nodes/pve1/qemu/100/status/stop", Write, true),
            ("POST", "/nodes/pve1/qemu/100/status/reset", Write, true),
            ("POST", "/nodes/pve1/lxc/100/status/shutdown", Write, true),
            ("POST", "/nodes/pve1/lxc/100/status/reboot", Write, true),
            ("POST", "/nodes/pve1/qemu/100/status/suspend", Write, true),
            ("POST", "/nodes/pve1/qemu/100/snapshot/s/rollback", Write, true),
            ("POST", "/nodes/pve1/lxc/100/template", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/shutdown", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/suspend-disk", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/suspend-hybrid", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/suspend-ram", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/fsfreeze-freeze", Write, true),
            ("PUT", "/nodes/pve1/qemu/100/unlink", Write, true),
            ("POST", "/cluster/ha/resources/vm:100/relocate", Write, true),
            ("POST", "/nodes/pve1/qemu/100/agent/fsfreeze-thaw", Write, false),
            ("POST", "/nodes/pve1/qemu/100/agent/fstrim", Write, false),
            ("POST", "/cluster/ha/resources/vm:100/migrate", Write, false),
            // elevated
            ("PUT", "/access/acl", Elevated, false),
            ("POST", "/access/users", Elevated, false),
            ("POST", "/access/users/root@pam/token/x", Elevated, false),
            ("POST", "/storage", Elevated, false),
            ("DELETE", "/storage/local", Elevated, true),
            ("POST", "/cluster/config", Elevated, true),
            ("POST", "/cluster/config/join", Elevated, true),
            ("PUT", "/cluster/options", Elevated, false),
            ("PUT", "/cluster/ceph/flags", Elevated, false),
            ("POST", "/nodes/pve1/ceph/osd", Elevated, true),
            ("POST", "/cluster/acme/account", Elevated, false),
            ("POST", "/nodes/pve1/certificates/custom", Elevated, false),
            ("PUT", "/cluster/sdn", Elevated, true),
            ("POST", "/cluster/firewall/rules", Elevated, false),
            ("PUT", "/nodes/pve1/firewall/options", Elevated, false),
            ("POST", "/cluster/bulk-action/guest/start", Elevated, false),
            ("POST", "/cluster/bulk-action/guest/shutdown", Elevated, true),
            ("POST", "/cluster/bulk-action/guest/suspend", Elevated, true),
            ("POST", "/nodes/pve1/status", Elevated, true),
            ("POST", "/nodes/pve1/startall", Elevated, false),
            ("POST", "/nodes/pve1/stopall", Elevated, true),
            ("POST", "/nodes/pve1/suspendall", Elevated, true),
            ("POST", "/nodes/pve1/migrateall", Elevated, true),
            ("POST", "/nodes/pve1/wakeonlan", Elevated, false),
            ("POST", "/nodes/pve1/apt/update", Elevated, false),
            ("PUT", "/nodes/pve1/network", Elevated, true),
            ("PUT", "/nodes/pve1/dns", Elevated, false),
            ("POST", "/nodes/pve1/hosts", Elevated, true),
            ("PUT", "/nodes/pve1/time", Elevated, false),
            ("PUT", "/nodes/pve1/config", Elevated, false),
            ("POST", "/nodes/pve1/services/pveproxy/restart", Elevated, true),
            ("PUT", "/nodes/pve1/subscription", Elevated, false),
            ("PUT", "/nodes/pve1/disks/wipedisk", Elevated, true),
            ("POST", "/nodes/pve1/disks/zfs", Elevated, true),
            ("POST", "/nodes/pve1/qemu/100/remote_migrate", Elevated, false),
            ("POST", "/cluster/config/nodes/pve2", Elevated, true),
            ("POST", "/cluster/sdn/rollback", Elevated, true),
            ("POST", "/cluster/ceph/restart-bulk", Elevated, true),
            ("POST", "/nodes/pve1/ceph/restart", Elevated, true),
            ("POST", "/nodes/pve1/ceph/restart-bulk", Elevated, true),
            ("POST", "/nodes/pve1/ceph/stop", Elevated, true),
            ("POST", "/nodes/pve1/ceph/start", Elevated, false),
            ("POST", "/nodes/pve1/ceph/osd/1/out", Elevated, true),
            ("POST", "/nodes/pve1/ceph/osd/1/in", Elevated, false),
            ("POST", "/cluster/bulk-action/guest/migrate", Elevated, true),
            ("POST", "/nodes/pve1/disks/initgpt", Elevated, true),
            ("POST", "/nodes/pve1/disks/directory", Elevated, true),
            ("POST", "/nodes/pve1/disks/lvm", Elevated, true),
            ("POST", "/nodes/pve1/disks/lvmthin", Elevated, true),
            ("POST", "/nodes/pve1/network", Elevated, false),
            ("POST", "/nodes/pve1/services/pveproxy/stop", Elevated, true),
            ("POST", "/nodes/pve1/services/pveproxy/start", Elevated, false),
            ("POST", "/nodes/pve1/services/pveproxy/reload", Elevated, false),
            ("PUT", "/access/password", Elevated, true),
            ("POST", "/cluster/ha/status/arm-ha", Elevated, false),
            ("POST", "/cluster/ha/status/disarm-ha", Elevated, true),
            ("POST", "/cluster/jobs/realm-sync/x", Elevated, false),
            ("POST", "/cluster/mapping/pci", Elevated, false),
            ("PUT", "/cluster/mapping/dir/x", Elevated, false),
            ("POST", "/cluster/metrics/server/x", Elevated, false),
            ("POST", "/cluster/notifications/endpoints/webhook", Elevated, false),
            ("POST", "/cluster/notifications/matchers", Elevated, false),
            ("POST", "/cluster/notifications/targets/x/test", Elevated, false),
            ("POST", "/cluster/qemu/custom-cpu-models", Elevated, false),
            ("GET", "/cluster/mapping/pci", Read, false),
            ("GET", "/cluster/metrics/server", Read, false),
            ("GET", "/cluster/notifications/endpoints/webhook", Read, false),
            ("POST", "/nodes/pve1/lxc/100/remote_migrate", Elevated, false),
            // guest_exec
            ("POST", "/nodes/pve1/qemu/100/agent/exec", GuestExec, true),
            ("GET", "/nodes/pve1/qemu/100/agent/exec-status", GuestExec, false),
            ("POST", "/nodes/pve1/qemu/100/agent/file-write", GuestExec, true),
            ("POST", "/nodes/pve1/qemu/100/agent/set-user-password", GuestExec, true),
            ("POST", "/nodes/pve1/qemu/100/monitor", GuestExec, true),
            ("POST", "/nodes/pve1/qemu/100/agent", GuestExec, true),
            ("PUT", "/nodes/pve1/qemu/100/sendkey", GuestExec, true),
            // console
            ("POST", "/nodes/pve1/qemu/100/vncproxy", Console, false),
            ("POST", "/nodes/pve1/qemu/100/termproxy", Console, false),
            ("POST", "/nodes/pve1/qemu/100/spiceproxy", Console, false),
            ("POST", "/nodes/pve1/lxc/100/vncproxy", Console, false),
            ("POST", "/nodes/pve1/lxc/100/termproxy", Console, false),
            ("POST", "/nodes/pve1/lxc/100/spiceproxy", Console, false),
            ("POST", "/nodes/pve1/vncshell", Console, false),
            ("POST", "/nodes/pve1/termproxy", Console, false),
            ("POST", "/nodes/pve1/spiceshell", Console, false),
            ("POST", "/access/vncticket", Console, false),
            // blocked
            ("POST", "/nodes/pve1/execute", Blocked, false),
            ("GET", "/nodes/pve1/vncwebsocket", Blocked, false),
            ("GET", "/nodes/pve1/qemu/100/vncwebsocket", Blocked, false),
            ("GET", "/nodes/pve1/lxc/100/vncwebsocket", Blocked, false),
            ("GET", "/nodes/pve1/qemu/100/mtunnelwebsocket", Blocked, false),
            ("POST", "/nodes/pve1/qemu/100/mtunnel", Blocked, false),
            ("POST", "/nodes/pve1/lxc/100/mtunnel", Blocked, false),
            ("POST", "/access/ticket", Blocked, false),
            ("GET", "/access/ticket", Blocked, false),
            ("POST", "/access/openid/login", Blocked, false),
        ];
        let mut wrong = Vec::new();
        for (method, path, gate, destructive) in cases {
            let d = classify(method, path, None).unwrap();
            if d.gate != *gate || d.destructive != *destructive {
                wrong.push(format!("{method} {path}: {} {} (want {} {destructive})", d.gate.as_str(), d.destructive, gate.as_str()));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn fails_closed_on_unknown_paths() {
        let get = classify("GET", "/nodes/pve1/qemu/100/brand-new", None).unwrap();
        assert_eq!(get.gate, Gate::Sensitive);
        assert!(get.template.is_none());
        assert_eq!(classify("POST", "/nodes/pve1/qemu/100/brand-new", None).unwrap().gate, Gate::Elevated);
        assert_eq!(classify("PUT", "/nope", None).unwrap().gate, Gate::Elevated);
        assert!(classify("DELETE", "/nope", None).unwrap().destructive);
        assert_eq!(classify("DELETE", "/version", None).unwrap().gate, Gate::Elevated);
        assert_eq!(classify("POST", "/version", None).unwrap().gate, Gate::Elevated);
        assert_eq!(classify("PUT", "/nodes/pve1/qemu/100/status/current", None).unwrap().gate, Gate::Elevated);
    }

    #[test]
    fn case_or_a_variant_never_reaches_a_rule_by_the_side() {
        for path in ["/NODES/pve1/qemu/100/agent/exec", "/nodes/pve1/QEMU/100/agent/exec", "/nodes/pve1/qemu/100/agent/EXEC", "/nodes/pve1/qemu/100/agent/exec/x"] {
            let d = classify("POST", path, None).unwrap();
            assert!(d.template.is_none(), "{path}");
            assert_eq!(d.gate, Gate::Elevated, "{path}");
        }
    }

    #[test]
    fn keeps_blocked_and_exec_rules_outside_the_catalog() {
        assert_eq!(classify("GET", "/nodes/pve1/execute", None).unwrap().gate, Gate::Blocked);
        assert_eq!(classify("PUT", "/access/ticket", None).unwrap().gate, Gate::Blocked);
        assert_eq!(classify("DELETE", "/nodes/pve1/lxc/100/mtunnel", None).unwrap().gate, Gate::Blocked);
        assert_eq!(classify("GET", "/nodes/pve1/qemu/100/vncproxy", None).unwrap().gate, Gate::Console);
    }

    fn pairs(m: &IndexMap<String, String>) -> Vec<(&str, &str)> {
        m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn matches_literal_segments_before_placeholders() {
        assert_eq!(classify("GET", "/nodes/pve1/qemu/100/status/current", None).unwrap().template.as_deref(), Some("/nodes/{node}/qemu/{vmid}/status/current"));
        assert_eq!(classify("GET", "/cluster/firewall/groups", None).unwrap().template.as_deref(), Some("/cluster/firewall/groups"));
        assert_eq!(classify("GET", "/cluster/firewall/groups/g1", None).unwrap().template.as_deref(), Some("/cluster/firewall/groups/{group}"));
        assert_eq!(pairs(&classify("GET", "/nodes/pve1/ceph/osd/3", None).unwrap().path_params), vec![("node", "pve1"), ("osdid", "3")]);
    }

    #[test]
    fn derives_path_params_from_the_template() {
        assert_eq!(pairs(&classify("PUT", "/cluster/ha/rules/r1", None).unwrap().path_params), vec![("rule", "r1")]);
        assert_eq!(pairs(&classify("PUT", "/cluster/sdn/prefix-lists/p1/entries/5", None).unwrap().path_params), vec![("id", "p1"), ("url_seq", "5")]);
    }

    #[test]
    fn refuses_other_http_methods() {
        assert_eq!(err_kind(classify("PATCH", "/version", None)), Some("invalid_input"));
        assert_eq!(err_kind(classify("get", "/version", None)), Some("invalid_input"));
    }

    #[test]
    fn force_on_create_and_purge_are_destructive() {
        let d = |m: &str, t: &str, a: serde_json::Value| destructive_args(m, t, &map(a));
        assert!(d("POST", "/nodes/{node}/lxc", json!({ "force": true })));
        assert!(d("POST", "/nodes/{node}/qemu", json!({ "force": true })));
        assert!(!d("POST", "/nodes/{node}/lxc", json!({ "force": false, "unprivileged": 1 })));
        assert!(!d("POST", "/nodes/{node}/lxc", json!({ "unprivileged": 1 })));
        assert!(d("POST", "/nodes/{node}/lxc", json!({})));
        assert!(d("POST", "/some/{thing}", json!({ "purge": 1 })));
        assert!(!d("POST", "/some/{thing}", json!({ "force": true })));
        assert!(!d("GET", "/some/{thing}", json!({ "purge": true })));
    }

    #[test]
    fn destructive_argument_values() {
        let vm = "/nodes/{node}/qemu/{vmid}/config";
        let ct = "/nodes/{node}/lxc/{vmid}/config";
        let cases: Vec<(&str, &str, serde_json::Value, bool)> = vec![
            ("PUT", vm, json!({ "delete": "unused0" }), true),
            ("POST", vm, json!({ "delete": "cores,unused1" }), true),
            ("PUT", ct, json!({ "delete": "unused0" }), true),
            ("PUT", vm, json!({ "delete": "cores,memory" }), false),
            ("PUT", vm, json!({ "force": 1 }), true),
            ("PUT", vm, json!({ "force": 0, "cores": 2 }), false),
            ("POST", "/nodes/{node}/qemu/{vmid}/move_disk", json!({ "delete": true }), true),
            ("POST", "/nodes/{node}/qemu/{vmid}/move_disk", json!({ "delete": false }), false),
            ("POST", "/nodes/{node}/lxc/{vmid}/move_volume", json!({ "delete": "yes" }), true),
            ("POST", "/nodes/{node}/lxc/{vmid}/migrate", json!({ "restart": 1 }), true),
            ("POST", "/nodes/{node}/lxc/{vmid}/migrate", json!({ "online": 1 }), false),
            ("PUT", "/access/users/{userid}/token/{tokenid}", json!({ "regenerate": true }), true),
            ("PUT", "/access/users/{userid}/token/{tokenid}", json!({ "comment": "x" }), false),
            ("PUT", "/access/acl", json!({ "delete": true, "path": "/" }), true),
            ("PUT", "/access/acl", json!({ "path": "/" }), false),
            ("POST", "/access/domains/{realm}/sync", json!({ "remove-vanished": "acl;entry" }), true),
            ("POST", "/access/domains/{realm}/sync", json!({ "remove-vanished": "none" }), false),
            ("POST", "/access/domains/{realm}/sync", json!({ "remove-vanished": "entry", "dry-run": true }), false),
            ("POST", "/cluster/jobs/realm-sync/{id}", json!({ "remove-vanished": "entry" }), true),
            ("PUT", "/cluster/ha/resources/{sid}", json!({ "state": "stopped" }), true),
            ("POST", "/cluster/ha/resources", json!({ "state": "disabled" }), true),
            ("PUT", "/cluster/ha/resources/{sid}", json!({ "state": "started" }), false),
            ("PUT", "/cluster/replication/{id}", json!({ "remove_job": "full" }), true),
            ("PUT", "/cluster/replication/{id}", json!({ "rate": 10 }), false),
            ("POST", "/nodes/{node}/vzdump", json!({ "mode": "stop" }), true),
            ("POST", "/nodes/{node}/vzdump", json!({ "stop": 1 }), true),
            ("POST", "/nodes/{node}/vzdump", json!({ "mode": "snapshot" }), false),
            ("PUT", "/cluster/ceph/flags", json!({ "pause": 1 }), true),
            ("PUT", "/cluster/ceph/flags", json!({ "noout": 1 }), false),
            ("PUT", "/cluster/ceph/flags/{flag}", json!({ "flag": "pause", "value": true }), true),
            ("PUT", "/cluster/ceph/flags/{flag}", json!({ "flag": "noout", "value": true }), false),
            ("POST", "/nodes/{node}/certificates/custom", json!({ "force": true }), true),
            ("POST", "/nodes/{node}/certificates/acme/certificate", json!({ "force": true }), true),
            ("PUT", "/cluster/firewall/options", json!({ "enable": 1 }), true),
            ("PUT", "/nodes/{node}/firewall/options", json!({ "enable": 0 }), true),
            ("PUT", "/cluster/firewall/options", json!({ "policy_in": "DROP" }), false),
            ("PUT", vm, json!({ "hookscript": "local:snippets/x.sh" }), true),
            ("POST", "/nodes/{node}/qemu", json!({ "hostpci": { "0": "01:00.0" } }), true),
            ("POST", "/nodes/{node}/qemu", json!({ "hostpci0": "01:00.0" }), true),
            ("PUT", ct, json!({ "mp": { "0": "/srv,mp=/mnt" } }), true),
            ("POST", "/nodes/{node}/vzdump", json!({ "script": "/root/x.sh" }), true),
        ];
        let mut wrong = Vec::new();
        for (m, t, a, want) in cases {
            if destructive_args(m, t, &map(a.clone())) != want {
                wrong.push(format!("{m} {t} {a}: want {want}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn conditional_marks_exactly_the_endpoints_with_a_watched_parameter() {
        let conditional: Vec<String> = crate::catalog::CATALOG
            .endpoints
            .iter()
            .filter(|e| has_destructive_args(|p| e.params.contains_key(p), &e.method, &e.path))
            .map(|e| format!("{} {}", e.method, e.path))
            .collect();
        for key in [
            "PUT /nodes/{node}/qemu/{vmid}/config",
            "POST /nodes/{node}/qemu/{vmid}/config",
            "POST /nodes/{node}/qemu",
            "PUT /nodes/{node}/lxc/{vmid}/config",
            "POST /nodes/{node}/lxc",
            "POST /nodes/{node}/vzdump",
            "POST /cluster/backup",
            "PUT /access/acl",
            "PUT /cluster/ceph/flags/{flag}",
            "POST /access/domains/{realm}/sync",
            "DELETE /nodes/{node}/qemu/{vmid}",
            "POST /nodes/{node}/certificates/custom",
            "PUT /cluster/replication/{id}",
            "PUT /cluster/firewall/options",
            "POST /nodes/{node}/lxc/{vmid}/migrate",
        ] {
            assert!(conditional.iter().any(|c| c == key), "{key}");
        }
        assert!(!conditional.iter().any(|c| c == "POST /nodes/{node}/qemu/{vmid}/status/start"));
        assert!(!conditional.iter().any(|c| c == "GET /nodes/{node}/qemu/{vmid}/config"));
    }

    #[test]
    fn arguments_that_reach_the_host() {
        let writes = subj(Allow { writes: true, ..Default::default() });
        let elevated = subj(Allow { writes: true, elevated: true, ..Default::default() });
        let vm = "/nodes/pve1/qemu/100/config";
        let ct = "/nodes/pve1/lxc/101/config";
        let cases: Vec<(&str, &str, serde_json::Value, Option<&str>)> = vec![
            ("PUT", vm, json!({ "hookscript": "local:snippets/x.sh" }), Some("hookscript")),
            ("POST", vm, json!({ "args": "-device foo" }), Some("args")),
            ("POST", "/nodes/pve1/qemu", json!({ "vmid": 200, "hostpci0": "01:00.0" }), Some("hostpci")),
            ("POST", "/nodes/pve1/qemu", json!({ "vmid": 200, "hostpci": { "0": "01:00.0" } }), Some("hostpci")),
            ("PUT", vm, json!({ "parallel0": "/dev/parport0" }), Some("parallel")),
            ("PUT", vm, json!({ "serial0": "/dev/ttyS0" }), Some("serial")),
            ("PUT", vm, json!({ "usb0": "host=1234:5678" }), Some("usb")),
            ("PUT", vm, json!({ "usb1": "spice,usb3=1,host=1-2" }), Some("usb")),
            ("PUT", ct, json!({ "hookscript": "local:snippets/x.sh" }), Some("hookscript")),
            ("PUT", ct, json!({ "dev0": "/dev/fuse" }), Some("dev")),
            ("PUT", ct, json!({ "mp0": "/srv/data,mp=/mnt" }), Some("mp")),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "mp": { "0": "volume=/srv/data,mp=/mnt" } }), Some("mp")),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "mp0": "mp=/mnt,volume=/srv/data" }), Some("mp")),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "rootfs": "/srv/root" }), Some("rootfs")),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "unprivileged": 0 }), Some("unprivileged")),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "unprivileged": false }), Some("unprivileged")),
            ("POST", "/nodes/pve1/vzdump", json!({ "vmid": 100, "script": "/root/x.sh" }), Some("script")),
            ("POST", "/nodes/pve1/vzdump", json!({ "vmid": 100, "dumpdir": "/root" }), Some("dumpdir")),
            ("POST", "/cluster/backup", json!({ "schedule": "daily", "tmpdir": "/root" }), Some("tmpdir")),
            ("PUT", "/cluster/backup/x", json!({ "script": "/root/x.sh" }), Some("script")),
            ("PUT", vm, json!({ "cores": 2, "net0": "virtio,bridge=vmbr0", "scsi0": "local-lvm:32" }), None),
            ("PUT", vm, json!({ "serial0": "socket", "usb0": "spice" }), None),
            ("PUT", vm, json!({ "usb0": "mapping=stick" }), None),
            ("PUT", ct, json!({ "mp0": "local-lvm:8,mp=/mnt", "rootfs": "local-lvm:8" }), None),
            ("POST", "/nodes/pve1/lxc", json!({ "vmid": 200, "rootfs": "volume=local-lvm:8,size=8G", "unprivileged": 1 }), None),
            ("POST", "/nodes/pve1/vzdump", json!({ "vmid": 100, "storage": "local" }), None),
        ];
        for (method, path, params, arg) in cases {
            let params = map(params);
            let template = classify(method, path, None).unwrap().template;
            assert_eq!(host_access_arg(method, template.as_deref(), Some(&params)), arg, "{method} {path} {params:?}");
            let opts = AuthorizeOptions { params: Some(&params), ..Default::default() };
            assert_eq!(auth(&writes, method, path, &[], &opts), arg.map(|_| "elevated_disabled"), "{method} {path} {params:?}");
            assert_eq!(auth(&elevated, method, path, &[], &opts), None, "{method} {path} {params:?}");
        }
    }

    #[test]
    fn host_access_refusal_names_the_argument_and_holds_on_a_dry_run() {
        let writes = subj(Allow { writes: true, ..Default::default() });
        let params = map(json!({ "hookscript": "x" }));
        let e = authorize(&writes, "PUT", "/nodes/pve1/qemu/100/config", &[], &AuthorizeOptions { params: Some(&params), ..Default::default() }).unwrap_err();
        assert!(e.message.contains("with \"hookscript\""), "{}", e.message);
        let opts = AuthorizeOptions { dry_run: true, params: Some(&params), ..Default::default() };
        assert_eq!(auth(&subj(Allow::default()), "PUT", "/nodes/pve1/qemu/100/config", &[], &opts), Some("elevated_disabled"));
    }

    #[test]
    fn host_access_only_where_the_arguments_mean_it() {
        let args = map(json!({ "args": "x" }));
        assert_eq!(host_access_arg("PUT", Some("/nodes/{node}/qemu/{vmid}/firewall/options"), Some(&args)), None);
        assert_eq!(host_access_arg("GET", Some("/nodes/{node}/qemu/{vmid}/config"), Some(&args)), None);
        assert_eq!(host_access_arg("POST", None, Some(&args)), None);
    }

    #[test]
    fn announces_only_parameters_the_schema_has() {
        let on = |method: &str, template: &str| {
            let e = crate::catalog::find_endpoint(method, template).unwrap();
            host_access_params(|p| e.params.contains_key(p), method, template)
        };
        assert_eq!(on("POST", "/nodes/{node}/qemu"), vec!["hookscript", "args", "hostpci[n]", "parallel[n]", "usb[n]", "serial[n]"]);
        assert_eq!(on("PUT", "/nodes/{node}/qemu/{vmid}/config"), vec!["hookscript", "args", "hostpci[n]", "parallel[n]", "usb[n]", "serial[n]"]);
        assert_eq!(on("POST", "/nodes/{node}/lxc"), vec!["hookscript", "dev[n]", "mp[n]", "rootfs", "unprivileged"]);
        assert_eq!(on("POST", "/nodes/{node}/vzdump"), vec!["script", "dumpdir", "tmpdir"]);
        assert_eq!(on("PUT", "/cluster/backup/{id}"), vec!["script", "dumpdir", "tmpdir"]);
    }

    #[test]
    fn gates() {
        let none = subj(Allow::default());
        let writes = subj(Allow { writes: true, ..Default::default() });
        let elevated = subj(Allow { writes: true, elevated: true, ..Default::default() });
        let dry = subj(Allow { dry_run: true, ..Default::default() });
        let plain = AuthorizeOptions::default();
        let t = |s: &PolicySubject, m: &str, p: &str| auth(s, m, p, &[], &plain);

        // read needs nothing
        assert_eq!(t(&none, "GET", "/nodes"), None);

        // sensitive needs allow_sensitive
        assert_eq!(t(&none, "GET", "/nodes/pve1/report"), Some("sensitive_disabled"));
        assert_eq!(t(&elevated, "GET", "/nodes/pve1/report"), Some("sensitive_disabled"));
        assert_eq!(t(&subj(Allow { sensitive: true, ..Default::default() }), "GET", "/nodes/pve1/report"), None);

        // write needs writes or a dry run
        let start = "/nodes/pve1/qemu/100/status/start";
        assert_eq!(t(&none, "POST", start), Some("write_disabled"));
        assert_eq!(t(&writes, "POST", start), None);
        assert_eq!(t(&dry, "POST", start), None);
        assert_eq!(auth(&none, "POST", start, &[], &AuthorizeOptions { dry_run: true, ..Default::default() }), None);

        // elevated needs writes (or a dry run) and allow_elevated
        let users = "/access/users";
        assert_eq!(t(&none, "POST", users), Some("write_disabled"));
        assert_eq!(t(&subj(Allow { elevated: true, ..Default::default() }), "POST", users), Some("write_disabled"));
        assert_eq!(t(&writes, "POST", users), Some("elevated_disabled"));
        assert_eq!(t(&dry, "POST", users), Some("elevated_disabled"));
        assert_eq!(t(&elevated, "POST", users), None);
        assert_eq!(t(&subj(Allow { dry_run: true, elevated: true, ..Default::default() }), "POST", users), None);

        // guest_exec needs allow_guest_exec, plus writes on anything but GET
        let post = "/nodes/pve1/qemu/100/agent/exec";
        let get = "/nodes/pve1/qemu/100/agent/exec-status";
        assert_eq!(t(&elevated, "POST", post), Some("guest_exec_disabled"));
        assert_eq!(t(&subj(Allow { guest_exec: true, ..Default::default() }), "POST", post), Some("write_disabled"));
        assert_eq!(t(&subj(Allow { guest_exec: true, writes: true, ..Default::default() }), "POST", post), None);
        assert_eq!(t(&subj(Allow { guest_exec: true, dry_run: true, ..Default::default() }), "POST", post), None);
        assert_eq!(t(&none, "GET", get), Some("guest_exec_disabled"));
        assert_eq!(t(&subj(Allow { guest_exec: true, ..Default::default() }), "GET", get), None);
        assert_eq!(auth(&subj(Allow { guest_exec: true, ..Default::default() }), "GET", get, &[], &AuthorizeOptions { read_only: true, ..Default::default() }), None);

        // console needs elevated, sensitive and writes, with no dry-run shortcut
        let term = "/nodes/pve1/termproxy";
        assert_eq!(t(&subj(Allow { elevated: true, writes: true, ..Default::default() }), "POST", term), Some("elevated_disabled"));
        assert_eq!(t(&subj(Allow { sensitive: true, writes: true, ..Default::default() }), "POST", term), Some("elevated_disabled"));
        assert_eq!(t(&subj(Allow { sensitive: true, elevated: true, ..Default::default() }), "POST", term), Some("elevated_disabled"));
        assert_eq!(t(&subj(Allow { sensitive: true, elevated: true, dry_run: true, ..Default::default() }), "POST", term), Some("elevated_disabled"));
        assert_eq!(t(&subj(Allow { sensitive: true, elevated: true, writes: true, ..Default::default() }), "POST", term), None);
    }

    #[test]
    fn blocked_stays_blocked_unless_listed_then_it_is_elevated() {
        let all = subj(Allow { writes: true, elevated: true, guest_exec: true, sensitive: true, ssh: true, ..Default::default() });
        let writes = subj(Allow { writes: true, ..Default::default() });
        let o = AuthorizeOptions::default();
        let exec = "/nodes/pve1/execute";
        assert_eq!(auth(&all, "POST", exec, &[], &o), Some("blocked_endpoint"));
        assert_eq!(auth(&all, "POST", exec, &["POST /nodes/{node}/execute"], &o), None);
        assert_eq!(auth(&all, "POST", exec, &["/nodes/{node}/execute"], &o), None);
        assert_eq!(auth(&all, "POST", exec, &["GET /nodes/{node}/execute"], &o), Some("blocked_endpoint"));
        assert_eq!(auth(&all, "POST", exec, &["/nodes/{node}/vncwebsocket"], &o), Some("blocked_endpoint"));
        assert_eq!(auth(&writes, "POST", exec, &["/nodes/{node}/execute"], &o), Some("elevated_disabled"));
        assert_eq!(authorize(&all, "POST", exec, &["/nodes/{node}/execute".to_string()], &o).unwrap().gate, Gate::Elevated);
    }

    #[test]
    fn a_read_scope_refuses_anything_but_a_read() {
        let all = subj(Allow { writes: true, elevated: true, guest_exec: true, sensitive: true, ..Default::default() });
        let ro = AuthorizeOptions { read_only: true, ..Default::default() };
        assert_eq!(auth(&all, "POST", "/nodes/pve1/qemu/100/status/start", &[], &ro), Some("not_read_only"));
        assert_eq!(auth(&all, "DELETE", "/nodes/pve1/qemu/100", &[], &ro), Some("not_read_only"));
        assert_eq!(auth(&all, "GET", "/nodes", &[], &ro), None);
        assert_eq!(auth(&all, "GET", "/nodes/pve1/report", &[], &ro), None);
        assert_eq!(auth(&all, "GET", "/nodes/pve1/vncwebsocket", &["/nodes/{node}/vncwebsocket"], &ro), Some("not_read_only"));
    }

    #[test]
    fn checks_the_path_before_the_gate_and_hides_encoded_bypasses() {
        assert_eq!(auth(&subj(Allow::default()), "POST", "/nodes/pve1/../x", &[], &AuthorizeOptions::default()), Some("invalid_path"));
        let all = subj(Allow { writes: true, elevated: true, guest_exec: true, sensitive: true, ..Default::default() });
        for path in ["/nodes/pve1/qemu/100/agent%2Fexec", "/nodes/pve1/qemu/100/status%2fstart", "/nodes/x%2F..%2Fpve1/execute", "/nodes/pve1/execut%65"] {
            assert_eq!(auth(&all, "POST", path, &[], &AuthorizeOptions::default()), Some("invalid_path"), "{path}");
        }
    }

    fn protected() -> BTreeSet<i64> {
        [100, 101].into_iter().collect()
    }

    fn check(method: &str, path: &str, params: Option<serde_json::Value>) -> Option<&'static str> {
        let d = classify(method, path, None).unwrap();
        let params = params.map(map);
        err_kind(assert_not_protected(&protected(), method, &d, params.as_ref()))
    }

    #[test]
    fn refuses_any_change_to_a_protected_guest_and_nothing_else() {
        assert_eq!(check("POST", "/nodes/pve1/qemu/100/status/stop", None), Some("protected_guest"));
        assert_eq!(check("DELETE", "/nodes/pve1/lxc/101", None), Some("protected_guest"));
        assert_eq!(check("PUT", "/nodes/pve1/qemu/100/config", None), Some("protected_guest"));
        assert_eq!(check("GET", "/nodes/pve1/qemu/100/config", None), None);
        assert_eq!(check("POST", "/nodes/pve1/qemu/102/status/stop", None), None);
        // A vmid given as a parameter: create with force would replace it, clone would write over it.
        assert_eq!(check("POST", "/nodes/pve1/qemu", Some(json!({ "vmid": 100, "force": 1 }))), Some("protected_guest"));
        assert_eq!(check("POST", "/nodes/pve1/qemu/102/clone", Some(json!({ "newid": 101 }))), Some("protected_guest"));
        assert_eq!(check("POST", "/nodes/pve1/qemu", Some(json!({ "vmid": 102 }))), None);
        // Any matching segment on a path outside the catalog.
        assert_eq!(check("POST", "/nodes/pve1/qemu/100/brand-new", None), Some("protected_guest"));
    }

    #[test]
    fn sees_the_guest_behind_a_volume_or_a_backup() {
        let volume = |id: &str| {
            let d = classify("DELETE", "/nodes/{node}/storage/{storage}/content/{volume}", Some(&map(json!({ "node": "pve1", "storage": "s", "volume": id })))).unwrap();
            assert_not_protected(&protected(), "DELETE", &d, None)
        };
        for id in [
            "local-lvm:vm-100-disk-0",
            "local:100/vm-100-disk-0.qcow2",
            "local:101/subvol-101-disk-0.subvol",
            "local:100/base-100-disk-0.raw",
            "local:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst",
            "local:backup/vzdump-lxc-101-2026_01_01-00_00_00.tar.zst",
            "pbs:backup/vm/100/2026-01-01T00:00:00Z",
            "pbs:backup/ct/101/2026-01-01T00:00:00Z",
        ] {
            let e = volume(id).expect_err(id);
            assert!(e.message.contains("protected"), "{id}");
        }
        for id in ["local:iso/debian-100-netinst.iso", "local-lvm:vm-102-disk-0", "local:backup/vzdump-qemu-102-2026_01_01-00_00_00.vma.zst", "pbs:backup/vm/102/2026-01-01T00:00:00Z"] {
            assert!(volume(id).is_ok(), "{id}");
        }
    }

    #[test]
    fn sees_the_guests_named_by_a_bulk_action_a_target_or_a_replication_job() {
        let p = Some("protected_guest");
        assert_eq!(check("POST", "/nodes/pve1/stopall", Some(json!({ "vms": "102,100" }))), p);
        assert_eq!(check("POST", "/nodes/pve1/stopall", Some(json!({ "vms": "102 100" }))), p);
        assert_eq!(check("POST", "/nodes/pve1/stopall", Some(json!({ "vms": "102" }))), None);
        assert_eq!(check("POST", "/cluster/bulk-action/guest/shutdown", Some(json!({ "vms": [102, 100] }))), p);
        assert_eq!(check("POST", "/cluster/bulk-action/guest/shutdown", Some(json!({ "vms": [102] }))), None);
        assert_eq!(check("POST", "/nodes/pve1/qemu/102/move_disk", Some(json!({ "target-vmid": 100 }))), p);
        assert_eq!(check("POST", "/cluster/replication", Some(json!({ "id": "100-0", "target": "pve2", "type": "local" }))), p);
        assert_eq!(check("PUT", "/cluster/replication/100-0", None), p);
        assert_eq!(check("DELETE", "/cluster/replication/101-3", None), p);
        assert_eq!(check("DELETE", "/cluster/replication/102-0", None), None);
    }

    #[test]
    fn reaching_every_guest_counts_as_naming_the_protected_ones() {
        let p = Some("protected_guest");
        for path in [
            "/nodes/pve1/stopall",
            "/nodes/pve1/startall",
            "/nodes/pve1/suspendall",
            "/nodes/pve1/migrateall",
            "/cluster/bulk-action/guest/shutdown",
            "/cluster/bulk-action/guest/start",
            "/cluster/bulk-action/guest/suspend",
            "/cluster/bulk-action/guest/migrate",
        ] {
            assert_eq!(check("POST", path, None), p, "{path}");
            assert_eq!(check("POST", path, Some(json!({ "vms": [] }))), p, "{path}");
            assert_eq!(check("POST", path, Some(json!({ "vms": "" }))), p, "{path}");
            assert_eq!(check("POST", path, Some(json!({ "vms": "102" }))), None, "{path}");
        }
        assert_eq!(check("POST", "/nodes/pve1/vzdump", Some(json!({ "all": 1 }))), p);
        assert_eq!(check("POST", "/cluster/backup", Some(json!({ "all": true, "schedule": "daily", "storage": "local" }))), p);
        assert_eq!(check("PUT", "/cluster/backup/job1", Some(json!({ "all": 1 }))), p);
        assert_eq!(check("POST", "/nodes/pve1/vzdump", Some(json!({ "all": 1, "exclude": "100,101" }))), None);
        assert_eq!(check("POST", "/nodes/pve1/vzdump", Some(json!({ "all": 0 }))), None);
        assert_eq!(check("POST", "/nodes/pve1/vzdump", Some(json!({ "vmid": "102" }))), None);
    }

    #[test]
    fn leaves_alone_what_only_looks_like_a_protected_guest() {
        assert_eq!(check("POST", "/nodes/pve1/qemu/102/remote_migrate", Some(json!({ "target-vmid": 100 }))), None);
        assert_eq!(check("PUT", "/pools", Some(json!({ "poolid": "p", "vms": "100" }))), None);
        let d = classify("DELETE", "/nodes/pve1/lxc/101", None).unwrap();
        assert!(assert_not_protected(&BTreeSet::new(), "DELETE", &d, None).is_ok());
    }
}
