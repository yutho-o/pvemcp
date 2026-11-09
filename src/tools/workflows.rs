//! Composite tools: several API calls behind one question or one job. Each section that could
//! not be read is named in `unavailable` and is never taken for good news, and each step of a
//! provisioning job is reported, with what it left behind when it stops.

use super::{Args, ArgsExt, FinishOptions, Source, ToolContext, ToolDef, gather, node_name, page_limit, page_offset, page_rows, paging_args, vmid};
use crate::errors::{PveError, Result, kind};
use crate::js::{Row, encode_uri_component, iso_from_millis, js_number_str, js_round, js_string, js_string_opt, nonempty_str, now_millis, num, number, number_text, rows_of, truthy_js};
use crate::obj;
use crate::proxmox::nodes::GuestLocation;
use crate::proxmox::policy::Gate;
use crate::proxmox::tasks::parse_upid;
use crate::proxmox::{Api, RequestOptions};
use crate::schema::{Schema, z};
use crate::shape;
use futures::FutureExt;
use futures::future::BoxFuture;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

const DAY_SECONDS: f64 = 86_400.0;
const DEFAULT_TASK_HOURS: f64 = 24.0;
const DEFAULT_STORAGE_WARN_PERCENT: f64 = 85.0;
const DEFAULT_STORAGE_CRITICAL_PERCENT: f64 = 95.0;
const DEFAULT_MEMORY_WARN_PERCENT: f64 = 90.0;
const DEFAULT_CERT_WARN_DAYS: f64 = 30.0;
const DEFAULT_BACKUP_MAX_AGE_DAYS: f64 = 7.0;
const DEFAULT_LXC_NET: &str = "name=eth0,bridge=vmbr0,ip=dhcp";
const DEFAULT_IP_WAIT_SECONDS: f64 = 30.0;
const DEFAULT_AGENT_WAIT_SECONDS: f64 = 120.0;
const MAX_LOG_PAGES: usize = 20;
const LOG_PAGE: usize = 5000;
/// A cluster where a whole section fails should not drown the answer in one reason per guest.
const MAX_REASONS_PER_SECTION: usize = 10;
const MAX_LISTED: usize = 50;
const MIN_FORECAST_POINTS: usize = 3;

const CORE_SERVICES: [&str; 8] = ["pve-cluster", "corosync", "pveproxy", "pvedaemon", "pvestatd", "pve-firewall", "pve-ha-crm", "pve-ha-lrm"];
/// Roles that amount to running the cluster, when granted on the root path.
const POWERFUL_ROLES: [&str; 8] = ["Administrator", "PVEAdmin", "PVESysAdmin", "PVEVMAdmin", "PVEDatastoreAdmin", "PVEUserAdmin", "PVEPoolAdmin", "PVESDNAdmin"];
const SECOND_FACTORS: [&str; 4] = ["totp", "u2f", "webauthn", "yubico"];

fn re(source: &str) -> Regex {
    Regex::new(source).unwrap()
}

static TASK_DONE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^(ok|running|stopped)$"));
static TASK_WARNINGS: LazyLock<Regex> = LazyLock::new(|| re(r"^WARNINGS: [0-9]+$"));
static HA_DAEMON_TROUBLE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)dead|old timestamp|unable|error"));
static TAG_SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r"[;,\s]+"));
static LINK_LOCAL6: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^fe80:"));
static DISK_KEY: LazyLock<Regex> = LazyLock::new(|| re(r"^(ide|sata|scsi|virtio)[0-9]+$"));
static CDROM: LazyLock<Regex> = LazyLock::new(|| re(r"(^|,)media=cdrom(,|$)"));
static BOOT_ORDER: LazyLock<Regex> = LazyLock::new(|| re(r"(?:^|;|,)order=([^,]+)"));
static SWITCH_ON: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^(1|true|yes|on)$"));
static NET_KEY: LazyLock<Regex> = LazyLock::new(|| re(r"^net[0-9]+$"));
static NIC_FIREWALL: LazyLock<Regex> = LazyLock::new(|| re(r"(^|,)firewall=1(,|$)"));
static CEPH_ABSENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)not initialized|not installed|not configured"));

/* ------------------------------------------------------------------ small JavaScript-like helpers */

/// The API says booleans as 0 and 1, and sometimes as true and false. None stays unknown.
fn flag(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(b) => Some(*b),
        Value::Number(n) if n.as_f64() == Some(1.0) => Some(true),
        Value::Number(n) if n.as_f64() == Some(0.0) => Some(false),
        Value::String(s) if s == "1" => Some(true),
        Value::String(s) if s == "0" => Some(false),
        _ => None,
    }
}

fn round(value: f64, digits: i32) -> f64 {
    let scale = 10f64.powi(digits);
    js_round(value * scale) / scale
}

fn fraction(used: Option<&Value>, total: Option<&Value>) -> Option<f64> {
    match (number(used), number(total)) {
        (Some(u), Some(t)) if t > 0.0 => Some(u / t),
        _ => None,
    }
}

fn percent(value: Option<f64>) -> Value {
    value.map(|v| num(round(v * 100.0, 1))).unwrap_or(Value::Null)
}

fn iso_seconds(seconds: f64) -> Value {
    Value::String(iso_from_millis((seconds * 1000.0) as i64))
}

fn iso_time(epoch: Option<&Value>) -> Value {
    number(epoch).map(iso_seconds).unwrap_or(Value::Null)
}

fn now_seconds() -> f64 {
    (now_millis() as f64 / 1000.0).floor()
}

/// row.key, absent when undefined.
fn field(row: &Row, key: &str) -> Option<Value> {
    row.get(key).cloned()
}

/// value ?? null
fn or_null(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

/// a ?? b
fn nullish<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    match a {
        Some(v) if !v.is_null() => Some(v),
        _ => b,
    }
}

/// String(value ?? fallback)
fn text_or(value: Option<&Value>, fallback: &str) -> String {
    match value {
        None | Some(Value::Null) => fallback.to_string(),
        Some(v) => js_string(v),
    }
}

/// row.key === text
fn is(row: &Row, key: &str, text: &str) -> bool {
    row.get(key).and_then(Value::as_str) == Some(text)
}

fn as_rows(rows: Vec<Row>) -> Value {
    Value::Array(rows.into_iter().map(Value::Object).collect())
}

fn first(rows: &[Value], n: usize) -> Value {
    Value::Array(rows.iter().take(n).cloned().collect())
}

/// The order a comparator of a - b gives.
fn ascending(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

fn path_of(pairs: Args) -> RequestOptions {
    RequestOptions::path(pairs)
}

fn get_opts() -> RequestOptions {
    RequestOptions::default()
}

/// The keys and futures of a gather built in a loop.
fn sources<'a>(keys: &'a [String], futures: Vec<BoxFuture<'a, Result<Value>>>) -> Vec<Source<'a>> {
    keys.iter().map(String::as_str).zip(futures).collect()
}

/* ------------------------------------------------------------------ findings */

const HEALTH_SEVERITIES: [&str; 3] = ["critical", "warning", "info"];
const AUDIT_SEVERITIES: [&str; 4] = ["high", "medium", "low", "info"];

struct Finding {
    severity: &'static str,
    check: String,
    object: String,
    evidence: Value,
    action: String,
}

/// What a report found, what it looked at, and above all what it could not look at.
#[derive(Default)]
struct Report {
    findings: Vec<Finding>,
    checked: BTreeSet<String>,
    unavailable: Map<String, Value>,
}

impl Report {
    fn add(&mut self, severity: &'static str, check: &str, object: impl Into<String>, evidence: Value, action: &str) {
        self.findings.push(Finding { severity, check: check.into(), object: object.into(), evidence, action: action.into() });
    }

    fn add_obj(&mut self, severity: &'static str, check: &str, object: impl Into<String>, evidence: Row, action: &str) {
        self.add(severity, check, object, Value::Object(evidence), action);
    }

    /// Takes in a gather: section/detail keys count their section as looked at when one of them answered.
    fn absorb(&mut self, data: &Args, unavailable: &Args) {
        for key in data.keys() {
            self.checked.insert(key.split('/').next().unwrap_or_default().to_string());
        }
        for (k, v) in unavailable {
            self.unavailable.insert(k.clone(), v.clone());
        }
    }

    fn reason(&mut self, key: impl Into<String>, reason: impl Into<String>) {
        self.unavailable.insert(key.into(), Value::String(reason.into()));
    }

    fn count(&self, severity: &str) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }

    fn summary(&mut self, severities: &[&'static str]) -> Args {
        let order = |s: &str| severities.iter().position(|x| *x == s).unwrap_or(99);
        self.findings.sort_by_key(|f| order(f.severity));
        let unavailable = compact_reasons(&self.unavailable);
        let mut counts = Map::new();
        for s in severities {
            counts.insert(s.to_string(), Value::from(self.count(s)));
        }
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|f| Value::Object(obj! { "severity" => f.severity, "check" => &f.check, "object" => &f.object, "evidence" => &f.evidence, "action" => &f.action }))
            .collect();
        obj! {
            "complete" => unavailable.is_empty(),
            "counts" => counts,
            "findings" => findings,
            "checked" => self.checked.iter().cloned().collect::<Vec<String>>(),
            "unavailable" => unavailable,
        }
    }
}

fn compact_reasons(reasons: &Map<String, Value>) -> Map<String, Value> {
    let mut by_section: IndexMap<&str, Vec<&String>> = IndexMap::new();
    for key in reasons.keys() {
        by_section.entry(key.split('/').next().unwrap_or_default()).or_default().push(key);
    }
    let mut out = Map::new();
    for (section, keys) in by_section {
        for key in keys.iter().take(MAX_REASONS_PER_SECTION) {
            out.insert((*key).clone(), reasons[key.as_str()].clone());
        }
        if keys.len() > MAX_REASONS_PER_SECTION {
            out.insert(format!("{section}/..."), Value::String(format!("{} more with the same section not read.", keys.len() - MAX_REASONS_PER_SECTION)));
        }
    }
    out
}

/* ------------------------------------------------------------------ shared reads */

struct Quorum {
    state: &'static str,
    cluster: Option<String>,
    nodes_total: f64,
    nodes_online: usize,
    offline_nodes: Vec<String>,
}

impl Quorum {
    fn to_json(&self) -> Value {
        Value::Object(obj! {
            "state" => self.state,
            "cluster" => self.cluster.clone(),
            "nodes_total" => num(self.nodes_total),
            "nodes_online" => self.nodes_online,
            "offline_nodes" => self.offline_nodes.clone(),
        })
    }
}

/// A single node that is not in a cluster has no row of type cluster at all. That is not a lost quorum.
fn quorum_of(rows: &[Row]) -> Quorum {
    let cluster = rows.iter().find(|r| is(r, "type", "cluster"));
    let nodes: Vec<&Row> = rows.iter().filter(|r| is(r, "type", "node")).collect();
    let quorate = cluster.and_then(|c| flag(c.get("quorate")));
    Quorum {
        state: match (cluster, quorate) {
            (None, _) => "standalone",
            (_, Some(true)) => "quorate",
            (_, Some(false)) => "no_quorum",
            _ => "unknown",
        },
        cluster: cluster.and_then(|c| nonempty_str(c.get("name"))).map(str::to_string),
        nodes_total: cluster.and_then(|c| number(c.get("nodes"))).unwrap_or(nodes.len() as f64),
        nodes_online: nodes.iter().filter(|n| flag(n.get("online")) == Some(true)).count(),
        offline_nodes: nodes.iter().filter(|n| flag(n.get("online")) == Some(false)).map(|n| js_string_opt(n.get("name"))).collect(),
    }
}

/// Status of a finished task. Anything but these is the error text of a failed one.
fn task_failed(row: &Row) -> bool {
    match nonempty_str(row.get("status")) {
        None => false,
        Some(status) => !TASK_DONE.is_match(status) && !TASK_WARNINGS.is_match(status),
    }
}

fn recent_failed_tasks(rows: &[Row], hours: f64) -> Vec<Value> {
    let since = now_seconds() - hours * 3600.0;
    let mut failed: Vec<&Row> = rows.iter().filter(|r| task_failed(r)).filter(|r| number(r.get("endtime")).or(number(r.get("starttime"))).unwrap_or(since) >= since).collect();
    failed.sort_by(|a, b| ascending(number(b.get("starttime")).unwrap_or(0.0), number(a.get("starttime")).unwrap_or(0.0)));
    failed
        .into_iter()
        .map(|r| {
            Value::Object(obj! {
                "upid" => field(r, "upid"),
                "node" => field(r, "node"),
                "type" => field(r, "type"),
                "id" => field(r, "id"),
                "user" => field(r, "user"),
                "status" => field(r, "status"),
                "started" => iso_time(r.get("starttime")),
                "ended" => iso_time(r.get("endtime")),
            })
        })
        .collect()
}

struct HaState {
    services: usize,
    by_state: Map<String, Value>,
    quorate: Option<bool>,
    problem_services: Vec<Row>,
    problem_daemons: Vec<Row>,
}

impl HaState {
    fn to_json(&self) -> Value {
        Value::Object(obj! {
            "services" => self.services,
            "by_state" => self.by_state.clone(),
            "quorate" => self.quorate,
            "problem_services" => as_rows(self.problem_services.clone()),
            "problem_daemons" => as_rows(self.problem_daemons.clone()),
        })
    }
}

fn ha_of(rows: &[Row]) -> HaState {
    let services: Vec<&Row> = rows.iter().filter(|r| is(r, "type", "service")).collect();
    let state_of = |s: &Row| nonempty_str(s.get("crm_state")).or(nonempty_str(s.get("state"))).map(str::to_string);
    let mut by_state = Map::new();
    for s in &services {
        let state = state_of(s).unwrap_or_else(|| "unknown".into());
        let count = by_state.get(&state).and_then(Value::as_u64).unwrap_or(0);
        by_state.insert(state, Value::from(count + 1));
    }
    let quorum = rows.iter().find(|r| is(r, "type", "quorum"));
    let quorate = quorum.and_then(|q| flag(q.get("quorate")));
    HaState {
        services: services.len(),
        by_state,
        quorate,
        problem_services: services
            .iter()
            .filter(|s| {
                let state = state_of(s).unwrap_or_default();
                matches!(state.as_str(), "error" | "fence" | "recovery" | "freeze")
            })
            .map(|s| {
                obj! {
                    "sid" => field(s, "sid"),
                    "node" => field(s, "node"),
                    "state" => nullish(s.get("crm_state"), s.get("state")).cloned(),
                    "requested" => field(s, "request_state"),
                    "status" => field(s, "status"),
                }
            })
            .collect(),
        problem_daemons: rows
            .iter()
            .filter(|r| (is(r, "type", "lrm") || is(r, "type", "master")) && HA_DAEMON_TROUBLE.is_match(&text_or(r.get("status"), "")))
            .map(|r| obj! { "id" => field(r, "id"), "node" => field(r, "node"), "status" => field(r, "status") })
            .collect(),
    }
}

fn guests_of(rows: Vec<Row>) -> Vec<Row> {
    rows.into_iter().filter(|r| (is(r, "type", "qemu") || is(r, "type", "lxc")) && number(r.get("vmid")).is_some()).collect()
}

fn storages_of(rows: &[Row]) -> Vec<Row> {
    rows.iter().filter(|r| is(r, "type", "storage")).cloned().collect()
}

/// A shared storage comes once per node: one entry, with the nodes that see it.
fn merge_shared(rows: Vec<Row>) -> Vec<(Row, Vec<String>)> {
    let mut merged: IndexMap<String, (Row, Vec<String>)> = IndexMap::new();
    for row in rows {
        let name = js_string_opt(row.get("storage"));
        let node = text_or(row.get("node"), "");
        let key = if flag(row.get("shared")) == Some(true) { name } else { format!("{name}@{node}") };
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, (row, vec![node]));
            }
            Some(entry) => {
                entry.1.push(node);
                // The history of a shared storage has to be read through a node that can see it.
                if is(&entry.0, "status", "unknown") && !is(&row, "status", "unknown") {
                    entry.0 = row;
                }
            }
        }
    }
    merged.into_values().collect()
}

/// Where a guest lives: its vmid, node and type (qemu or lxc).
#[derive(Clone)]
struct Loc {
    vmid: i64,
    node: String,
    kind: &'static str,
}

impl Loc {
    fn of_guest(g: &GuestLocation) -> Loc {
        Loc { vmid: g.vmid, node: g.node.clone(), kind: if g.kind == "lxc" { "lxc" } else { "qemu" } }
    }

    fn path(&self, suffix: &str) -> String {
        format!("/nodes/{{node}}/{}/{{vmid}}{suffix}", self.kind)
    }

    fn params(&self) -> RequestOptions {
        path_of(obj! { "node" => &self.node, "vmid" => self.vmid })
    }
}

fn location_of(row: &Row) -> Loc {
    Loc { vmid: number(row.get("vmid")).unwrap_or(0.0) as i64, node: js_string_opt(row.get("node")), kind: if is(row, "type", "lxc") { "lxc" } else { "qemu" } }
}

/// Node names and which of them can answer, from /nodes and, failing that, from the cluster status.
fn node_names(node_rows: &[Row], status_rows: &[Row]) -> (Vec<String>, Vec<String>) {
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    if !node_rows.is_empty() {
        let online = node_rows.iter().filter(|n| !is(n, "status", "offline")).map(|n| js_string_opt(n.get("node"))).collect();
        let offline = node_rows.iter().filter(|n| is(n, "status", "offline")).map(|n| js_string_opt(n.get("node"))).collect();
        return (sorted(online), sorted(offline));
    }
    let entries: Vec<&Row> = status_rows.iter().filter(|r| is(r, "type", "node")).collect();
    (
        sorted(entries.iter().filter(|n| flag(n.get("online")) != Some(false)).map(|n| js_string_opt(n.get("name"))).collect()),
        sorted(entries.iter().filter(|n| flag(n.get("online")) == Some(false)).map(|n| js_string_opt(n.get("name"))).collect()),
    )
}

fn offline_reasons(report: &mut Report, sections: &[&str], offline: &[String]) {
    for section in sections {
        for node in offline {
            report.reason(format!("{section}/{node}"), "not checked: the node is offline.");
        }
    }
}

/// Addresses from LXC interfaces or from the guest agent, which name the fields differently.
fn addresses_of(value: &Value) -> Vec<String> {
    let rows = match value.get("result") {
        Some(result @ Value::Array(_)) if value.is_object() => rows_of(Some(result)),
        _ => rows_of(Some(value)),
    };
    let mut out: Vec<String> = Vec::new();
    for iface in &rows {
        if is(iface, "name", "lo") {
            continue;
        }
        for key in ["inet", "inet6"] {
            if let Some(text) = nonempty_str(iface.get(key)) {
                out.push(text.split('/').next().unwrap_or_default().to_string());
            }
        }
        for entry in rows_of(iface.get("ip-addresses")) {
            if let Some(text) = nonempty_str(entry.get("ip-address")) {
                out.push(text.to_string());
            }
        }
    }
    let mut seen = HashSet::new();
    out.into_iter().filter(|ip| seen.insert(ip.clone())).filter(|ip| !ip.starts_with("127.") && ip != "::1").collect()
}

/// The address someone would connect to, IPv4 before IPv6. Link-local does not count: it is there before the network is up.
fn primary_address(ips: &[String]) -> Option<String> {
    let link_local = |ip: &str| LINK_LOCAL6.is_match(ip) || ip.starts_with("169.254.");
    ips.iter().find(|ip| ip.contains('.') && !link_local(ip)).or_else(|| ips.iter().find(|ip| !link_local(ip))).cloned()
}

async fn read_addresses(ctx: &ToolContext, guest: &Loc) -> Result<Vec<String>> {
    let path = if guest.kind == "lxc" { guest.path("/interfaces") } else { guest.path("/agent/network-get-interfaces") };
    Ok(addresses_of(&ctx.api.get(&path, guest.params()).await?))
}

/* ------------------------------------------------------------------ overview and search */

fn task_hours() -> Schema {
    z::int().min(1).max(8760).optional().describe(format!("How far back failed tasks count, in hours. Default {}.", number_text(DEFAULT_TASK_HOURS)))
}

fn wait_seconds(text: &str) -> Schema {
    z::int().min(0).max(3600).optional().describe(text)
}

const WAIT_TASK: &str = "How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30).";
const WAIT_EACH_TASK: &str = "How long to wait for each task. Default: PROXMOX_TASK_WAIT_SECONDS (30). Past this the job stops and reports what remains.";

fn overview_tool() -> ToolDef {
    ToolDef::new(
        "pve_overview",
        "Cluster overview",
        "workflows",
        Gate::Read,
        "The state of the cluster in one answer: version, quorum, nodes, guest counts, storage usage, HA and recent failed tasks. Whatever could not be read is named in \"unavailable\". A token only sees what it has audit rights on, so counts may be partial.",
    )
    .also(&["cluster"])
    .idempotent()
    .input(shape!["task_hours" => task_hours()])
    .handler(overview)
}

async fn overview(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let hours = args.f64("task_hours").unwrap_or(DEFAULT_TASK_HOURS);
    let api = &ctx.api;
    let (data, unavailable) = gather(vec![
        ("version", api.get("/version", get_opts())),
        ("quorum", api.get("/cluster/status", get_opts())),
        ("resources", api.get("/cluster/resources", get_opts())),
        ("ha", api.get("/cluster/ha/status/current", get_opts())),
        ("tasks", api.get("/cluster/tasks", get_opts())),
    ])
    .await;
    let resources = rows_of(data.get("resources"));
    let guests = guests_of(resources.clone());
    let count_by = |rows: &[Row], key: &str| {
        let mut out = Map::new();
        for r in rows {
            let k = text_or(r.get(key), "unknown");
            let n = out.get(&k).and_then(Value::as_u64).unwrap_or(0);
            out.insert(k, Value::from(n + 1));
        }
        out
    };
    let has_resources = data.contains_key("resources");
    let failed = data.get("tasks").map(|t| recent_failed_tasks(&rows_of(Some(t)), hours));
    let nodes = has_resources.then(|| {
        Value::Array(
            resources
                .iter()
                .filter(|r| is(r, "type", "node"))
                .map(|n| {
                    Value::Object(obj! {
                        "node" => field(n, "node"),
                        "status" => field(n, "status"),
                        "uptime" => field(n, "uptime"),
                        "cores" => field(n, "maxcpu"),
                        "cpu_percent" => percent(number(n.get("cpu"))),
                        "memory_percent" => percent(fraction(n.get("mem"), n.get("maxmem"))),
                    })
                })
                .collect(),
        )
    });
    let guest_counts = has_resources.then(|| {
        Value::Object(obj! {
            "total" => guests.len(),
            "by_type" => count_by(&guests, "type"),
            "by_status" => count_by(&guests, "status"),
            "templates" => guests.iter().filter(|g| flag(g.get("template")) == Some(true)).count(),
        })
    });
    let storage = has_resources.then(|| {
        Value::Array(
            merge_shared(storages_of(&resources))
                .into_iter()
                .map(|(row, nodes)| {
                    Value::Object(obj! {
                        "storage" => field(&row, "storage"),
                        "type" => field(&row, "plugintype"),
                        "shared" => flag(row.get("shared")) == Some(true),
                        "nodes" => nodes,
                        "status" => field(&row, "status"),
                        "used_bytes" => field(&row, "disk"),
                        "total_bytes" => field(&row, "maxdisk"),
                        "used_percent" => percent(fraction(row.get("disk"), row.get("maxdisk"))),
                    })
                })
                .collect(),
        )
    });
    Ok(Value::Object(obj! {
        "version" => or_null(data.get("version")),
        "quorum" => data.get("quorum").map(|q| quorum_of(&rows_of(Some(q))).to_json()).unwrap_or(Value::Null),
        "nodes" => nodes.unwrap_or(Value::Null),
        "guests" => guest_counts.unwrap_or(Value::Null),
        "storage" => storage.unwrap_or(Value::Null),
        "ha" => data.get("ha").map(|h| ha_of(&rows_of(Some(h))).to_json()).unwrap_or(Value::Null),
        "failed_tasks" => failed.map(|f| Value::Object(obj! { "window_hours" => num(hours), "count" => f.len(), "recent" => first(&f, 10) })).unwrap_or(Value::Null),
        "complete" => unavailable.is_empty(),
        "unavailable" => unavailable,
    }))
}

fn find_guest_tool() -> ToolDef {
    ToolDef::new(
        "pve_find_guest",
        "Find a guest",
        "workflows",
        Gate::Read,
        "Finds VMs and containers by vmid, name, tag, status, node, type or IP address, across the cluster. An IP can only be read from a running LXC or from a running VM with its guest agent: those that could not be checked are listed in ip_not_checked, so no match does not mean the address is free.",
    )
    .also(&["vm", "lxc"])
    .idempotent()
    .input(shape![
        "vmid" => vmid().optional(),
        "name" => z::string().min(1).max(255).optional().describe("Part of the name, in any case."),
        "tag" => z::string().min(1).max(255).optional().describe("A whole tag, in any case."),
        "status" => z::string().min(1).max(32).optional().describe("Such as running or stopped."),
        "node" => node_name().optional().describe("Only guests on this node."),
        "type" => z::enumeration(&["qemu", "lxc"]).optional().describe("qemu for VMs, lxc for containers."),
        "ip" => z::string().min(2).max(64).optional().describe("An IPv4 or IPv6 address, without prefix length."),
        "include_ips" => z::boolean().optional().describe("Also read the addresses of each running guest found. One request per guest. Implied by ip."),
        "page_limit" => page_limit(),
        "page_offset" => page_offset(),
    ])
    .handler(find_guest)
}

/// The key Number(vmid) gives in a JavaScript Map.
fn vmid_key(value: Option<&Value>) -> String {
    number(value).map(number_text).unwrap_or_else(|| "NaN".into())
}

async fn find_guest(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let listed = ctx.api.get("/cluster/resources", RequestOptions::params(obj! { "type" => "vm" })).await?;
    let rows = guests_of(rows_of(Some(&listed)));
    let name = args.str("name").map(str::to_lowercase);
    let tag = args.str("tag").map(str::to_lowercase);
    let wanted_vmid = args.get("vmid").and_then(Value::as_f64);
    let mut found: Vec<Row> = rows
        .into_iter()
        .filter(|r| {
            wanted_vmid.is_none_or(|id| r.get("vmid").and_then(Value::as_f64) == Some(id))
                && name.as_ref().is_none_or(|n| text_or(r.get("name"), "").to_lowercase().contains(n.as_str()))
                && tag.as_ref().is_none_or(|t| TAG_SPLIT.split(&text_or(r.get("tags"), "").to_lowercase()).any(|part| part == t.as_str()))
                && args.str("status").is_none_or(|s| is(r, "status", s))
                && args.str("node").is_none_or(|n| is(r, "node", n))
                && args.str("type").is_none_or(|t| is(r, "type", t))
        })
        .collect();
    let mut addresses: HashMap<String, Vec<String>> = HashMap::new();
    let mut not_checked: Vec<Value> = Vec::new();
    if args.has("ip") || args.flag("include_ips") {
        let mut running: Vec<&Row> = Vec::new();
        for r in &found {
            if is(r, "status", "running") {
                running.push(r);
            } else {
                not_checked.push(Value::Object(obj! {
                    "vmid" => num(number(r.get("vmid")).unwrap_or(f64::NAN)),
                    "reason" => format!("status is {}: addresses can only be read from a running guest.", js_string_opt(r.get("status"))),
                }));
            }
        }
        let keys: Vec<String> = running.iter().map(|r| js_string_opt(r.get("vmid"))).collect();
        let c: &ToolContext = &ctx;
        let futures = running
            .iter()
            .map(|r| {
                let loc = location_of(r);
                async move { read_addresses(c, &loc).await.map(|ips| Value::from(ips)) }.boxed()
            })
            .collect();
        let (data, unavailable) = gather(sources(&keys, futures)).await;
        for (key, value) in data {
            let ips = value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            addresses.insert(js_number_str(&key).map(number_text).unwrap_or_else(|| "NaN".into()), ips);
        }
        // Integer keys of a JavaScript object come out in ascending order.
        let mut failures: Vec<(f64, Value)> = unavailable.into_iter().map(|(k, v)| (js_number_str(&k).unwrap_or(f64::NAN), v)).collect();
        failures.sort_by(|a, b| ascending(a.0, b.0));
        for (id, reason) in failures {
            not_checked.push(Value::Object(obj! { "vmid" => num(id), "reason" => reason }));
        }
    }
    if let Some(ip) = args.str("ip") {
        let ip = ip.to_lowercase();
        found.retain(|r| addresses.get(&vmid_key(r.get("vmid"))).is_some_and(|list| list.iter().any(|a| a.to_lowercase() == ip)));
    }
    let out: Vec<Value> = found
        .iter()
        .map(|r| {
            Value::Object(obj! {
                "vmid" => field(r, "vmid"),
                "name" => field(r, "name"),
                "type" => field(r, "type"),
                "node" => field(r, "node"),
                "status" => field(r, "status"),
                "tags" => truthy_js(r.get("tags")).then(|| or_null(r.get("tags"))),
                "template" => (flag(r.get("template")) == Some(true)).then_some(true),
                "pool" => truthy_js(r.get("pool")).then(|| or_null(r.get("pool"))),
                "lock" => truthy_js(r.get("lock")).then(|| or_null(r.get("lock"))),
                "hastate" => truthy_js(r.get("hastate")).then(|| or_null(r.get("hastate"))),
                "ips" => addresses.get(&vmid_key(r.get("vmid"))).cloned(),
            })
        })
        .collect();
    let (limit, offset) = paging_args(&args);
    let mut result = page_rows(out, limit, offset);
    if !not_checked.is_empty() {
        result.insert("ip_not_checked".into(), first(&not_checked, MAX_LISTED));
        result.insert("ip_not_checked_count".into(), Value::from(not_checked.len()));
    }
    Ok(Value::Object(result))
}

/* ------------------------------------------------------------------ tasks */

fn wait_task_tool() -> ToolDef {
    ToolDef::new(
        "pve_wait_task",
        "Wait for a task",
        "workflows",
        Gate::Read,
        "Waits for a task (UPID) to end and gives its result with the end of its log. A failed task is an error, task_failed. A task that outlasts the wait comes back with still_running: it goes on and is not cancelled.",
    )
    .also(&["tasks"])
    .idempotent()
    .input(shape![
        "upid" => z::string().min(1).max(512).describe("The task id, such as UPID:pve1:00001234:00ABCDEF:65000000:qmstart:100:root@pam:"),
        "wait_seconds" => wait_seconds("How long to wait. Default: PROXMOX_TASK_WAIT_SECONDS (30)."),
    ])
    .handler(|args: Args, ctx: Arc<ToolContext>| async move {
        let upid = args.string("upid").unwrap_or_default();
        // finish() hands back anything that is not a UPID as it is: here that is a mistake.
        parse_upid(&upid)?;
        let outcome = ctx.tasks.finish(Value::String(upid), FinishOptions { wait: None, wait_seconds: args.u64("wait_seconds") }).await?;
        Ok(Value::Object(outcome))
    })
}

/// Not task_log_tail: that one hides a failure behind an empty log, and here the log is the whole point.
async fn read_log_tail(api: &dyn Api, upid: &str, node: &str, lines: usize) -> Result<(Vec<String>, usize, bool)> {
    let mut tail: Vec<String> = Vec::new();
    let mut total = 0usize;
    for _ in 0..MAX_LOG_PAGES {
        let page = api.get("/nodes/{node}/tasks/{upid}/log", path_of(obj! { "node" => node, "upid" => upid }).with_params(obj! { "start" => total, "limit" => LOG_PAGE })).await?;
        let rows = rows_of(Some(&page));
        if rows.is_empty() {
            return Ok((tail, total, true));
        }
        total += rows.len();
        tail.extend(rows.iter().map(|r| text_or(r.get("t"), "")).filter(|t| t != "no content"));
        if tail.len() > lines {
            tail.drain(..tail.len() - lines);
        }
        if rows.len() < LOG_PAGE {
            return Ok((tail, total, true));
        }
    }
    Ok((tail, total, false))
}

fn task_log_tool() -> ToolDef {
    ToolDef::new(
        "pve_get_task_log_tail",
        "End of a task log",
        "workflows",
        Gate::Read,
        "The status of a task and the last lines of its log, without having to page through it. The log is untrusted text.",
    )
    .also(&["tasks"])
    .idempotent()
    .input(shape![
        "upid" => z::string().min(1).max(512).describe("The task id."),
        "lines" => z::int().min(1).max(5000).optional().describe("How many lines, from the end. Default 50."),
    ])
    .handler(|args: Args, ctx: Arc<ToolContext>| async move {
        let upid = args.string("upid").unwrap_or_default();
        let node = parse_upid(&upid)?.node;
        let lines = args.u64("lines").unwrap_or(50) as usize;
        let (status, log) = futures::join!(
            ctx.api.get("/nodes/{node}/tasks/{upid}/status", path_of(obj! { "node" => &node, "upid" => &upid })),
            read_log_tail(&ctx.api, &upid, &node, lines),
        );
        if let (Err(_), Err(e)) = (&status, &log) {
            return Err(e.clone());
        }
        let state = status.as_ref().ok().and_then(Value::as_object);
        let mut unavailable = Map::new();
        if let Err(e) = &status {
            unavailable.insert("status".into(), Value::String(e.reason()));
        }
        if let Err(e) = &log {
            unavailable.insert("log".into(), Value::String(e.reason()));
        }
        let mut out = obj! {
            "upid" => &upid,
            "node" => &node,
            "status" => or_null(state.and_then(|s| nullish(s.get("status"), None))),
            "exitstatus" => or_null(state.and_then(|s| nullish(s.get("exitstatus"), None))),
            "log_tail" => log.as_ref().ok().map(|(l, _, _)| Value::from(l.clone())).unwrap_or(Value::Null),
        };
        if let Ok((_, total, complete)) = &log {
            out.insert("lines_read".into(), Value::from(*total));
            if !complete {
                out.insert("note".into(), Value::String(format!("Read the first {total} lines only: the log is longer, so this is not its end.")));
            }
        }
        if !unavailable.is_empty() {
            out.insert("unavailable".into(), Value::Object(unavailable));
        }
        Ok(Value::Object(out))
    })
}

/* ------------------------------------------------------------------ one guest, whatever its type */

async fn current_status(ctx: &ToolContext, guest: &Loc) -> Result<Option<String>> {
    let value = ctx.api.get(&guest.path("/status/current"), guest.params()).await?;
    Ok(value.as_object().and_then(|v| nonempty_str(v.get("status"))).map(str::to_string))
}

fn power_noop(action: &str) -> Option<&'static str> {
    match action {
        "start" => Some("running"),
        "stop" | "shutdown" => Some("stopped"),
        _ => None,
    }
}

fn guest_power_tool() -> ToolDef {
    ToolDef::new(
        "pve_guest_power",
        "Start or stop a guest",
        "workflows",
        Gate::Write,
        "Starts, shuts down, stops or reboots a VM or a container from its vmid, finds the node and the type, and waits for the task. stop cuts the power at once, as pulling the plug would; shutdown asks the guest to stop cleanly. Destructive except for start. A guest that is already in the requested state is left alone.",
    )
    .also(&["vm", "lxc"])
    .destructive_when(|args| args.str("action") != Some("start"))
    .input(shape![
        "vmid" => vmid(),
        "action" => z::enumeration(&["start", "shutdown", "stop", "reboot"]).describe("What to do."),
        "timeout" => z::int().min(0).optional().describe("For shutdown and reboot: seconds the guest has to comply."),
        "force_stop" => z::boolean().optional().describe("For shutdown: stop the guest hard when it did not comply within the timeout."),
        "wait_seconds" => wait_seconds(WAIT_TASK),
    ])
    .confirmation(|args| format!("{} guest {}? This interrupts whatever runs in it.", js_string_opt(args.get("action")), js_string_opt(args.get("vmid"))))
    .handler(guest_power)
}

async fn guest_power(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let action = args.string("action").unwrap_or_default();
    if action != "shutdown" && args.get("force_stop").is_some() {
        return Err(PveError::new(kind::INVALID_INPUT, "force_stop only applies to shutdown."));
    }
    if action != "shutdown" && action != "reboot" && args.get("timeout").is_some() {
        return Err(PveError::new(kind::INVALID_INPUT, "timeout only applies to shutdown and reboot."));
    }
    let resolved = ctx.nodes.resolve_guest(args.i64("vmid").unwrap_or_default()).await?;
    let guest = Loc::of_guest(&resolved);
    let base = obj! { "vmid" => guest.vmid, "node" => &guest.node, "type" => guest.kind, "action" => &action };
    let (before, before_error) = match current_status(&ctx, &guest).await {
        Ok(s) => (s, None),
        // The action can still be right, and Proxmox will say if it is not.
        Err(e) => (None, Some(e.reason())),
    };
    if let Some(state) = &before {
        if power_noop(&action) == Some(state.as_str()) {
            let mut out = base;
            out.insert("changed".into(), Value::Bool(false));
            out.insert("status".into(), Value::String(state.clone()));
            out.insert("note".into(), Value::String(format!("Guest {} is already {state}: nothing was sent.", guest.vmid)));
            return Ok(Value::Object(out));
        }
    }
    if action == "reboot" && before.as_deref() == Some("stopped") {
        return Err(PveError::new(kind::GUEST_NOT_RUNNING, format!("Guest {} is stopped, so it cannot be rebooted.", guest.vmid)).hint("Use action start."));
    }
    let params = obj! { "timeout" => field(&args, "timeout"), "forceStop" => field(&args, "force_stop") };
    let answer = ctx.api.post(&guest.path(&format!("/status/{action}")), params, guest.params()).await?;
    let outcome = ctx.tasks.finish(answer, FinishOptions { wait: None, wait_seconds: args.u64("wait_seconds") }).await?;
    let mut report = base;
    report.insert("status_before".into(), before.map(Value::String).unwrap_or(Value::Null));
    if let Some(e) = before_error.filter(|e| !e.is_empty()) {
        report.insert("status_before_unavailable".into(), Value::String(e));
    }
    let still_running = truthy_js(outcome.get("still_running"));
    for (k, v) in outcome {
        report.insert(k, v);
    }
    if ctx.dry_run || still_running {
        return Ok(Value::Object(report));
    }
    report.insert("changed".into(), Value::Bool(true));
    match current_status(&ctx, &guest).await {
        Ok(s) => {
            report.insert("status_after".into(), s.map(Value::String).unwrap_or(Value::Null));
        }
        Err(e) => {
            report.insert("status_after".into(), Value::Null);
            report.insert("status_after_unavailable".into(), Value::String(e.reason()));
        }
    }
    Ok(Value::Object(report))
}

fn snapshot_name() -> Schema {
    z::string().regex(r"^[a-zA-Z][a-zA-Z0-9_-]{1,39}$", "Expected a letter, then 1 to 39 letters, digits, - or _").describe("Name of the snapshot.")
}

fn snapshot_tool() -> ToolDef {
    ToolDef::new("pve_snapshot_guest", "Snapshot a guest", "workflows", Gate::Write, "Takes a snapshot of a VM or a container from its vmid and waits for the task. Only VMs can include their memory.")
        .also(&["vm", "lxc"])
        .input(shape![
            "vmid" => vmid(),
            "snapname" => snapshot_name(),
            "description" => z::string().max(8192).optional().describe("A note kept with the snapshot."),
            "vmstate" => z::boolean().optional().describe("VMs only: save the memory too."),
            "wait_seconds" => wait_seconds(WAIT_TASK),
        ])
        .handler(|args: Args, ctx: Arc<ToolContext>| async move {
            let guest = Loc::of_guest(&ctx.nodes.resolve_guest(args.i64("vmid").unwrap_or_default()).await?);
            if guest.kind == "lxc" && args.get("vmstate").is_some() {
                return Err(PveError::new(kind::INVALID_INPUT, format!("Guest {} is a container, and a container snapshot cannot include memory.", guest.vmid)).hint("Leave vmstate out."));
            }
            let params = obj! { "snapname" => field(&args, "snapname"), "description" => field(&args, "description"), "vmstate" => field(&args, "vmstate") };
            let answer = ctx.api.post(&guest.path("/snapshot"), params, guest.params()).await?;
            let outcome = ctx.tasks.finish(answer, FinishOptions { wait: None, wait_seconds: args.u64("wait_seconds") }).await?;
            let mut out = obj! { "vmid" => guest.vmid, "node" => &guest.node, "type" => guest.kind, "snapname" => field(&args, "snapname") };
            out.extend(outcome);
            Ok(Value::Object(out))
        })
}

fn list_snapshots_tool() -> ToolDef {
    ToolDef::new(
        "pve_list_guest_snapshots",
        "List the snapshots of a guest",
        "workflows",
        Gate::Read,
        "The snapshots of a VM or a container from its vmid, oldest first, and which one the guest currently runs from. The \"current\" entry of the API is not a snapshot and is left out of rows.",
    )
    .also(&["vm", "lxc"])
    .idempotent()
    .input(shape!["vmid" => vmid(), "page_limit" => page_limit(), "page_offset" => page_offset()])
    .handler(|args: Args, ctx: Arc<ToolContext>| async move {
        let guest = Loc::of_guest(&ctx.nodes.resolve_guest(args.i64("vmid").unwrap_or_default()).await?);
        let rows = rows_of(Some(&ctx.api.get(&guest.path("/snapshot"), guest.params()).await?));
        let current = rows.iter().find(|r| is(r, "name", "current"));
        let mut snapshots: Vec<Row> = rows.iter().filter(|r| !is(r, "name", "current")).cloned().collect();
        snapshots.sort_by(|a, b| ascending(number(a.get("snaptime")).unwrap_or(0.0), number(b.get("snaptime")).unwrap_or(0.0)));
        let mut out = obj! {
            "vmid" => guest.vmid,
            "node" => &guest.node,
            "type" => guest.kind,
            "current_parent" => or_null(current.and_then(|c| c.get("parent"))),
        };
        let (limit, offset) = paging_args(&args);
        out.extend(page_rows(snapshots.into_iter().map(Value::Object).collect(), limit, offset));
        Ok(Value::Object(out))
    })
}

/* ------------------------------------------------------------------ provisioning */

/// Why a provisioning job stopped before its end.
enum Stop {
    /// A task outlasted the wait.
    StillRunning { task: String, node: String },
    Failed(PveError),
}

impl From<PveError> for Stop {
    fn from(e: PveError) -> Self {
        Stop::Failed(e)
    }
}

type Step<T> = std::result::Result<T, Stop>;

/// Errors that do not tell whether Proxmox went on with the request.
const OUTCOME_UNKNOWN: [&str; 6] = ["task_failed", "task_timeout", "timeout", "unreachable", "bad_response", "node_unreachable"];

/// What a task creates, and how to remove it.
struct Creates {
    what: String,
    row: Row,
    cleanup: String,
}

/// The account of a provisioning job: what ran, what it created, and what is left to do.
struct Provision {
    dry_run: bool,
    tasks: super::TaskHelper,
    tool_name: &'static str,
    secrets: Vec<String>,
    wait_seconds: Option<u64>,
    steps: Vec<Row>,
    created: Vec<Row>,
    warnings: Vec<String>,
    /// How to remove what was created, if it is not wanted: it is never done automatically.
    cleanups: Vec<String>,
    plan: Vec<(String, String)>,
    uncertain: Option<String>,
    failed_step: Option<String>,
}

impl Provision {
    fn new(ctx: &ToolContext, tool_name: &'static str, secrets: &[Option<&str>], wait_seconds: Option<u64>) -> Provision {
        let secrets = secret_list(secrets);
        Provision {
            dry_run: ctx.dry_run,
            tasks: ctx.tasks.clone(),
            tool_name,
            secrets,
            wait_seconds,
            steps: Vec::new(),
            created: Vec::new(),
            warnings: Vec::new(),
            cleanups: Vec::new(),
            plan: Vec::new(),
            uncertain: None,
            failed_step: None,
        }
    }

    /// What this job still has to do, as tool calls an agent can make itself if it stops here.
    fn set_plan(&mut self, plan: Vec<(&str, String)>) {
        self.plan = plan.into_iter().map(|(s, h)| (s.to_string(), h)).collect();
    }

    fn note(&mut self, step: &str, status: &str, fields: Row) {
        let mut row = obj! { "step" => step, "status" => status };
        row.extend(fields);
        self.steps.push(row);
        // Still running counts: remaining must not invite anyone to start it a second time.
        self.plan.retain(|(s, _)| s != step);
    }

    fn warn(&mut self, step: &str, message: String) {
        self.warnings.push(message.clone());
        self.note(step, "warning", obj! { "detail" => message });
    }

    fn fail(&mut self, step: &str, err: &PveError) {
        self.failed_step = Some(step.to_string());
        let details = err.details.as_ref().and_then(Value::as_object);
        let mut row = obj! { "step" => step, "status" => "failed", "error_type" => err.kind, "error" => &err.message };
        if let Some(status) = err.status {
            row.insert("http_status".into(), Value::from(status));
        }
        if let Some(tail) = details.and_then(|d| d.get("log_tail")).filter(|v| v.is_array()) {
            row.insert("log_tail".into(), tail.clone());
        }
        if let Some(fields) = details.and_then(|d| d.get("fields")).filter(|v| v.is_object()) {
            row.insert("field_errors".into(), fields.clone());
        }
        self.steps.push(row);
    }

    /// A read: it really runs in a dry run too, so a dry run can say what it found.
    async fn read<T>(&mut self, step: &str, fields: impl FnOnce(&T) -> Row, run: impl Future<Output = Result<T>>) -> Step<T> {
        match run.await {
            Ok(value) => {
                self.note(step, "done", fields(&value));
                Ok(value)
            }
            Err(e) => {
                self.fail(step, &e);
                Err(Stop::Failed(e))
            }
        }
    }

    /// A write that answers at once.
    async fn write(&mut self, step: &str, fields: Row, run: impl Future<Output = Result<Value>>) -> Step<()> {
        match run.await {
            Ok(_) => {
                let status = if self.dry_run { "would_run" } else { "done" };
                self.note(step, status, fields);
                Ok(())
            }
            Err(e) => {
                self.fail(step, &e);
                Err(Stop::Failed(e))
            }
        }
    }

    /// A write that starts a task, followed to its end. Past the delay the whole job stops, reporting so.
    async fn task(&mut self, step: &str, fields: Row, send: impl Future<Output = Result<Value>>, creates: Option<Creates>) -> Step<()> {
        let sent = match send.await {
            Ok(answer) => self.tasks.finish(answer, FinishOptions { wait: None, wait_seconds: self.wait_seconds }).await,
            Err(e) => Err(e),
        };
        let outcome = match sent {
            Ok(o) => o,
            Err(e) => {
                self.fail(step, &e);
                if let Some(c) = &creates {
                    if OUTCOME_UNKNOWN.contains(&e.kind) {
                        self.uncertain = Some(format!("{} may exist in part: the request was sent and did not end well ({}). Check with pve_find_guest and with the task log.", c.what, e.kind));
                        self.cleanups.push(c.cleanup.clone());
                    }
                }
                return Err(Stop::Failed(e));
            }
        };
        if truthy_js(outcome.get("still_running")) {
            let mut row = fields;
            if let Some(task) = outcome.get("task") {
                row.insert("task".into(), task.clone());
            }
            self.note(step, "still_running", row);
            let task = js_string_opt(outcome.get("task"));
            if let Some(c) = &creates {
                self.uncertain = Some(format!("{} is still being created by task {task}.", c.what));
                self.cleanups.push(c.cleanup.clone());
            }
            return Err(Stop::StillRunning { task, node: js_string_opt(outcome.get("node")) });
        }
        if self.dry_run {
            self.note(step, "would_run", fields);
            return Ok(());
        }
        let warning = nonempty_str(outcome.get("warning")).map(str::to_string);
        if let Some(w) = &warning {
            self.warnings.push(format!("{step}: {w}"));
        }
        let mut row = fields;
        row.extend(obj! { "task" => field(&outcome, "upid"), "exitstatus" => field(&outcome, "exitstatus"), "warning" => warning });
        self.note(step, "done", row);
        if let Some(c) = creates {
            self.created.push(c.row);
            self.cleanups.push(c.cleanup);
        }
        Ok(())
    }

    fn account(&self) -> Row {
        obj! {
            "steps" => as_rows(self.steps.clone()),
            "created" => as_rows(self.created.clone()),
            "remaining" => self.plan.iter().map(|(s, h)| format!("{s}: {h}")).collect::<Vec<String>>(),
            "warnings" => (!self.warnings.is_empty()).then(|| self.warnings.clone()),
            "uncertain" => self.uncertain.clone(),
        }
    }

    fn report(&self, fields: Row) -> Value {
        let status = if self.dry_run {
            "dry_run"
        } else if !self.warnings.is_empty() {
            "complete_with_warnings"
        } else {
            "complete"
        };
        let mut out = obj! { "status" => status };
        out.extend(fields);
        out.extend(self.account());
        self.scrub(Value::Object(out))
    }

    fn still_running(&self, task: String, node: String) -> Value {
        let mut out = obj! {
            "status" => "still_running",
            "task" => task,
            "node" => node,
            "next_step" => "pve_wait_task",
            "note" => "The job stopped waiting here and did not go on: the steps under remaining were not run. Once the task has ended, carry them out one by one.",
        };
        out.extend(self.account());
        self.scrub(Value::Object(out))
    }

    fn failure(&self, err: PveError) -> PveError {
        let at = self.failed_step.as_ref().map(|s| format!(" at step \"{s}\"")).unwrap_or_default();
        let message = format!("{} stopped{at}: {}", self.tool_name, err.message);
        let nothing_left = self.created.is_empty() && self.uncertain.is_none();
        let mut details = obj! { "failed_step" => self.failed_step.clone().map(Value::String).unwrap_or(Value::Null) };
        details.extend(self.account());
        let cleanup = if nothing_left {
            "Nothing was created, so there is nothing to clean up.".to_string()
        } else {
            let how = if self.cleanups.is_empty() { String::new() } else { format!(" What is not wanted can be removed with: {}.", self.cleanups.join("; ")) };
            format!("Nothing was deleted automatically.{how}")
        };
        details.insert("cleanup".into(), Value::String(cleanup));
        let mut out = PveError::new(err.kind, self.scrub_text(&message));
        if let Some(hint) = err.hint.filter(|h| !h.is_empty()) {
            out = out.hint(self.scrub_text(&hint));
        }
        if let Some(status) = err.status {
            out = out.status(status);
        }
        out.details(self.scrub(Value::Object(details)))
    }

    /// The end of the job: a report, a job stopped while a task runs, or the error with the account.
    fn conclude(&self, result: Step<Row>) -> Result<Value> {
        match result {
            Ok(fields) => Ok(self.report(fields)),
            Err(Stop::StillRunning { task, node }) => Ok(self.still_running(task, node)),
            Err(Stop::Failed(e)) => Err(self.failure(e)),
        }
    }

    fn scrub_text(&self, text: &str) -> String {
        scrub_text(&self.secrets, text)
    }

    fn scrub(&self, value: Value) -> Value {
        scrub_value(&self.secrets, value)
    }
}

/// The secrets given, and how they look once encoded in a form, which is how Proxmox may quote them back.
fn secret_list(secrets: &[Option<&str>]) -> Vec<String> {
    let kept: Vec<String> = secrets.iter().flatten().filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
    let encoded: Vec<String> = kept.iter().map(|s| encode_uri_component(s)).filter(|e| !kept.contains(e)).collect();
    kept.into_iter().chain(encoded).collect()
}

fn scrub_text(secrets: &[String], text: &str) -> String {
    secrets.iter().fold(text.to_string(), |t, secret| t.replace(secret.as_str(), "[REDACTED]"))
}

/// Proxmox can quote a refused value in its error: a password given as input must not come back that way.
fn scrub_value(secrets: &[String], value: Value) -> Value {
    if secrets.is_empty() {
        return value;
    }
    match value {
        Value::String(s) => Value::String(scrub_text(secrets, &s)),
        Value::Array(items) => Value::Array(items.into_iter().map(|v| scrub_value(secrets, v)).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, scrub_value(secrets, v))).collect()),
        other => other,
    }
}

fn assert_public_keys(value: Option<&str>) -> Result<()> {
    if value.is_some_and(|v| v.contains("PRIVATE KEY")) {
        return Err(PveError::new(kind::INVALID_INPUT, "The SSH keys given hold a private key. Only public keys go here: nothing was sent."));
    }
    Ok(())
}

/// Given: Proxmox itself says whether it is free. Not given: Proxmox picks.
async fn choose_vmid(run: &mut Provision, ctx: &ToolContext, given: Option<i64>) -> Step<i64> {
    if let Some(id) = given {
        run.read("check_vmid", |_: &Value| obj! { "vmid" => id }, ctx.api.get("/cluster/nextid", RequestOptions::params(obj! { "vmid" => id }))).await?;
        return Ok(id);
    }
    run.read("pick_vmid", |id: &i64| obj! { "vmid" => *id }, async {
        let value = ctx.api.get("/cluster/nextid", get_opts()).await?;
        number(Some(&value)).map(|n| n as i64).ok_or_else(|| PveError::new(kind::BAD_RESPONSE, "/cluster/nextid did not answer with a vmid."))
    })
    .await
}

/// Polls until there is an answer or the time is up. Only trouble that can pass is tried again.
async fn poll<T, F, Fut>(seconds: f64, mut attempt: F, transient: fn(&PveError) -> bool) -> (Option<T>, Option<String>)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + Duration::from_secs_f64(seconds.max(0.0));
    let mut wait = 500u64;
    let mut last_error: Option<String>;
    loop {
        match attempt().await {
            Ok(Some(value)) => return (Some(value), None),
            Ok(None) => last_error = None,
            Err(e) => {
                if !transient(&e) {
                    return (None, Some(e.reason()));
                }
                last_error = Some(e.reason());
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (None, last_error);
        }
        tokio::time::sleep(left.min(Duration::from_millis(wait))).await;
        wait = (wait * 2).min(5000);
    }
}

fn is_transient_guest_error(err: &PveError) -> bool {
    matches!(err.kind, kind::UPSTREAM_ERROR | kind::TIMEOUT | kind::GUEST_LOCKED)
}

fn template_basename(volid: &str) -> &str {
    volid.rfind('/').map(|i| &volid[i + 1..]).unwrap_or(volid)
}

fn match_template(names: &[String], wanted: &str) -> Vec<String> {
    let exact: Vec<String> = names.iter().filter(|n| *n == wanted).cloned().collect();
    if !exact.is_empty() { exact } else { names.iter().filter(|n| n.starts_with(wanted)).cloned().collect() }
}

/// Finds the template on a storage of the node, else downloads it from the appliance index.
async fn resolve_lxc_template(run: &mut Provision, ctx: &ToolContext, node: &str, args: &Args) -> Step<String> {
    let path = || path_of(obj! { "node" => node });
    let wanted = args.string("template").unwrap_or_default();
    let storage_of: Option<String> = wanted.find(':').map(|i| wanted[..i].to_string()).filter(|s| !s.is_empty());

    // A volume names its storage: being refused the list of storages should not stop that case.
    let all_storages: Vec<Row> = if storage_of.is_some() {
        Vec::new()
    } else {
        run.read(
            "list_template_storages",
            |rows: &Vec<Row>| obj! { "storages" => Value::Array(rows.iter().map(|r| or_null(r.get("storage"))).collect()) },
            async {
                let value = ctx.api.get("/nodes/{node}/storage", path().with_params(obj! { "content" => "vztmpl" })).await?;
                Ok(rows_of(Some(&value))
                    .into_iter()
                    .filter(|r| flag(r.get("enabled")) != Some(false) && (r.get("content").is_none() || js_string_opt(r.get("content")).split(',').any(|c| c == "vztmpl")))
                    .collect())
            },
        )
        .await?
    };
    let names: Vec<String> = match (&storage_of, args.str("template_storage").filter(|s| !s.is_empty())) {
        (Some(s), _) => vec![s.clone()],
        (None, Some(s)) => vec![s.to_string()],
        (None, None) => all_storages.iter().map(|r| js_string_opt(r.get("storage"))).collect(),
    };
    let futures = names
        .iter()
        .map(|storage| {
            async move {
                let value = ctx.api.get("/nodes/{node}/storage/{storage}/content", path_of(obj! { "node" => node, "storage" => storage }).with_params(obj! { "content" => "vztmpl" })).await?;
                Ok(as_rows(rows_of(Some(&value))))
            }
            .boxed()
        })
        .collect();
    let (data, unavailable) = gather(sources(&names, futures)).await;
    let unread: Vec<(String, String)> = unavailable.iter().map(|(k, v)| (k.clone(), js_string(v))).collect();
    for (storage, reason) in &unread {
        run.warn("read_template_storage", format!("Could not list templates on storage {storage}: {reason}"));
    }

    if let Some(storage) = &storage_of {
        let rows = rows_of(data.get(storage));
        if rows.iter().any(|r| is(r, "volid", &wanted)) {
            run.note("find_template", "done", obj! { "ostemplate" => &wanted, "source" => "storage" });
            return Ok(wanted);
        }
        // Proxmox has the last word when the storage could not be listed.
        if !unread.is_empty() {
            run.warn("find_template", format!("Template {wanted} could not be verified before use."));
            return Ok(wanted);
        }
        return Err(PveError::new(kind::INVALID_INPUT, format!("Template {wanted} is not on storage {storage} of node {node}."))
            .hint("pve_list_storage_content lists what is there. Give a template name without storage to have it looked up and downloaded.")
            .into());
    }

    let local: Vec<String> = data.values().flat_map(|rows| rows_of(Some(rows)).into_iter().map(|r| text_or(r.get("volid"), "")).filter(|v| !v.is_empty()).collect::<Vec<_>>()).collect();
    let basenames: Vec<String> = local.iter().map(|v| template_basename(v).to_string()).collect();
    let matched = match_template(&basenames, &wanted);
    let local_hits: Vec<String> = local.iter().filter(|v| matched.iter().any(|m| m == template_basename(v))).cloned().collect();
    if local_hits.len() > 1 {
        return Err(PveError::new(kind::INVALID_INPUT, format!("\"{wanted}\" matches several templates on this node: {}.", local_hits.join(", ")))
            .hint("Give the full volume id.")
            .details(Value::Object(obj! { "candidates" => local_hits }))
            .into());
    }
    if let [hit] = local_hits.as_slice() {
        run.note("find_template", "done", obj! { "ostemplate" => hit, "source" => "storage" });
        return Ok(hit.clone());
    }

    let index = run
        .read("read_appliance_index", |rows: &Vec<Row>| obj! { "available" => rows.len() }, async {
            let value = ctx.api.get("/nodes/{node}/aplinfo", path()).await?;
            Ok(rows_of(Some(&value)))
        })
        .await?;
    let offered: Vec<String> = index.iter().map(|r| text_or(r.get("template"), "")).filter(|t| !t.is_empty()).collect();
    let hits = match_template(&offered, &wanted);
    if hits.is_empty() {
        return Err(PveError::new(kind::INVALID_INPUT, format!("No template \"{wanted}\" on the storages of node {node} nor in the appliance index."))
            .hint("pve_list_appliance_templates lists what can be downloaded.")
            .details(Value::Object(obj! { "offered" => offered.iter().take(MAX_LISTED).cloned().collect::<Vec<String>>() }))
            .into());
    }
    if hits.len() > 1 {
        return Err(PveError::new(kind::INVALID_INPUT, format!("\"{wanted}\" matches several templates in the appliance index: {}.", hits.iter().take(20).cloned().collect::<Vec<_>>().join(", ")))
            .hint("Give the full name of one of them.")
            .details(Value::Object(obj! { "candidates" => hits.iter().take(MAX_LISTED).cloned().collect::<Vec<String>>() }))
            .into());
    }
    let hit = hits[0].clone();
    if args.bool("download_template") == Some(false) {
        return Err(PveError::new(kind::INVALID_INPUT, format!("Template {hit} is not on this node, and download_template is false.")).into());
    }
    let storage = args.string("template_storage").or_else(|| all_storages.first().and_then(|r| nonempty_str(r.get("storage"))).map(str::to_string)).filter(|s| !s.is_empty());
    let Some(storage) = storage else {
        return Err(PveError::new(kind::INVALID_INPUT, format!("No storage on node {node} accepts container templates.")).hint("Give template_storage, or have the operator enable vztmpl content on a storage.").into());
    };
    let volid = format!("{storage}:vztmpl/{hit}");
    run.task(
        "download_template",
        obj! { "template" => &hit, "storage" => &storage },
        ctx.api.post("/nodes/{node}/aplinfo", obj! { "storage" => &storage, "template" => &hit }, path()),
        Some(Creates { what: format!("Template {volid}"), row: obj! { "type" => "template", "volid" => &volid, "node" => node }, cleanup: format!("pve_delete_storage_volume with storage {storage} and volume {volid}") }),
    )
    .await?;
    Ok(volid)
}

fn host_name() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", "Expected a host name").max(255)
}

fn provision_lxc_tool() -> ToolDef {
    ToolDef::new(
        "pve_provision_lxc",
        "Provision a container",
        "workflows",
        Gate::Write,
        "Creates a container from start to finish: free vmid, template found on a storage or downloaded from the appliance index, creation, start, IP address. Each step is reported. If one fails, the error says what was created and what remains: nothing is ever deleted automatically. It never replaces an existing guest. The password is never returned.",
    )
    .also(&["lxc"])
    .input(shape![
        "hostname" => host_name().describe("Host name of the container."),
        "template" => z::string().min(1).max(512).describe("A volume such as local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst, or a name or start of name such as debian-12-standard, looked up on the storages of the node and then in the appliance index."),
        "node" => node_name().optional().describe("The node. Optional when there is a default node or only one node."),
        "vmid" => vmid().optional().describe("The id to use. Default: the next free one."),
        "storage" => z::string().min(1).max(128).optional().describe("Storage of the root disk."),
        "disk_gb" => z::int().min(1).max(131072).optional().describe("Size of the root disk in GiB. Needs storage."),
        "template_storage" => z::string().min(1).max(128).optional().describe("Storage to look for the template on and to download it to. Default: the storages of the node that accept templates."),
        "download_template" => z::boolean().optional().describe("Download the template when it is not on the node. Default true."),
        "net0" => z::string().min(1).max(512).optional().describe(format!("First network interface, as a Proxmox property string. Default: {DEFAULT_LXC_NET}.")),
        "ssh_public_keys" => z::string().max(65536).optional().describe("Public SSH keys for root, one per line."),
        "password" => z::string().min(5).max(512).optional().describe("Root password of the container. Never returned nor logged."),
        "cores" => z::int().min(1).max(8192).optional().describe("CPU cores."),
        "memory" => z::int().min(16).optional().describe("Memory in MiB."),
        "swap" => z::int().min(0).optional().describe("Swap in MiB."),
        "unprivileged" => z::boolean().optional().describe("Run as an unprivileged container. Default true, which is safer than the Proxmox default."),
        "features" => z::string().max(512).optional().describe("Features as a property string, such as nesting=1."),
        "nameserver" => z::string().max(512).optional().describe("DNS servers."),
        "searchdomain" => z::string().max(512).optional().describe("DNS search domain."),
        "tags" => z::string().max(512).optional().describe("Tags, separated by semicolons."),
        "pool" => z::string().max(128).optional().describe("Resource pool."),
        "onboot" => z::boolean().optional().describe("Start with the node."),
        "description" => z::string().max(8192).optional().describe("Notes."),
        "start" => z::boolean().optional().describe("Start it at the end. Default true."),
        "ip_wait_seconds" => z::int().min(0).max(600).optional().describe(format!("How long to wait for an IP address after the start. Default {}.", number_text(DEFAULT_IP_WAIT_SECONDS))),
        "wait_seconds" => wait_seconds(WAIT_EACH_TASK),
    ])
    .handler(|args: Args, ctx: Arc<ToolContext>| async move {
        let mut run = Provision::new(&ctx, "pve_provision_lxc", &[args.str("password")], args.u64("wait_seconds"));
        let result = provision_lxc(&mut run, &ctx, &args).await;
        run.conclude(result)
    })
}

async fn provision_lxc(run: &mut Provision, ctx: &ToolContext, args: &Args) -> Step<Row> {
    assert_public_keys(args.str("ssh_public_keys"))?;
    if args.get("disk_gb").is_some() && args.get("storage").is_none() {
        return Err(PveError::new(kind::INVALID_INPUT, "disk_gb needs storage: the root disk has to go somewhere.").into());
    }
    let node = match args.string("node") {
        Some(n) => n,
        None => run.read("resolve_node", |n: &String| obj! { "node" => n }, ctx.nodes.default_node()).await?,
    };
    let id = choose_vmid(run, ctx, args.i64("vmid")).await?;
    let place = || path_of(obj! { "node" => &node, "vmid" => id });
    let start = args.bool("start") != Some(false);
    let mut plan = vec![("create", format!("pve_create_lxc with vmid {id} and the wanted values"))];
    if start {
        plan.push(("start", format!("pve_start_lxc with vmid {id}")));
    }
    run.set_plan(plan);
    let ostemplate = resolve_lxc_template(run, ctx, &node, args).await?;
    let storage = args.get("storage").cloned();
    let disk = match (args.get("disk_gb"), &storage) {
        (Some(gb), _) => obj! { "rootfs" => format!("{}:{}", js_string_opt(storage.as_ref()), js_string(gb)) },
        (None, Some(s)) => obj! { "storage" => s },
        (None, None) => Map::new(),
    };
    let mut params = obj! {
        "vmid" => id,
        "ostemplate" => &ostemplate,
        "hostname" => field(args, "hostname"),
        "unprivileged" => args.get("unprivileged").cloned().unwrap_or(Value::Bool(true)),
        "net0" => args.get("net0").cloned().unwrap_or_else(|| Value::from(DEFAULT_LXC_NET)),
    };
    params.extend(disk);
    params.extend(obj! {
        "ssh-public-keys" => field(args, "ssh_public_keys"),
        "password" => field(args, "password"),
        "cores" => field(args, "cores"),
        "memory" => field(args, "memory"),
        "swap" => field(args, "swap"),
        "features" => field(args, "features"),
        "nameserver" => field(args, "nameserver"),
        "searchdomain" => field(args, "searchdomain"),
        "tags" => field(args, "tags"),
        "pool" => field(args, "pool"),
        "onboot" => field(args, "onboot"),
        "description" => field(args, "description"),
    });
    run.task(
        "create",
        obj! { "vmid" => id, "ostemplate" => &ostemplate },
        ctx.api.post("/nodes/{node}/lxc", params, path_of(obj! { "node" => &node })),
        Some(Creates { what: format!("Container {id} on {node}"), row: obj! { "type" => "lxc", "vmid" => id, "node" => &node }, cleanup: format!("pve_delete_lxc with vmid {id}") }),
    )
    .await?;

    let common = obj! { "vmid" => id, "node" => &node, "hostname" => field(args, "hostname"), "ostemplate" => &ostemplate };
    let with = |extra: Row| {
        let mut out = common.clone();
        out.extend(extra);
        out
    };
    if !start {
        run.note("start", "skipped", obj! { "detail" => "start is false." });
        return Ok(with(obj! { "running" => false, "ip" => Value::Null }));
    }
    run.task("start", obj! { "vmid" => id }, ctx.api.request("POST", "/nodes/{node}/lxc/{vmid}/status/start", place()), None).await?;
    if ctx.dry_run {
        run.note("find_ip", "would_run", obj! { "detail" => "The address can only be read once the container runs." });
        return Ok(with(obj! { "running" => false, "ip" => Value::Null }));
    }
    let guest = Loc { vmid: id, node: node.clone(), kind: "lxc" };
    let guest = &guest;
    let (value, last_error) = poll(
        args.f64("ip_wait_seconds").unwrap_or(DEFAULT_IP_WAIT_SECONDS),
        move || async move {
            let ips = read_addresses(ctx, guest).await?;
            Ok(primary_address(&ips).map(|_| ips))
        },
        is_transient_guest_error,
    )
    .await;
    if let Some(ips) = value {
        run.note("find_ip", "done", obj! { "ips" => ips.clone() });
        return Ok(with(obj! { "running" => true, "ip" => primary_address(&ips), "ips" => ips }));
    }
    let why = last_error.map(|e| format!(" ({e})")).unwrap_or_default();
    run.warn("find_ip", format!("No IP address seen on container {id} in the time given{why}. It may still be getting one: see pve_list_lxc_interfaces."));
    Ok(with(obj! { "running" => true, "ip" => Value::Null }))
}

fn is_disk(config: &Row, name: &str) -> bool {
    DISK_KEY.is_match(name) && config.get(name).and_then(Value::as_str).is_some_and(|v| !CDROM.is_match(v))
}

/// The first disk of the boot order, else the old bootdisk key, else nothing.
fn boot_disk(config: &Row) -> Option<String> {
    let boot = text_or(config.get("boot"), "");
    let order = BOOT_ORDER.captures(&boot).map(|c| c[1].to_string());
    if let Some(found) = order.as_deref().and_then(|o| o.split(';').find(|d| is_disk(config, d))) {
        return Some(found.to_string());
    }
    nonempty_str(config.get("bootdisk")).filter(|d| is_disk(config, d)).map(str::to_string)
}

fn agent_enabled(config: &Row) -> bool {
    // A property string: the switch comes either as a bare first value or as enabled=, in any place.
    let agent = text_or(config.get("agent"), "0");
    let parts: Vec<&str> = agent.split(',').collect();
    SWITCH_ON.is_match(parts[0]) || parts.iter().any(|p| p.strip_prefix("enabled=").is_some_and(|v| SWITCH_ON.is_match(v)))
}

fn has_cloud_init_drive(config: &Row) -> bool {
    config.iter().any(|(k, v)| DISK_KEY.is_match(k) && v.as_str().is_some_and(|s| s.contains("cloudinit")))
}

fn provision_vm_tool() -> ToolDef {
    ToolDef::new(
        "pve_provision_vm_from_template",
        "Provision a VM from a template",
        "workflows",
        Gate::Write,
        "Makes a VM from a VM template from start to finish: clone, cloud-init (ciuser, cipassword, sshkeys, ipconfig0), disk resize, start, wait for the guest agent. Each step is reported. If one fails, the error says what was created and what remains: nothing is ever deleted automatically. It never replaces an existing guest. The password is never returned.",
    )
    .also(&["vm"])
    .input(shape![
        "template_vmid" => vmid().describe("The vmid of the VM template to clone."),
        "newid" => vmid().optional().describe("The id of the new VM. Default: the next free one."),
        "name" => host_name().describe("Name of the new VM."),
        "target_node" => node_name().optional().describe("Node of the new VM. Default: the template's. A different node needs storage the target can reach."),
        "full" => z::boolean().optional().describe("Full copy rather than linked clone. Implied by storage."),
        "storage" => z::string().min(1).max(128).optional().describe("Storage for a full clone."),
        "pool" => z::string().max(128).optional().describe("Resource pool."),
        "description" => z::string().max(8192).optional().describe("Notes."),
        "ciuser" => z::string().max(128).optional().describe("Cloud-init user."),
        "cipassword" => z::string().min(5).max(512).optional().describe("Cloud-init password. Never returned nor logged."),
        "sshkeys" => z::string().max(65536).optional().describe("Public SSH keys for cloud-init, one per line, in plain text."),
        "ipconfig0" => z::string().max(512).optional().describe("Cloud-init address of the first interface, such as ip=dhcp or ip=10.0.0.5/24,gw=10.0.0.1."),
        "nameserver" => z::string().max(512).optional().describe("Cloud-init DNS servers."),
        "searchdomain" => z::string().max(512).optional().describe("Cloud-init search domain."),
        "cores" => z::int().min(1).max(8192).optional().describe("CPU cores."),
        "memory" => z::int().min(16).optional().describe("Memory in MiB."),
        "tags" => z::string().max(512).optional().describe("Tags, separated by semicolons."),
        "onboot" => z::boolean().optional().describe("Start with the node."),
        "enable_agent" => z::boolean().optional().describe("Set agent=1 on the new VM. The guest system still has to run qemu-guest-agent."),
        "disk" => z::string().regex(r"^(ide|sata|scsi|virtio)\d+$", "Expected a disk such as scsi0").optional().describe("Disk to resize. Default: the first disk of the boot order."),
        "disk_size" => z::string().regex(r"^\+?\d+(\.\d+)?[KMGT]?$", "Expected a size such as 40G or +10G").optional().describe("New size such as 40G, or growth such as +10G. Disks cannot shrink."),
        "start" => z::boolean().optional().describe("Start it at the end. Default true."),
        "agent_wait_seconds" => z::int().min(0).max(1800).optional().describe(format!("How long to wait for the guest agent after the start. Default {}. 0 does not wait.", number_text(DEFAULT_AGENT_WAIT_SECONDS))),
        "wait_seconds" => wait_seconds(WAIT_EACH_TASK),
    ])
    .handler(|args: Args, ctx: Arc<ToolContext>| async move {
        let mut run = Provision::new(&ctx, "pve_provision_vm_from_template", &[args.str("cipassword")], args.u64("wait_seconds"));
        let result = provision_vm(&mut run, &ctx, &args).await;
        run.conclude(result)
    })
}

async fn provision_vm(run: &mut Provision, ctx: &ToolContext, args: &Args) -> Step<Row> {
    assert_public_keys(args.str("sshkeys"))?;
    let template_vmid = args.i64("template_vmid").unwrap_or_default();
    let source = run
        .read("find_template", |g: &GuestLocation| obj! { "vmid" => g.vmid, "node" => &g.node, "name" => g.name.clone() }, async {
            let guest = ctx.nodes.resolve_guest(template_vmid).await?;
            if guest.kind != "qemu" {
                return Err(PveError::new(kind::INVALID_INPUT, format!("Guest {} is a container.", guest.vmid)).hint("pve_provision_lxc or pve_clone_lxc are the tools for containers."));
            }
            if !guest.template {
                return Err(PveError::new(kind::INVALID_INPUT, format!("VM {} is not a template.", guest.vmid)).hint("pve_clone_vm clones any VM. pve_convert_vm_to_template makes a template, irreversibly."));
            }
            Ok(guest)
        })
        .await?;
    let source_loc = Loc::of_guest(&source);
    let config: Row = run
        .read("read_template_config", |_: &Row| obj! { "vmid" => source.vmid }, async {
            let value = ctx.api.get("/nodes/{node}/qemu/{vmid}/config", source_loc.params()).await?;
            Ok(value.as_object().cloned().unwrap_or_default())
        })
        .await?;
    let disk_size = args.string("disk_size");
    let resize_disk = args.string("disk").or_else(|| if disk_size.is_some() { boot_disk(&config) } else { None });
    if disk_size.is_some() && resize_disk.as_deref().is_none_or(str::is_empty) {
        return Err(PveError::new(kind::INVALID_INPUT, format!("Could not tell which disk of template {} to resize.", source.vmid)).hint("Give disk, such as scsi0.").into());
    }

    let id = choose_vmid(run, ctx, args.i64("newid")).await?;
    let node = args.string("target_node").unwrap_or_else(|| source.node.clone());
    let place = || path_of(obj! { "node" => &node, "vmid" => id });
    let settings = obj! {
        "ciuser" => field(args, "ciuser"),
        "cipassword" => field(args, "cipassword"),
        "sshkeys" => field(args, "sshkeys"),
        "ipconfig0" => field(args, "ipconfig0"),
        "nameserver" => field(args, "nameserver"),
        "searchdomain" => field(args, "searchdomain"),
        "cores" => field(args, "cores"),
        "memory" => field(args, "memory"),
        "tags" => field(args, "tags"),
        "onboot" => field(args, "onboot"),
        "agent" => args.bool("enable_agent").map(|on| if on { "1" } else { "0" }),
    };
    let configure = !settings.is_empty();
    let start = args.bool("start") != Some(false);
    let resize_name = resize_disk.clone().unwrap_or_else(|| "undefined".into());
    let mut plan = vec![("clone", format!("pve_clone_vm with vmid {} and newid {id}", source.vmid))];
    if configure {
        plan.push(("configure", format!("pve_update_vm_config with vmid {id} and the wanted values")));
    }
    if let Some(size) = &disk_size {
        plan.push(("resize", format!("pve_resize_vm_disk with vmid {id}, disk {resize_name} and size {size}")));
    }
    if start {
        plan.push(("start", format!("pve_start_vm with vmid {id}")));
    }
    run.set_plan(plan);

    let full = args.bool("full").or_else(|| args.get("storage").is_some().then_some(true));
    let clone_params = obj! {
        "newid" => id,
        "name" => field(args, "name"),
        "full" => full,
        "storage" => field(args, "storage"),
        "target" => field(args, "target_node"),
        "pool" => field(args, "pool"),
        "description" => field(args, "description"),
    };
    run.task(
        "clone",
        obj! { "source" => source.vmid, "newid" => id },
        ctx.api.post("/nodes/{node}/qemu/{vmid}/clone", clone_params, source_loc.params()),
        Some(Creates { what: format!("VM {id} on {node}"), row: obj! { "type" => "qemu", "vmid" => id, "node" => &node }, cleanup: format!("pve_delete_vm with vmid {id}") }),
    )
    .await?;

    let cloud_init = ["ciuser", "cipassword", "sshkeys", "ipconfig0", "nameserver", "searchdomain"].iter().any(|k| settings.contains_key(*k));
    if cloud_init && !has_cloud_init_drive(&config) {
        run.warnings.push(format!("Template {} has no cloud-init drive: the cloud-init values are stored, but the guest will not receive them until one is added.", source.vmid));
    }
    if configure {
        let keys: Vec<String> = settings.keys().cloned().collect();
        run.write("configure", obj! { "keys" => keys }, ctx.api.put("/nodes/{node}/qemu/{vmid}/config", settings.clone(), place())).await?;
    } else {
        run.note("configure", "skipped", obj! { "detail" => "No value to set." });
    }
    if let Some(size) = &disk_size {
        run.task(
            "resize",
            obj! { "disk" => resize_disk.clone(), "size" => size },
            ctx.api.put("/nodes/{node}/qemu/{vmid}/resize", obj! { "disk" => resize_disk.clone(), "size" => size }, place()),
            None,
        )
        .await?;
    } else {
        run.note("resize", "skipped", obj! { "detail" => "No disk_size given." });
    }

    let common = obj! { "vmid" => id, "node" => &node, "name" => field(args, "name"), "template" => source.vmid };
    let with = |extra: Row| {
        let mut out = common.clone();
        out.extend(extra);
        out
    };
    if !start {
        run.note("start", "skipped", obj! { "detail" => "start is false." });
        return Ok(with(obj! { "running" => false, "ip" => Value::Null }));
    }
    run.task("start", obj! { "vmid" => id }, ctx.api.request("POST", "/nodes/{node}/qemu/{vmid}/status/start", place()), None).await?;

    let agent_on = args.bool("enable_agent").unwrap_or_else(|| agent_enabled(&config));
    let agent_seconds = args.f64("agent_wait_seconds").unwrap_or(DEFAULT_AGENT_WAIT_SECONDS);
    if ctx.dry_run {
        run.note("wait_agent", if agent_on && agent_seconds > 0.0 { "would_run" } else { "skipped" }, Map::new());
        return Ok(with(obj! { "running" => false, "ip" => Value::Null }));
    }
    if !agent_on || agent_seconds == 0.0 {
        let detail = if agent_on {
            "agent_wait_seconds is 0."
        } else {
            "The guest agent is not enabled on this VM: there is nothing to wait for, and no way to read its address here. enable_agent turns it on."
        };
        run.note("wait_agent", "skipped", obj! { "detail" => detail });
        return Ok(with(obj! { "running" => true, "ip" => Value::Null }));
    }
    let guest = Loc { vmid: id, node: node.clone(), kind: "qemu" };
    let guest = &guest;
    let (value, last_error) = poll(
        agent_seconds,
        move || async move {
            ctx.api.request("POST", "/nodes/{node}/qemu/{vmid}/agent/ping", guest.params()).await?;
            let ips = read_addresses(ctx, guest).await?;
            Ok(primary_address(&ips).map(|_| ips))
        },
        is_transient_guest_error,
    )
    .await;
    if let Some(ips) = value {
        run.note("wait_agent", "done", obj! { "ips" => ips.clone() });
        return Ok(with(obj! { "running" => true, "ip" => primary_address(&ips), "ips" => ips }));
    }
    let why = last_error.map(|e| format!(" ({e})")).unwrap_or_default();
    run.warn("wait_agent", format!("The guest agent of VM {id} gave no address in the time given{why}. The guest system may still be booting, or may not run qemu-guest-agent: see pve_ping_vm_agent."));
    Ok(with(obj! { "running" => true, "ip" => Value::Null }))
}

/* ------------------------------------------------------------------ health */

fn check_ceph(report: &mut Report, data: &Args, unavailable: &Args) -> Map<String, Value> {
    let mut not_applicable = Map::new();
    if let Some(reason) = unavailable.get("ceph") {
        // What Proxmox answers where Ceph was never set up. It is not a failure to read.
        if CEPH_ABSENT.is_match(&js_string(reason)) {
            not_applicable.insert("ceph".into(), reason.clone());
        } else {
            report.unavailable.insert("ceph".into(), reason.clone());
        }
        return not_applicable;
    }
    let health = data.get("ceph").and_then(Value::as_object).and_then(|s| s.get("health")).and_then(Value::as_object);
    let Some(value) = health.and_then(|h| nonempty_str(h.get("status"))) else {
        report.reason("ceph", "The answer holds no health status.");
        return not_applicable;
    };
    report.checked.insert("ceph".into());
    if value == "HEALTH_OK" {
        return not_applicable;
    }
    let checks: Vec<String> = health.and_then(|h| h.get("checks")).and_then(Value::as_object).map(|c| c.keys().cloned().collect()).unwrap_or_default();
    let severity = if value == "HEALTH_ERR" { "critical" } else { "warning" };
    report.add_obj(severity, "ceph", "ceph", obj! { "status" => value, "checks" => checks }, "See pve_get_cluster_ceph_status for the detail of each check.");
    not_applicable
}

fn check_node_storage(report: &mut Report, per_node: &[(String, Vec<Row>)], warn: f64, critical: f64) {
    let mut rows: Vec<Row> = Vec::new();
    for (node, list) in per_node {
        for row in list {
            let mut row = row.clone();
            row.insert("node".into(), Value::String(node.clone()));
            rows.push(row);
        }
    }
    for (row, nodes) in merge_shared(rows.into_iter().filter(|r| flag(r.get("enabled")) != Some(false)).collect()) {
        let object = format!("storage {}", js_string_opt(row.get("storage")));
        if flag(row.get("active")) == Some(false) {
            report.add_obj("critical", "storage", object, obj! { "nodes" => nodes, "active" => false, "type" => field(&row, "type") }, "The storage is enabled but not reachable from these nodes. Check its backend, then pve_list_node_storage.");
            continue;
        }
        let Some(used) = number(row.get("used_fraction")).or_else(|| fraction(row.get("used"), row.get("total"))) else { continue };
        let used_percent = round(used * 100.0, 1);
        if used_percent >= warn {
            let is_critical = used_percent >= critical;
            report.add_obj(
                if is_critical { "critical" } else { "warning" },
                "storage",
                object,
                obj! { "nodes" => nodes, "used_percent" => num(used_percent), "used_bytes" => field(&row, "used"), "total_bytes" => field(&row, "total"), "threshold_percent" => num(if is_critical { critical } else { warn }) },
                "Free space or extend the storage. pve_capacity_report shows the trend and the biggest guests.",
            );
        }
    }
}

fn health_tool() -> ToolDef {
    ToolDef::new(
        "pve_health_check",
        "Health check",
        "workflows",
        Gate::Read,
        "Checks nodes, quorum, storage usage, failed services, failed tasks, HA, Ceph if there is any, replication and subscriptions. Each finding has a severity, the object, the evidence and a suggested action. Sections that could not be read are in \"unavailable\" and are not counted as healthy: overall says \"incomplete\" rather than good news. The thresholds used are returned with the answer.",
    )
    .also(&["cluster"])
    .idempotent()
    .input(shape![
        "storage_warn_percent" => z::number().min(1).max(100).optional().describe(format!("Usage from which a storage or root disk is a warning. Default {}.", number_text(DEFAULT_STORAGE_WARN_PERCENT))),
        "storage_critical_percent" => z::number().min(1).max(100).optional().describe(format!("Usage from which it is critical. Default {}.", number_text(DEFAULT_STORAGE_CRITICAL_PERCENT))),
        "memory_warn_percent" => z::number().min(1).max(100).optional().describe(format!("Node memory usage from which it is a warning. Default {}.", number_text(DEFAULT_MEMORY_WARN_PERCENT))),
        "task_hours" => task_hours(),
    ])
    .handler(health_check)
}

async fn health_check(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let storage_warn = args.f64("storage_warn_percent").unwrap_or(DEFAULT_STORAGE_WARN_PERCENT);
    let storage_critical = args.f64("storage_critical_percent").unwrap_or(DEFAULT_STORAGE_CRITICAL_PERCENT);
    let memory_warn = args.f64("memory_warn_percent").unwrap_or(DEFAULT_MEMORY_WARN_PERCENT);
    let hours = args.f64("task_hours").unwrap_or(DEFAULT_TASK_HOURS);
    let thresholds = obj! {
        "storage_warn_percent" => num(storage_warn),
        "storage_critical_percent" => num(storage_critical),
        "memory_warn_percent" => num(memory_warn),
        "task_hours" => num(hours),
    };
    let mut report = Report::default();
    let api = &ctx.api;
    let (top, top_unavailable) = gather(vec![
        ("nodes", api.get("/nodes", get_opts())),
        ("quorum", api.get("/cluster/status", get_opts())),
        ("tasks", api.get("/cluster/tasks", get_opts())),
        ("ha", api.get("/cluster/ha/status/current", get_opts())),
    ])
    .await;
    report.absorb(&top, &top_unavailable);
    let (ceph, ceph_unavailable) = gather(vec![("ceph", api.get("/cluster/ceph/status", get_opts()))]).await;
    let not_applicable = check_ceph(&mut report, &ceph, &ceph_unavailable);

    let node_rows = rows_of(top.get("nodes"));
    let status_rows = rows_of(top.get("quorum"));
    for n in &node_rows {
        let object = format!("node {}", js_string_opt(n.get("node")));
        if is(n, "status", "offline") {
            report.add_obj("critical", "nodes", object, obj! { "status" => field(n, "status") }, "Bring the node back or find out why it left. Its guests and local storage are out of reach.");
            continue;
        }
        if !is(n, "status", "online") {
            report.add_obj("warning", "nodes", object.clone(), obj! { "status" => or_null(n.get("status")) }, "The cluster cannot tell the state of this node: check corosync and the node itself.");
        }
        if let Some(used) = fraction(n.get("mem"), n.get("maxmem")) {
            if round(used * 100.0, 1) >= memory_warn {
                report.add_obj("warning", "nodes", object, obj! { "memory_percent" => num(round(used * 100.0, 1)), "threshold_percent" => num(memory_warn) }, "Look at the guests on this node with pve_capacity_report.");
            }
        }
    }

    if top.contains_key("quorum") {
        let quorum = quorum_of(&status_rows);
        let object = format!("cluster {}", quorum.cluster.clone().unwrap_or_default()).trim().to_string();
        if quorum.state == "no_quorum" {
            report.add_obj(
                "critical",
                "quorum",
                object.clone(),
                obj! { "quorate" => false, "nodes_online" => quorum.nodes_online, "nodes_total" => num(quorum.nodes_total) },
                "Without quorum, /etc/pve is read-only and guests cannot be changed. Bring nodes back before anything else.",
            );
        }
        if quorum.state == "unknown" {
            report.add_obj("warning", "quorum", object, obj! { "quorate" => Value::Null }, "The cluster status does not say whether there is quorum: check with pve_get_cluster_status.");
        }
        for name in &quorum.offline_nodes {
            if !top.contains_key("nodes") {
                report.add_obj("critical", "nodes", format!("node {name}"), obj! { "online" => false, "source" => "/cluster/status" }, "Bring the node back or find out why it left.");
            }
        }
    }

    if let Some(tasks) = top.get("tasks") {
        let failed = recent_failed_tasks(&rows_of(Some(tasks)), hours);
        if !failed.is_empty() {
            report.add_obj("warning", "tasks", "tasks", obj! { "window_hours" => num(hours), "count" => failed.len(), "recent" => first(&failed, 20) }, "Read why with pve_get_task_log_tail and the upid.");
        }
    }

    if let Some(ha) = top.get("ha") {
        let ha = ha_of(&rows_of(Some(ha)));
        if ha.quorate == Some(false) {
            report.add_obj("critical", "ha", "ha quorum", obj! { "quorate" => false }, "HA does nothing without quorum. Restore the quorum first.");
        }
        for s in ha.problem_services {
            let frozen = is(&s, "state", "freeze");
            report.add_obj(
                if frozen { "warning" } else { "critical" },
                "ha",
                format!("ha resource {}", js_string_opt(s.get("sid"))),
                s,
                if frozen {
                    "A frozen resource is not being recovered: this is normal while its node restarts, otherwise look at the node."
                } else {
                    "Read pve_get_ha_status and the task log of the node, then clear the state with pve_update_ha_resource."
                },
            );
        }
        for d in ha.problem_daemons {
            report.add_obj("warning", "ha", format!("ha daemon {}", js_string_opt(d.get("id"))), d, "Look at pve-ha-lrm and pve-ha-crm on this node with pve_list_node_services.");
        }
    }

    let (online, offline) = node_names(&node_rows, &status_rows);
    let per_node_sections = ["node_status", "storage", "services", "replication", "subscription"];
    if online.is_empty() && offline.is_empty() {
        for section in per_node_sections {
            report.reason(section, "not checked: no node list could be read.");
        }
    }
    offline_reasons(&mut report, &per_node_sections, &offline);

    let mut keys = Vec::new();
    let mut futures = Vec::new();
    for node in &online {
        for (section, path) in [
            ("node_status", "/nodes/{node}/status"),
            ("storage", "/nodes/{node}/storage"),
            ("services", "/nodes/{node}/services"),
            ("replication", "/nodes/{node}/replication"),
            ("subscription", "/nodes/{node}/subscription"),
        ] {
            keys.push(format!("{section}/{node}"));
            futures.push(api.get(path, path_of(obj! { "node" => node })));
        }
    }
    let (per_node, per_node_unavailable) = gather(sources(&keys, futures)).await;
    report.absorb(&per_node, &per_node_unavailable);

    let mut storage_by_node: Vec<(String, Vec<Row>)> = Vec::new();
    for node in &online {
        if let Some(rootfs) = per_node.get(&format!("node_status/{node}")).and_then(Value::as_object).and_then(|s| s.get("rootfs")).and_then(Value::as_object) {
            let used_percent = fraction(rootfs.get("used"), rootfs.get("total")).map(|u| round(u * 100.0, 1));
            if let Some(used_percent) = used_percent.filter(|p| *p >= storage_warn) {
                let critical = used_percent >= storage_critical;
                report.add_obj(
                    if critical { "critical" } else { "warning" },
                    "node_status",
                    format!("node {node} root disk"),
                    obj! { "used_percent" => num(used_percent), "used_bytes" => field(rootfs, "used"), "total_bytes" => field(rootfs, "total"), "threshold_percent" => num(if critical { storage_critical } else { storage_warn }) },
                    "A full root disk stops the cluster filesystem and logging on this node. Free space there.",
                );
            }
        }
        if let Some(storage) = per_node.get(&format!("storage/{node}")) {
            storage_by_node.push((node.clone(), rows_of(Some(storage))));
        }

        for service in rows_of(per_node.get(&format!("services/{node}"))) {
            if is(&service, "active-state", "failed") || is(&service, "state", "failed") {
                let name = js_string_opt(nullish(service.get("service"), service.get("name")));
                report.add_obj(
                    if CORE_SERVICES.contains(&name.as_str()) { "critical" } else { "warning" },
                    "services",
                    format!("service {name} on {node}"),
                    obj! { "active-state" => field(&service, "active-state"), "state" => field(&service, "state"), "unit-state" => field(&service, "unit-state") },
                    "Read why with pve_get_node_journal, then restart it with pve_restart_node_service.",
                );
            }
        }

        // The schema only documents the id here: fail_count and error are what the state file holds.
        for job in rows_of(per_node.get(&format!("replication/{node}"))) {
            let failures = number(job.get("fail_count")).unwrap_or(0.0);
            if failures > 0.0 || nonempty_str(job.get("error")).is_some() {
                report.add_obj(
                    "warning",
                    "replication",
                    format!("replication job {}", js_string_opt(job.get("id"))),
                    obj! { "node" => node, "guest" => field(&job, "guest"), "target" => field(&job, "target"), "fail_count" => num(failures), "error" => field(&job, "error"), "last_sync" => iso_time(job.get("last_sync")) },
                    "Read pve_get_node_replication_log for this job. Until it works, the guest has no recent copy on the target.",
                );
            }
        }

        if let Some(subscription) = per_node.get(&format!("subscription/{node}")).and_then(Value::as_object) {
            let status = text_or(subscription.get("status"), "unknown").to_lowercase();
            let evidence = obj! { "status" => &status, "level" => field(subscription, "level"), "message" => field(subscription, "message"), "nextduedate" => field(subscription, "nextduedate") };
            if status == "notfound" || status == "new" {
                report.add_obj("info", "subscription", format!("node {node}"), evidence, "No active subscription: only an issue if this cluster should use the enterprise repository or support.");
            } else if status != "active" {
                report.add_obj("warning", "subscription", format!("node {node}"), evidence, "Renew or check the subscription key of this node.");
            }
        }
    }
    check_node_storage(&mut report, &storage_by_node, storage_warn, storage_critical);

    let body = report.summary(&HEALTH_SEVERITIES);
    let overall = if report.count("critical") > 0 {
        "critical"
    } else if report.count("warning") > 0 {
        "warning"
    } else if body.get("complete") == Some(&Value::Bool(true)) {
        "no_findings"
    } else {
        "incomplete"
    };
    let mut out = obj! { "overall" => overall };
    out.extend(body);
    if !not_applicable.is_empty() {
        out.insert("not_applicable".into(), Value::Object(not_applicable));
    }
    out.insert("thresholds".into(), Value::Object(thresholds));
    out.insert(
        "note".into(),
        Value::String("These are the checks listed under checked, on the data this token may read. No finding in one of them does not prove that all is well, and unavailable sections say nothing at all.".into()),
    );
    Ok(Value::Object(out))
}

/* ------------------------------------------------------------------ security audit */

fn nics_with_firewall(config: &Row) -> (usize, usize) {
    let nics: Vec<&str> = config.iter().filter(|(k, _)| NET_KEY.is_match(k)).filter_map(|(_, v)| v.as_str()).collect();
    (nics.len(), nics.iter().filter(|v| NIC_FIREWALL.is_match(v)).count())
}

fn audit_tokens(report: &mut Report, users: &[Row]) {
    let mut no_expiry: Vec<String> = Vec::new();
    let mut no_privsep: Vec<String> = Vec::new();
    for user in users {
        for token in rows_of(user.get("tokens")) {
            let id = format!("{}!{}", js_string_opt(user.get("userid")), js_string_opt(token.get("tokenid")));
            // Left out, a token expires with its user.
            let expire = number(token.get("expire")).or(number(user.get("expire"))).unwrap_or(0.0);
            if expire == 0.0 {
                no_expiry.push(id.clone());
            }
            if flag(token.get("privsep")) == Some(false) {
                no_privsep.push(id);
            }
        }
    }
    if !no_expiry.is_empty() {
        report.add_obj("low", "tokens", "api tokens", obj! { "without_expiry" => no_expiry }, "Set an expiry on tokens that do not need to live forever: pve_update_user_token.");
    }
    if !no_privsep.is_empty() {
        let root = no_privsep.iter().any(|id| id.starts_with("root@pam!"));
        report.add_obj(
            if root { "high" } else { "medium" },
            "tokens",
            "api tokens",
            obj! { "without_privilege_separation" => no_privsep },
            "These tokens hold all the rights of their user. Prefer privsep=1 with an ACL for only what the token needs.",
        );
    }
}

fn audit_root_tfa(report: &mut Report, entries: &Value) {
    let rows = rows_of(Some(entries));
    let usable = rows.iter().any(|e| SECOND_FACTORS.contains(&js_string_opt(e.get("type")).as_str()) && flag(e.get("enable")) != Some(false));
    if usable {
        return;
    }
    let listed: Vec<Value> = rows.iter().map(|e| Value::Object(obj! { "type" => field(e, "type"), "enable" => nullish(e.get("enable"), None).cloned().unwrap_or(Value::from(1)) })).collect();
    report.add_obj(
        "high",
        "root_tfa",
        "root@pam",
        obj! { "entries" => listed },
        "root@pam has no enabled second factor (recovery keys do not count). Add one in the web interface: the API refuses this to tokens.",
    );
}

fn audit_acl(report: &mut Report, acl: &[Row]) {
    for entry in acl {
        if !is(entry, "path", "/") || !POWERFUL_ROLES.contains(&js_string_opt(entry.get("roleid")).as_str()) {
            continue;
        }
        report.add_obj(
            if is(entry, "roleid", "Administrator") { "high" } else { "medium" },
            "acl",
            format!("{} {}", js_string_opt(entry.get("type")), js_string_opt(entry.get("ugid"))),
            obj! { "path" => field(entry, "path"), "roleid" => field(entry, "roleid"), "propagate" => flag(entry.get("propagate")).unwrap_or(true) },
            "Confirm that this account needs this much on the whole cluster. Otherwise grant a narrower role on a narrower path with pve_update_acl.",
        );
    }
}

fn audit_certificates(report: &mut Report, node: &str, certs: &[Row], warn_days: f64) {
    let now = now_seconds();
    for cert in certs {
        let Some(after) = number(cert.get("notafter")) else { continue };
        let days_left = ((after - now) / DAY_SECONDS).floor();
        if days_left > warn_days {
            continue;
        }
        let name = text_or(nullish(nullish(cert.get("filename"), cert.get("fingerprint")), None), "unnamed");
        report.add_obj(
            if days_left < 0.0 { "high" } else { "medium" },
            "certificates",
            format!("certificate {name} on {node}"),
            obj! { "not_after" => iso_seconds(after), "days_left" => num(days_left), "subject" => field(cert, "subject"), "threshold_days" => num(warn_days) },
            "Renew it, with ACME (pve_renew_node_acme_certificate) or by hand, before clients start refusing it.",
        );
    }
}

fn security_audit_tool() -> ToolDef {
    ToolDef::new(
        "pve_security_audit",
        "Security audit",
        "workflows",
        Gate::Read,
        "Reads the security-related settings: firewall state (cluster, nodes, guests), privileged containers, API tokens without expiry or privilege separation, second factor on root@pam, powerful ACLs on /, backups, pending updates, certificate expiry. Findings state what the data shows, with evidence and a suggested action. Sections it could not read are named in \"unavailable\". This is neither a certification nor a statement of compliance, and only sees what this token may read.",
    )
    .also(&["access", "firewall"])
    .idempotent()
    .input(shape![
        "cert_warn_days" => z::int().min(0).max(3650).optional().describe(format!("Days before expiry from which a certificate is a finding. Default {}.", number_text(DEFAULT_CERT_WARN_DAYS))),
        "include_guests" => z::boolean().optional().describe("Also read the config and firewall options of each guest. Two requests per guest. Default true."),
    ])
    .handler(security_audit)
}

async fn security_audit(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let cert_warn_days = args.f64("cert_warn_days").unwrap_or(DEFAULT_CERT_WARN_DAYS);
    let include_guests = args.bool("include_guests") != Some(false);
    let mut report = Report::default();
    let api = &ctx.api;
    let (top, top_unavailable) = gather(vec![
        ("cluster_firewall", api.get("/cluster/firewall/options", get_opts())),
        ("tokens", api.get("/access/users", RequestOptions::params(obj! { "full" => 1 }))),
        ("root_tfa", api.get("/access/tfa/{userid}", path_of(obj! { "userid" => "root@pam" }))),
        ("acl", api.get("/access/acl", get_opts())),
        ("not_backed_up", api.get("/cluster/backup-info/not-backed-up", get_opts())),
        ("backup_jobs", api.get("/cluster/backup", get_opts())),
        ("node_list", api.get("/nodes", get_opts())),
        ("guests", api.get("/cluster/resources", RequestOptions::params(obj! { "type" => "vm" }))),
    ])
    .await;
    report.absorb(&top, &top_unavailable);

    if let Some(firewall) = top.get("cluster_firewall").and_then(Value::as_object) {
        if flag(firewall.get("enable")) != Some(true) {
            report.add_obj(
                "medium",
                "cluster_firewall",
                "datacenter firewall",
                obj! { "enable" => nullish(firewall.get("enable"), None).cloned().unwrap_or(Value::from(0)) },
                "The firewall is off for the whole cluster, so no rule of any node or guest applies. Review the rules first, as enabling it can cut access: pve_update_cluster_firewall_options.",
            );
        }
    }
    if let Some(tokens) = top.get("tokens") {
        audit_tokens(&mut report, &rows_of(Some(tokens)));
    }
    if let Some(tfa) = top.get("root_tfa") {
        audit_root_tfa(&mut report, tfa);
    }
    if let Some(acl) = top.get("acl") {
        audit_acl(&mut report, &rows_of(Some(acl)));
    }
    if let Some(missing) = top.get("not_backed_up") {
        let missing = rows_of(Some(missing));
        if !missing.is_empty() {
            let guests: Vec<Value> = missing.iter().take(MAX_LISTED).map(|g| Value::Object(obj! { "vmid" => field(g, "vmid"), "name" => field(g, "name"), "type" => field(g, "type") })).collect();
            report.add_obj("medium", "not_backed_up", "guests", obj! { "count" => missing.len(), "guests" => guests }, "These guests are in no backup job. See pve_backup_coverage.");
        }
    }
    if let Some(jobs) = top.get("backup_jobs") {
        let jobs = rows_of(Some(jobs));
        if !jobs.iter().any(|j| flag(j.get("enabled")) != Some(false)) {
            report.add_obj("medium", "backup_jobs", "backup jobs", obj! { "jobs" => jobs.len(), "enabled" => 0 }, "No enabled backup job. Create one with pve_create_backup_job.");
        }
    }

    let (online, offline) = node_names(&rows_of(top.get("node_list")), &[]);
    let per_node_sections = ["node_firewall", "updates", "certificates"];
    if online.is_empty() && offline.is_empty() {
        for section in per_node_sections {
            report.reason(section, "not checked: no node list could be read.");
        }
    }
    offline_reasons(&mut report, &per_node_sections, &offline);
    let offline_set: HashSet<&String> = offline.iter().collect();
    let guests: Vec<Row> = if include_guests { guests_of(rows_of(top.get("guests"))).into_iter().filter(|g| flag(g.get("template")) != Some(true)).collect() } else { Vec::new() };
    let mut keys = Vec::new();
    let mut futures = Vec::new();
    for node in &online {
        for (section, path) in [("node_firewall", "/nodes/{node}/firewall/options"), ("updates", "/nodes/{node}/apt/update"), ("certificates", "/nodes/{node}/certificates/info")] {
            keys.push(format!("{section}/{node}"));
            futures.push(api.get(path, path_of(obj! { "node" => node })));
        }
    }
    if include_guests && !top.contains_key("guests") {
        report.reason("guest_config", "not checked: the guest list could not be read.");
        report.reason("guest_firewall", "not checked: the guest list could not be read.");
    }
    for row in &guests {
        let guest = location_of(row);
        if offline_set.contains(&guest.node) {
            report.reason(format!("guest_config/{}", guest.vmid), format!("not checked: node {} is offline.", guest.node));
            report.reason(format!("guest_firewall/{}", guest.vmid), format!("not checked: node {} is offline.", guest.node));
            continue;
        }
        keys.push(format!("guest_config/{}", guest.vmid));
        futures.push(api.get(&guest.path("/config"), guest.params()));
        keys.push(format!("guest_firewall/{}", guest.vmid));
        futures.push(api.get(&guest.path("/firewall/options"), guest.params()));
    }
    let (details, details_unavailable) = gather(sources(&keys, futures)).await;
    report.absorb(&details, &details_unavailable);

    for node in &online {
        // Host rules default to on here, unlike the cluster and guest switches.
        if let Some(firewall) = details.get(&format!("node_firewall/{node}")).and_then(Value::as_object) {
            if flag(firewall.get("enable")) == Some(false) {
                report.add_obj("low", "node_firewall", format!("node {node}"), obj! { "enable" => field(firewall, "enable") }, "Host firewall rules are off on this node. Check that this is intended: pve_update_node_firewall_options.");
            }
        }
        if let Some(updates) = details.get(&format!("updates/{node}")) {
            let rows = rows_of(Some(updates));
            if !rows.is_empty() {
                let sample: Vec<String> = rows.iter().take(10).map(|r| format!("{} {} -> {}", js_string_opt(r.get("Package")), text_or(r.get("OldVersion"), "?"), js_string_opt(r.get("Version")))).collect();
                report.add_obj(
                    "low",
                    "updates",
                    format!("node {node}"),
                    obj! { "pending" => rows.len(), "from_proxmox" => rows.iter().filter(|r| is(r, "Origin", "Proxmox")).count(), "sample" => sample },
                    "Plan the upgrade. The list is from the last package index refresh: pve_refresh_apt_index renews it.",
                );
            }
        }
        if let Some(certs) = details.get(&format!("certificates/{node}")) {
            audit_certificates(&mut report, node, &rows_of(Some(certs)), cert_warn_days);
        }
    }

    let mut privileged: Vec<Value> = Vec::new();
    let mut firewall_off: Vec<Value> = Vec::new();
    let mut firewall_not_on_nics: Vec<Value> = Vec::new();
    for row in &guests {
        let guest = location_of(row);
        let label = obj! { "vmid" => guest.vmid, "name" => field(row, "name"), "type" => guest.kind, "node" => &guest.node };
        let config = details.get(&format!("guest_config/{}", guest.vmid)).and_then(Value::as_object);
        let options = details.get(&format!("guest_firewall/{}", guest.vmid)).and_then(Value::as_object);
        if guest.kind == "lxc" && config.is_some_and(|c| flag(c.get("unprivileged")) != Some(true)) {
            privileged.push(Value::Object(label.clone()));
        }
        let Some(options) = options else { continue };
        // Off by default, on guests.
        if flag(options.get("enable")) != Some(true) {
            firewall_off.push(Value::Object(label));
        } else if let Some(config) = config {
            let (nics, with_firewall) = nics_with_firewall(config);
            if nics > 0 && with_firewall == 0 {
                let mut entry = label;
                entry.insert("nics".into(), Value::from(nics));
                firewall_not_on_nics.push(Value::Object(entry));
            }
        }
    }
    if !privileged.is_empty() {
        report.add_obj(
            "medium",
            "guest_config",
            "privileged containers",
            obj! { "count" => privileged.len(), "guests" => first(&privileged, MAX_LISTED) },
            "Root in a privileged container is much closer to root on the node. Move them to unprivileged containers where possible.",
        );
    }
    if !firewall_off.is_empty() {
        report.add_obj(
            "low",
            "guest_firewall",
            "guests with the firewall off",
            obj! { "count" => firewall_off.len(), "guests" => first(&firewall_off, MAX_LISTED) },
            "Rules defined for these guests do not apply. Enable with pve_update_vm_firewall_options or pve_update_lxc_firewall_options where traffic should be filtered.",
        );
    }
    if !firewall_not_on_nics.is_empty() {
        report.add_obj(
            "low",
            "guest_firewall",
            "guests with the firewall on but on no interface",
            obj! { "count" => firewall_not_on_nics.len(), "guests" => first(&firewall_not_on_nics, MAX_LISTED) },
            "The guest firewall is enabled, but no net interface has firewall=1, so no traffic goes through it. Set it in the interface config.",
        );
    }

    let mut out = report.summary(&AUDIT_SEVERITIES);
    out.insert("thresholds".into(), Value::Object(obj! { "cert_warn_days" => num(cert_warn_days), "powerful_roles" => POWERFUL_ROLES.iter().map(|r| r.to_string()).collect::<Vec<String>>() }));
    let mut limits: Vec<String> = vec![
        "Users, tokens and second factors are limited to the accounts this token is allowed to see, and ACL entries to the objects whose permissions it may modify: an empty list does not prove there are none.".into(),
        "Pending updates come from the last refresh of the package index.".into(),
        "A second factor enforced at realm level is not looked at.".into(),
    ];
    if !include_guests {
        limits.push("Guest config and firewall were not read, since include_guests is false.".into());
    }
    out.insert("limits".into(), Value::from(limits));
    out.insert("disclaimer".into(), Value::String("This reports what the data shows on the checks listed. It is not a certification nor a statement of compliance, and no finding does not mean secure.".into()));
    Ok(Value::Object(out))
}

/* ------------------------------------------------------------------ backups */

fn backup_coverage_tool() -> ToolDef {
    ToolDef::new(
        "pve_backup_coverage",
        "Backup coverage",
        "workflows",
        Gate::Read,
        "For each guest: whether it is in a backup job, and the age of its last backup found on the backup storages. Also the jobs and the guests that no job covers. A storage or node that could not be read is named in \"unavailable\", and a guest whose last backup could therefore be missed is listed under not_determined instead of being called unprotected. Having a backup says nothing of whether it restores.",
    )
    .also(&["backup"])
    .idempotent()
    .input(shape![
        "max_age_days" => z::number().min(0).max(36500).optional().describe(format!("A last backup older than this is a finding. Default {}.", number_text(DEFAULT_BACKUP_MAX_AGE_DAYS))),
        "page_limit" => page_limit(),
        "page_offset" => page_offset(),
    ])
    .handler(backup_coverage)
}

struct LastBackup {
    ctime: f64,
    volid: Option<Value>,
    storage: String,
    count: usize,
    verification: Option<Value>,
}

async fn backup_coverage(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let max_age_days = args.f64("max_age_days").unwrap_or(DEFAULT_BACKUP_MAX_AGE_DAYS);
    let mut report = Report::default();
    let api = &ctx.api;
    let (top, top_unavailable) = gather(vec![
        ("not_backed_up", api.get("/cluster/backup-info/not-backed-up", get_opts())),
        ("jobs", api.get("/cluster/backup", get_opts())),
        ("guests", api.get("/cluster/resources", RequestOptions::params(obj! { "type" => "vm" }))),
        ("node_list", api.get("/nodes", get_opts())),
    ])
    .await;
    report.absorb(&top, &top_unavailable);

    let (online, offline) = node_names(&rows_of(top.get("node_list")), &[]);
    if online.is_empty() && offline.is_empty() {
        report.reason("backups", "not checked: no node list could be read.");
    }
    offline_reasons(&mut report, &["backups"], &offline);

    let keys: Vec<String> = online.iter().map(|node| format!("storages/{node}")).collect();
    let futures = online.iter().map(|node| api.get("/nodes/{node}/storage", path_of(obj! { "node" => node }).with_params(obj! { "content" => "backup" }))).collect();
    let (listed, listed_unavailable) = gather(sources(&keys, futures)).await;
    report.absorb(&listed, &listed_unavailable);

    // A shared storage holds the same backups from every node: it is listed once.
    let mut places: Vec<(String, String)> = Vec::new();
    let mut seen_shared: HashSet<String> = HashSet::new();
    for node in &online {
        for row in rows_of(listed.get(&format!("storages/{node}"))) {
            let storage = js_string_opt(row.get("storage"));
            if flag(row.get("enabled")) == Some(false) {
                continue;
            }
            if row.get("content").is_some() && !js_string_opt(row.get("content")).split(',').any(|c| c == "backup") {
                continue;
            }
            if flag(row.get("active")) == Some(false) {
                report.reason(format!("backups/{storage}@{node}"), "not read: the storage is not active.");
                continue;
            }
            if flag(row.get("shared")) == Some(true) && !seen_shared.insert(storage.clone()) {
                continue;
            }
            places.push((node.clone(), storage));
        }
    }
    let keys: Vec<String> = places.iter().map(|(node, storage)| format!("backups/{storage}@{node}")).collect();
    let futures = places
        .iter()
        .map(|(node, storage)| api.get("/nodes/{node}/storage/{storage}/content", path_of(obj! { "node" => node, "storage" => storage }).with_params(obj! { "content" => "backup" })))
        .collect();
    let (contents, contents_unavailable) = gather(sources(&keys, futures)).await;
    report.absorb(&contents, &contents_unavailable);

    let mut last: HashMap<String, LastBackup> = HashMap::new();
    for (key, value) in &contents {
        let end = key.rfind('@').unwrap_or(key.len()).max("backups/".len());
        let storage = key.get("backups/".len()..end).unwrap_or_default().to_string();
        for volume in rows_of(Some(value)) {
            if volume.get("content").is_some() && !is(&volume, "content", "backup") {
                continue;
            }
            let Some(id) = number(volume.get("vmid")) else { continue };
            let ctime = number(volume.get("ctime")).unwrap_or(0.0);
            let id = number_text(id);
            match last.get_mut(&id) {
                Some(known) if ctime <= known.ctime => known.count += 1,
                known => {
                    let count = known.map(|k| k.count).unwrap_or(0) + 1;
                    let verification = volume.get("verification").and_then(Value::as_object).and_then(|v| v.get("state")).cloned();
                    last.insert(id, LastBackup { ctime, volid: field(&volume, "volid"), storage: storage.clone(), count, verification });
                }
            }
        }
    }

    let jobless: Option<HashSet<Option<String>>> = top.get("not_backed_up").map(|v| rows_of(Some(v)).iter().map(|g| number(g.get("vmid")).map(number_text)).collect());
    let storages_complete = !report.unavailable.keys().any(|k| k.starts_with("backups") || k.starts_with("storages"));
    let now = now_seconds();
    let mut stale: Vec<Value> = Vec::new();
    let mut none: Vec<Value> = Vec::new();
    let mut not_determined: Vec<Value> = Vec::new();
    let mut guests = guests_of(rows_of(top.get("guests")));
    guests.sort_by(|a, b| ascending(number(a.get("vmid")).unwrap_or(0.0), number(b.get("vmid")).unwrap_or(0.0)));
    let rows: Vec<Value> = guests
        .iter()
        .map(|g| {
            let id = number(g.get("vmid")).unwrap_or(0.0);
            let backup = last.get(&number_text(id));
            // Without a date there is no age to judge, only a backup that exists.
            let age_days = backup.filter(|b| b.ctime > 0.0).map(|b| round((now - b.ctime) / DAY_SECONDS, 1));
            let too_old = age_days.is_some_and(|a| a > max_age_days);
            let label = obj! { "vmid" => num(id), "name" => field(g, "name"), "type" => field(g, "type"), "node" => field(g, "node") };
            let with = |extra: Row| {
                let mut out = label.clone();
                out.extend(extra);
                Value::Object(out)
            };
            // A template does not change, so an old backup of it says nothing: it is listed, not judged.
            if flag(g.get("template")) != Some(true) {
                match backup {
                    Some(b) if too_old && storages_complete => stale.push(with(obj! { "age_days" => age_days.map(num), "last_backup" => iso_seconds(b.ctime) })),
                    Some(_) if too_old => not_determined.push(with(obj! { "reason" => "The newest backup found is old, and a newer one may be on a storage that could not be read." })),
                    None if storages_complete => none.push(Value::Object(label.clone())),
                    None => not_determined.push(with(obj! { "reason" => "No backup found, but some storages could not be read." })),
                    _ => {}
                }
            }
            let mut out = label.clone();
            out.extend(obj! {
                "status" => field(g, "status"),
                "template" => (flag(g.get("template")) == Some(true)).then_some(true),
                "in_backup_job" => jobless.as_ref().map(|j| Value::Bool(!j.contains(&Some(number_text(id))))).unwrap_or(Value::Null),
                "last_backup" => backup.filter(|b| b.ctime > 0.0).map(|b| iso_seconds(b.ctime)).unwrap_or(Value::Null),
                "age_days" => age_days.map(num).unwrap_or(Value::Null),
            });
            if let Some(b) = backup {
                out.extend(obj! {
                    "storage" => &b.storage,
                    "volid" => b.volid.clone(),
                    "backups_found" => b.count,
                    "verification" => b.verification.clone().filter(|v| truthy_js(Some(v))),
                });
            }
            Value::Object(out)
        })
        .collect();

    if let Some(jobless) = jobless.as_ref().filter(|j| !j.is_empty()) {
        let guests: Vec<Value> = rows_of(top.get("not_backed_up")).iter().take(MAX_LISTED).map(|g| Value::Object(obj! { "vmid" => field(g, "vmid"), "name" => field(g, "name"), "type" => field(g, "type") })).collect();
        report.add_obj(
            "medium",
            "not_backed_up",
            "guests in no backup job",
            obj! { "count" => jobless.len(), "guests" => guests },
            "Add them to a job, or exclude them knowingly: pve_create_backup_job, pve_update_backup_job.",
        );
    }
    if !none.is_empty() {
        report.add_obj("medium", "backups", "guests without any backup found", obj! { "count" => none.len(), "guests" => first(&none, MAX_LISTED) }, "Check that they are meant to be backed up, and pve_run_backup for a first one.");
    }
    if !stale.is_empty() {
        report.add_obj(
            "low",
            "backups",
            "guests whose last backup is old",
            obj! { "threshold_days" => num(max_age_days), "count" => stale.len(), "guests" => first(&stale, MAX_LISTED) },
            "Check the job that should cover them and the logs of its last run.",
        );
    }
    let jobs = top.get("jobs").map(|j| rows_of(Some(j)));
    if let Some(jobs) = &jobs {
        if !jobs.iter().any(|j| flag(j.get("enabled")) != Some(false)) {
            report.add_obj("medium", "jobs", "backup jobs", obj! { "jobs" => jobs.len(), "enabled" => 0 }, "No enabled backup job. Create one with pve_create_backup_job.");
        }
    }

    let mut out = report.summary(&AUDIT_SEVERITIES);
    out.insert("thresholds".into(), Value::Object(obj! { "max_age_days" => num(max_age_days) }));
    out.insert(
        "jobs".into(),
        jobs.map(|jobs| {
            Value::Array(
                jobs.iter()
                    .map(|j| {
                        Value::Object(obj! {
                            "id" => field(j, "id"),
                            "enabled" => flag(j.get("enabled")).unwrap_or(true),
                            "schedule" => field(j, "schedule"),
                            "storage" => field(j, "storage"),
                            "all" => flag(j.get("all")).unwrap_or(false),
                            "vmid" => field(j, "vmid"),
                            "pool" => field(j, "pool"),
                            "exclude" => field(j, "exclude"),
                            "node" => field(j, "node"),
                            "next_run" => iso_time(j.get("next-run")),
                            "mode" => field(j, "mode"),
                        })
                    })
                    .collect(),
            )
        })
        .unwrap_or(Value::Null),
    );
    let read: Vec<String> = places.iter().filter(|(node, storage)| contents.contains_key(&format!("backups/{storage}@{node}"))).map(|(node, storage)| format!("{storage}@{node}")).collect();
    out.insert("storages_read".into(), Value::from(read));
    out.insert("not_determined".into(), first(&not_determined, MAX_LISTED));
    let (limit, offset) = paging_args(&args);
    out.extend(page_rows(rows, limit, offset));
    Ok(Value::Object(out))
}

/* ------------------------------------------------------------------ capacity */

/// Least squares on used bytes over time. A straight line through the past, and it says so.
fn forecast_storage(points: &[Row], total_bytes: Option<f64>, window: &str) -> Value {
    let clean: Vec<(f64, f64)> = points.iter().filter_map(|p| Some((number(p.get("time"))?, number(p.get("used"))?))).collect();
    if clean.len() < MIN_FORECAST_POINTS {
        return Value::Object(obj! { "available" => false, "reason" => format!("Only {} data points in the window: at least {MIN_FORECAST_POINTS} are needed.", clean.len()) });
    }
    let n = clean.len() as f64;
    let mean_t = clean.iter().fold(0.0, |s, p| s + p.0) / n;
    let mean_y = clean.iter().fold(0.0, |s, p| s + p.1) / n;
    let denominator = clean.iter().fold(0.0, |s, p| s + (p.0 - mean_t) * (p.0 - mean_t));
    if denominator == 0.0 {
        return Value::Object(obj! { "available" => false, "reason" => "All the data points have the same time." });
    }
    let slope = clean.iter().fold(0.0, |s, p| s + (p.0 - mean_t) * (p.1 - mean_y)) / denominator;
    let per_day = slope * DAY_SECONDS;
    let last_total = number(points.last().and_then(|p| p.get("total"))).or(total_bytes);
    let latest = clean[clean.len() - 1].1;
    let mut out = obj! { "available" => true, "method" => format!("linear least squares on RRD averages, last {window}"), "points" => clean.len(), "growth_bytes_per_day" => num(js_round(per_day)) };
    if per_day <= 0.0 {
        out.extend(obj! { "days_until_full" => Value::Null, "trend" => "not_growing" });
        return Value::Object(out);
    }
    match last_total {
        Some(total) if total > 0.0 => {
            let days = ((total - latest) / per_day).max(0.0);
            out.extend(obj! { "days_until_full" => num(round(days, 1)), "trend" => "growing", "assumption" => "Extrapolates past growth in a straight line: a rough idea, not a prediction." });
        }
        _ => out.extend(obj! { "days_until_full" => Value::Null, "trend" => "growing", "reason" => "The total size is not known." }),
    }
    Value::Object(out)
}

fn capacity_tool() -> ToolDef {
    ToolDef::new(
        "pve_capacity_report",
        "Capacity report",
        "workflows",
        Gate::Read,
        "CPU, memory and disk per node, what the guests are allocated against that (overcommit ratios), storage usage with a straight-line forecast from its history, and the biggest guests. Facts and ratios only: no threshold judges them. Sections that could not be read are in \"unavailable\".",
    )
    .also(&["cluster", "storage"])
    .idempotent()
    .input(shape![
        "forecast_window" => z::enumeration(&["day", "week", "month", "year"]).optional().describe("History the storage forecast is based on. Default month."),
        "forecast" => z::boolean().optional().describe("Read the history of each storage for a forecast. One request per storage. Default true."),
        "top" => z::int().min(1).max(100).optional().describe("How many guests in each list of the biggest. Default 5."),
    ])
    .handler(capacity_report)
}

async fn capacity_report(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let window = args.string("forecast_window").unwrap_or_else(|| "month".into());
    let top = args.u64("top").unwrap_or(5) as usize;
    let forecast = args.bool("forecast") != Some(false);
    let api = &ctx.api;
    let (data, mut unavailable) = gather(vec![("resources", api.get("/cluster/resources", get_opts()))]).await;
    let Some(resources) = data.get("resources") else {
        return Ok(Value::Object(obj! { "complete" => false, "nodes" => Value::Null, "storage" => Value::Null, "biggest_guests" => Value::Null, "unavailable" => unavailable }));
    };
    let resources = rows_of(Some(resources));
    let all_guests = guests_of(resources.clone());
    let guests: Vec<Row> = all_guests.iter().filter(|g| flag(g.get("template")) != Some(true)).cloned().collect();

    let sum = |rows: &[&Row], key: &str| rows.iter().fold(0.0, |total, g| total + number(g.get(key)).unwrap_or(0.0));
    let ratio = |allocated: f64, available: Option<f64>| match available {
        Some(a) if a > 0.0 => num(round(allocated / a, 2)),
        _ => Value::Null,
    };
    let nodes: Vec<Value> = resources
        .iter()
        .filter(|r| is(r, "type", "node"))
        .map(|n| {
            let here: Vec<&Row> = guests.iter().filter(|g| g.get("node") == n.get("node")).collect();
            let running: Vec<&Row> = here.iter().copied().filter(|g| is(g, "status", "running")).collect();
            let cores = number(n.get("maxcpu"));
            let memory = number(n.get("maxmem"));
            Value::Object(obj! {
                "node" => field(n, "node"),
                "status" => field(n, "status"),
                "cores" => cores.map(num).unwrap_or(Value::Null),
                "cpu_percent" => percent(number(n.get("cpu"))),
                "memory_used_bytes" => or_null(n.get("mem")),
                "memory_total_bytes" => or_null(n.get("maxmem")),
                "memory_percent" => percent(fraction(n.get("mem"), n.get("maxmem"))),
                "root_disk_used_bytes" => or_null(n.get("disk")),
                "root_disk_total_bytes" => or_null(n.get("maxdisk")),
                "root_disk_percent" => percent(fraction(n.get("disk"), n.get("maxdisk"))),
                "guests" => here.len(),
                "guests_running" => running.len(),
                "vcpus_allocated" => num(sum(&here, "maxcpu")),
                "vcpus_running" => num(sum(&running, "maxcpu")),
                "memory_allocated_bytes" => num(sum(&here, "maxmem")),
                "memory_running_bytes" => num(sum(&running, "maxmem")),
                // More than 1 means overcommitted, which is a choice rather than a fault.
                "cpu_overcommit_ratio" => ratio(sum(&here, "maxcpu"), cores),
                "cpu_overcommit_ratio_running" => ratio(sum(&running, "maxcpu"), cores),
                "memory_overcommit_ratio" => ratio(sum(&here, "maxmem"), memory),
                "memory_overcommit_ratio_running" => ratio(sum(&running, "maxmem"), memory),
            })
        })
        .collect();

    let storages = merge_shared(storages_of(&resources));
    let history_key = |row: &Row| format!("forecast/{}@{}", js_string_opt(row.get("storage")), js_string_opt(row.get("node")));
    let read: Vec<&Row> = if forecast { storages.iter().map(|(row, _)| row).filter(|row| !is(row, "status", "unknown")).collect() } else { Vec::new() };
    let keys: Vec<String> = read.iter().map(|row| history_key(row)).collect();
    let futures = read
        .iter()
        .map(|row| {
            api.get(
                "/nodes/{node}/storage/{storage}/rrddata",
                path_of(obj! { "node" => js_string_opt(row.get("node")), "storage" => js_string_opt(row.get("storage")) }).with_params(obj! { "timeframe" => &window, "cf" => "AVERAGE" }),
            )
        })
        .collect();
    let (history, history_unavailable) = gather(sources(&keys, futures)).await;
    for (k, v) in &history_unavailable {
        unavailable.insert(k.clone(), v.clone());
    }
    let storage: Vec<Value> = storages
        .iter()
        .map(|(row, seen_on)| {
            let key = history_key(row);
            let total = number(row.get("maxdisk"));
            let forecast_value = if !forecast {
                Value::Null
            } else if let Some(points) = history.get(&key) {
                forecast_storage(&rows_of(Some(points)), total, &window)
            } else {
                Value::Object(obj! { "available" => false, "reason" => history_unavailable.get(&key).cloned().unwrap_or_else(|| Value::from("The storage is in an unknown state.")) })
            };
            Value::Object(obj! {
                "storage" => field(row, "storage"),
                "type" => field(row, "plugintype"),
                "shared" => flag(row.get("shared")) == Some(true),
                "nodes" => seen_on.clone(),
                "status" => field(row, "status"),
                "used_bytes" => or_null(row.get("disk")),
                "total_bytes" => or_null(row.get("maxdisk")),
                "used_percent" => percent(fraction(row.get("disk"), row.get("maxdisk"))),
                "forecast" => forecast_value,
            })
        })
        .collect();

    let biggest = |key: &str| {
        let mut list: Vec<&Row> = guests.iter().filter(|g| number(g.get(key)).is_some()).collect();
        list.sort_by(|a, b| ascending(number(b.get(key)).unwrap_or(0.0), number(a.get(key)).unwrap_or(0.0)));
        Value::Array(
            list.into_iter()
                .take(top)
                .map(|g| Value::Object(obj! { "vmid" => field(g, "vmid"), "name" => field(g, "name"), "type" => field(g, "type"), "node" => field(g, "node"), "status" => field(g, "status"), key => field(g, key) }))
                .collect(),
        )
    };

    Ok(Value::Object(obj! {
        "complete" => unavailable.is_empty(),
        "nodes" => nodes,
        "storage" => storage,
        "biggest_guests" => Value::Object(obj! { "by_memory" => biggest("maxmem"), "by_disk" => biggest("maxdisk"), "by_vcpus" => biggest("maxcpu") }),
        "templates_excluded" => all_guests.len() - guests.len(),
        "note" => "Allocations count guests that are not templates. A token only sees what it has audit rights on, so totals may be partial.",
        "unavailable" => unavailable,
    }))
}

/// Composite tools.
pub fn workflow_tools() -> Vec<ToolDef> {
    vec![
        overview_tool(),
        find_guest_tool(),
        wait_task_tool(),
        task_log_tool(),
        guest_power_tool(),
        snapshot_tool(),
        list_snapshots_tool(),
        provision_lxc_tool(),
        provision_vm_tool(),
        health_tool(),
        security_audit_tool(),
        backup_coverage_tool(),
        capacity_tool(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rows(v: Value) -> Vec<Row> {
        rows_of(Some(&v))
    }

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&workflow_tools());
    }

    #[test]
    fn flags_and_numbers_read_like_the_api_writes_them() {
        assert_eq!(flag(Some(&json!(1))), Some(true));
        assert_eq!(flag(Some(&json!("0"))), Some(false));
        assert_eq!(flag(Some(&json!(true))), Some(true));
        assert_eq!(flag(Some(&json!("yes"))), None);
        assert_eq!(flag(None), None);
        assert_eq!(percent(fraction(Some(&json!(1)), Some(&json!(3)))), json!(33.3));
        assert_eq!(percent(fraction(Some(&json!(1)), Some(&json!(0)))), Value::Null);
        assert_eq!(percent(Some(0.5)), json!(50));
        assert_eq!(iso_time(Some(&json!(0))), json!("1970-01-01T00:00:00.000Z"));
        assert_eq!(iso_time(Some(&json!("x"))), Value::Null);
    }

    #[test]
    fn quorum_of_a_single_node_is_standalone() {
        let q = quorum_of(&rows(json!([{ "type": "node", "name": "pve1", "online": 1 }])));
        assert_eq!(q.to_json(), json!({ "state": "standalone", "nodes_total": 1, "nodes_online": 1, "offline_nodes": [] }));
        let q = quorum_of(&rows(json!([
            { "type": "cluster", "name": "lab", "quorate": 0, "nodes": 3 },
            { "type": "node", "name": "pve1", "online": 1 },
            { "type": "node", "name": "pve2", "online": 0 },
        ])));
        assert_eq!(q.to_json(), json!({ "state": "no_quorum", "cluster": "lab", "nodes_total": 3, "nodes_online": 1, "offline_nodes": ["pve2"] }));
        let q = quorum_of(&rows(json!([{ "type": "cluster", "name": "" }])));
        assert_eq!(q.state, "unknown");
        assert_eq!(q.cluster, None);
    }

    #[test]
    fn failed_tasks_are_those_with_an_error_status() {
        let ok = |s: &str| task_failed(&rows(json!([{ "status": s }]))[0]);
        assert!(!ok("OK"));
        assert!(!ok("running"));
        assert!(!ok("WARNINGS: 3"));
        assert!(ok("command 'x' failed: exit code 1"));
        assert!(!task_failed(&Map::new()));
        let now = now_seconds();
        let list = rows(json!([
            { "upid": "a", "status": "boom", "starttime": now - 10.0 },
            { "upid": "b", "status": "OK", "starttime": now - 5.0 },
            { "upid": "c", "status": "boom", "starttime": now - 100_000.0, "endtime": now - 90_000.0 },
            { "upid": "d", "status": "bang", "starttime": now - 1.0 },
        ]));
        let failed = recent_failed_tasks(&list, 24.0);
        let ids: Vec<&str> = failed.iter().map(|f| f["upid"].as_str().unwrap()).collect();
        assert_eq!(ids, ["d", "a"]);
        assert!(failed[0].as_object().unwrap().contains_key("ended"));
        assert_eq!(failed[0]["ended"], Value::Null);
    }

    #[test]
    fn ha_names_resources_and_daemons_in_trouble() {
        let ha = ha_of(&rows(json!([
            { "type": "quorum", "quorate": 1 },
            { "type": "service", "sid": "vm:100", "crm_state": "started" },
            { "type": "service", "sid": "vm:101", "state": "error", "node": "pve1" },
            { "type": "service", "sid": "vm:102", "crm_state": "freeze" },
            { "type": "lrm", "id": "pve2", "status": "old timestamp - dead?" },
            { "type": "master", "id": "pve1", "status": "active" },
        ])));
        let json = ha.to_json();
        assert_eq!(json["services"], json!(3));
        assert_eq!(json["by_state"], json!({ "started": 1, "error": 1, "freeze": 1 }));
        assert_eq!(json["quorate"], json!(true));
        assert_eq!(json["problem_services"], json!([{ "sid": "vm:101", "node": "pve1", "state": "error" }, { "sid": "vm:102", "state": "freeze" }]));
        assert_eq!(json["problem_daemons"], json!([{ "id": "pve2", "status": "old timestamp - dead?" }]));
    }

    #[test]
    fn shared_storage_is_merged_once() {
        let merged = merge_shared(rows(json!([
            { "storage": "ceph", "shared": 1, "node": "pve1", "status": "unknown" },
            { "storage": "local", "node": "pve1", "status": "available" },
            { "storage": "ceph", "shared": 1, "node": "pve2", "status": "available" },
            { "storage": "local", "node": "pve2", "status": "available" },
        ])));
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].1, ["pve1", "pve2"]);
        assert_eq!(merged[0].0["node"], json!("pve2"));
        assert_eq!(merged[1].1, ["pve1"]);
    }

    #[test]
    fn nodes_come_from_the_node_list_or_the_cluster_status() {
        let (online, offline) = node_names(&rows(json!([{ "node": "b", "status": "online" }, { "node": "a", "status": "unknown" }, { "node": "c", "status": "offline" }])), &[]);
        assert_eq!(online, ["a", "b"]);
        assert_eq!(offline, ["c"]);
        let (online, offline) = node_names(&[], &rows(json!([{ "type": "node", "name": "x" }, { "type": "node", "name": "y", "online": 0 }, { "type": "cluster" }])));
        assert_eq!(online, ["x"]);
        assert_eq!(offline, ["y"]);
    }

    #[test]
    fn reasons_are_capped_per_section() {
        let mut reasons = Map::new();
        for i in 0..12 {
            reasons.insert(format!("guest_config/{i}"), json!("forbidden: no"));
        }
        reasons.insert("acl".into(), json!("forbidden: no"));
        let out = compact_reasons(&reasons);
        assert_eq!(out.len(), 12);
        assert_eq!(out["guest_config/..."], json!("2 more with the same section not read."));
        assert!(out.contains_key("acl"));
        assert!(!out.contains_key("guest_config/10"));
    }

    #[test]
    fn report_sorts_by_severity_and_says_what_it_could_not_read() {
        let mut report = Report::default();
        report.add("info", "subscription", "node a", json!({}), "x");
        report.add("critical", "nodes", "node b", json!({}), "y");
        report.add("warning", "tasks", "tasks", json!({}), "z");
        let data = obj! { "nodes" => 1, "storage/pve1" => 2 };
        let unavailable = obj! { "storage/pve2" => "forbidden: no" };
        report.absorb(&data, &unavailable);
        let summary = report.summary(&HEALTH_SEVERITIES);
        assert_eq!(summary["complete"], json!(false));
        assert_eq!(summary["counts"], json!({ "critical": 1, "warning": 1, "info": 1 }));
        let order: Vec<&str> = summary["findings"].as_array().unwrap().iter().map(|f| f["severity"].as_str().unwrap()).collect();
        assert_eq!(order, ["critical", "warning", "info"]);
        assert_eq!(summary["checked"], json!(["nodes", "storage"]));
        assert_eq!(summary["unavailable"], json!({ "storage/pve2": "forbidden: no" }));
        let keys: Vec<&String> = summary.keys().collect();
        assert_eq!(keys, ["complete", "counts", "findings", "checked", "unavailable"]);
    }

    #[test]
    fn addresses_from_lxc_and_from_the_agent() {
        let lxc = json!([
            { "name": "lo", "inet": "127.0.0.1/8" },
            { "name": "eth0", "inet": "10.0.0.5/24", "inet6": "fe80::1/64" },
            { "name": "eth1", "inet": "10.0.0.5/24" },
        ]);
        assert_eq!(addresses_of(&lxc), ["10.0.0.5", "fe80::1"]);
        let agent = json!({ "result": [
            { "name": "lo", "ip-addresses": [{ "ip-address": "127.0.0.1" }] },
            { "name": "ens18", "ip-addresses": [{ "ip-address": "fe80::2" }, { "ip-address": "2001:db8::5" }, { "ip-address": "::1" }] },
        ] });
        assert_eq!(addresses_of(&agent), ["fe80::2", "2001:db8::5"]);
        assert_eq!(primary_address(&addresses_of(&agent)).as_deref(), Some("2001:db8::5"));
        assert_eq!(primary_address(&["169.254.1.1".into(), "FE80::1".into()]), None);
        assert_eq!(primary_address(&["2001:db8::1".into(), "192.168.1.2".into()]).as_deref(), Some("192.168.1.2"));
    }

    #[test]
    fn boot_disk_agent_and_cloud_init_from_a_vm_config() {
        let config = rows(json!([{ "boot": "order=ide2;scsi0;net0", "ide2": "local:iso/x.iso,media=cdrom", "scsi0": "local-lvm:vm-100-disk-0,size=8G", "agent": "enabled=1,fstrim_cloned_disks=1", "ide0": "local-lvm:vm-100-cloudinit,media=cdrom" }])).remove(0);
        assert_eq!(boot_disk(&config).as_deref(), Some("scsi0"));
        assert!(agent_enabled(&config));
        assert!(has_cloud_init_drive(&config));
        let legacy = rows(json!([{ "bootdisk": "virtio0", "virtio0": "local:100/disk.qcow2", "agent": 1 }])).remove(0);
        assert_eq!(boot_disk(&legacy).as_deref(), Some("virtio0"));
        assert!(agent_enabled(&legacy));
        assert!(!has_cloud_init_drive(&legacy));
        let none = rows(json!([{ "boot": "order=net0", "agent": "0,fstrim_cloned_disks=1" }])).remove(0);
        assert_eq!(boot_disk(&none), None);
        assert!(!agent_enabled(&none));
        assert!(!agent_enabled(&Map::new()));
    }

    #[test]
    fn templates_match_exactly_before_by_prefix() {
        let names: Vec<String> = ["debian-12-standard_12.7-1_amd64.tar.zst", "debian-12-turnkey.tar.gz", "debian-12"].iter().map(|s| s.to_string()).collect();
        assert_eq!(match_template(&names, "debian-12"), ["debian-12"]);
        assert_eq!(match_template(&names, "debian-12-").len(), 2);
        assert_eq!(template_basename("local:vztmpl/a.tar.zst"), "a.tar.zst");
        assert_eq!(template_basename("a.tar.zst"), "a.tar.zst");
    }

    #[test]
    fn nics_with_the_firewall_on() {
        let config = rows(json!([{ "net0": "virtio=AA,bridge=vmbr0,firewall=1", "net1": "virtio=BB,bridge=vmbr1", "netx": "firewall=1" }])).remove(0);
        assert_eq!(nics_with_firewall(&config), (2, 1));
    }

    #[test]
    fn forecast_is_a_straight_line_and_says_so() {
        let points = rows(json!([
            { "time": 0, "used": 100, "total": 1000 },
            { "time": 86400, "used": 200, "total": 1000 },
            { "time": 172800, "used": 300, "total": 1000 },
        ]));
        assert_eq!(
            forecast_storage(&points, None, "month"),
            json!({ "available": true, "method": "linear least squares on RRD averages, last month", "points": 3, "growth_bytes_per_day": 100, "days_until_full": 7, "trend": "growing", "assumption": "Extrapolates past growth in a straight line: a rough idea, not a prediction." })
        );
        let flat = rows(json!([{ "time": 1, "used": 5 }, { "time": 2, "used": 5 }, { "time": 3, "used": 5 }]));
        assert_eq!(forecast_storage(&flat, Some(10.0), "day")["trend"], json!("not_growing"));
        let few = rows(json!([{ "time": 1, "used": 5 }, { "time": 2 }]));
        assert_eq!(forecast_storage(&few, None, "day"), json!({ "available": false, "reason": "Only 1 data points in the window: at least 3 are needed." }));
        let same = rows(json!([{ "time": 1, "used": 5 }, { "time": 1, "used": 6 }, { "time": 1, "used": 7 }]));
        assert_eq!(forecast_storage(&same, None, "day")["reason"], json!("All the data points have the same time."));
        let unknown = rows(json!([{ "time": 0, "used": 1 }, { "time": 86400, "used": 2 }, { "time": 172800, "used": 3 }]));
        assert_eq!(forecast_storage(&unknown, None, "week")["reason"], json!("The total size is not known."));
    }

    #[test]
    fn audit_helpers_find_what_they_should() {
        let mut report = Report::default();
        audit_tokens(&mut report, &rows(json!([
            { "userid": "root@pam", "tokens": [{ "tokenid": "ci", "privsep": 0 }] },
            { "userid": "bob@pve", "expire": 2000000000, "tokens": [{ "tokenid": "t", "privsep": 1 }] },
        ])));
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].evidence, json!({ "without_expiry": ["root@pam!ci"] }));
        assert_eq!(report.findings[1].severity, "high");

        let mut report = Report::default();
        audit_root_tfa(&mut report, &json!([{ "type": "recovery" }, { "type": "totp", "enable": 0 }]));
        assert_eq!(report.findings[0].evidence, json!({ "entries": [{ "type": "recovery", "enable": 1 }, { "type": "totp", "enable": 0 }] }));
        let mut report = Report::default();
        audit_root_tfa(&mut report, &json!([{ "type": "webauthn" }]));
        assert!(report.findings.is_empty());

        let mut report = Report::default();
        audit_acl(&mut report, &rows(json!([
            { "path": "/", "roleid": "Administrator", "type": "user", "ugid": "bob@pve" },
            { "path": "/", "roleid": "PVEAuditor", "type": "user", "ugid": "eve@pve" },
            { "path": "/vms/100", "roleid": "PVEAdmin", "type": "group", "ugid": "ops" },
            { "path": "/", "roleid": "PVEVMAdmin", "type": "group", "ugid": "ops", "propagate": 0 },
        ])));
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].object, "user bob@pve");
        assert_eq!(report.findings[0].severity, "high");
        assert_eq!(report.findings[1].evidence["propagate"], json!(false));

        let mut report = Report::default();
        let now = now_seconds();
        audit_certificates(&mut report, "pve1", &rows(json!([
            { "filename": "gone.pem", "notafter": now - 2.0 * DAY_SECONDS },
            { "filename": "soon.pem", "notafter": now + 3.0 * DAY_SECONDS },
            { "filename": "fine.pem", "notafter": now + 300.0 * DAY_SECONDS },
            { "fingerprint": "AB:CD", "notafter": now + 1.0 * DAY_SECONDS },
        ])), 30.0);
        let objects: Vec<&str> = report.findings.iter().map(|f| f.object.as_str()).collect();
        assert_eq!(objects, ["certificate gone.pem on pve1", "certificate soon.pem on pve1", "certificate AB:CD on pve1"]);
        assert_eq!(report.findings[0].severity, "high");
        assert_eq!(report.findings[1].severity, "medium");
    }

    #[test]
    fn private_keys_are_refused() {
        assert!(assert_public_keys(Some("ssh-ed25519 AAAA user")).is_ok());
        assert!(assert_public_keys(None).is_ok());
        let err = assert_public_keys(Some("-----BEGIN OPENSSH PRIVATE KEY-----")).unwrap_err();
        assert_eq!(err.kind, kind::INVALID_INPUT);
    }

    #[test]
    fn secrets_never_come_back_even_encoded() {
        let secrets = secret_list(&[Some("p@ss word"), None, Some("")]);
        assert_eq!(secrets, ["p@ss word", "p%40ss%20word"]);
        let value = json!({ "error": "bad value 'p@ss word'", "steps": [{ "detail": "password=p%40ss%20word" }], "n": 1 });
        assert_eq!(scrub_value(&secrets, value), json!({ "error": "bad value '[REDACTED]'", "steps": [{ "detail": "password=[REDACTED]" }], "n": 1 }));
        assert_eq!(secret_list(&[Some("plain")]), ["plain"]);
        assert_eq!(scrub_value(&[], json!("p@ss word")), json!("p@ss word"));
    }

    #[test]
    fn only_passing_trouble_is_retried() {
        assert!(is_transient_guest_error(&PveError::new(kind::UPSTREAM_ERROR, "x")));
        assert!(is_transient_guest_error(&PveError::new(kind::GUEST_LOCKED, "x")));
        assert!(!is_transient_guest_error(&PveError::new(kind::FORBIDDEN, "x")));
    }
}
