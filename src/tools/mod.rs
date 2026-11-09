//! What every tool is made of, and what it gets to work with.

pub mod api;
pub mod endpoints;
pub mod info;
pub mod naming;
pub mod ssh_common;
pub mod ssh_guest;
pub mod ssh_lxc;
pub mod ssh_node;
pub mod ssh_session;
pub mod workflows;

use crate::config::{InstanceConfig, ServerConfig};
use crate::errors::{PveError, Result, kind};
use crate::obj;
use crate::proxmox::client::ProxmoxClient;
use crate::proxmox::nodes::NodeResolver;
use crate::proxmox::policy::Gate;
use crate::proxmox::tasks::{TaskResult, WaitOptions, is_upid, parse_upid, wait_for_task};
use crate::proxmox::{Api, DryRunLog, RequestOptions, UploadFile};
use crate::runtime::Runtime;
use crate::schema::{Schema, Shape, z};
use crate::ssh::ScopedSsh;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use std::future::Future;
use std::sync::{Arc, LazyLock};

pub type Args = Map<String, Value>;

/// Tools are grouped by domain and can be filtered with PROXMOX_TOOLSETS.
pub const DOMAINS: [&str; 21] = ["vm", "lxc", "node", "storage", "backup", "tasks", "cluster", "ha", "firewall", "access", "pools", "network", "disks", "sdn", "ceph", "notifications", "acme", "mapping", "ssh", "workflows", "api"];

/// Large domains that few setups use stay out of the default list, to spare the context of the agent.
pub const OPT_IN_TOOLSETS: [&str; 5] = ["sdn", "ceph", "notifications", "acme", "mapping"];

/// The client with this tool call's scope applied: dry run for writes, read-only for read tools.
#[derive(Clone)]
pub struct ScopedApi {
    client: Arc<ProxmoxClient>,
    defaults: RequestOptions,
}

fn merge(defaults: &RequestOptions, opts: RequestOptions) -> RequestOptions {
    RequestOptions {
        params: opts.params.or_else(|| defaults.params.clone()),
        path_params: opts.path_params.or_else(|| defaults.path_params.clone()),
        read_only: opts.read_only.or(defaults.read_only),
        dry_run: opts.dry_run.or(defaults.dry_run),
        dry_run_log: opts.dry_run_log.or_else(|| defaults.dry_run_log.clone()),
        timeout_ms: opts.timeout_ms.or(defaults.timeout_ms),
        include_sensitive: opts.include_sensitive || defaults.include_sensitive,
    }
}

impl ScopedApi {
    pub fn new(client: Arc<ProxmoxClient>, defaults: RequestOptions) -> Self {
        ScopedApi { client, defaults }
    }

    pub fn client(&self) -> &Arc<ProxmoxClient> {
        &self.client
    }

    pub async fn post(&self, path: &str, params: Args, opts: RequestOptions) -> Result<Value> {
        self.request("POST", path, opts.with_params(params)).await
    }

    pub async fn put(&self, path: &str, params: Args, opts: RequestOptions) -> Result<Value> {
        self.request("PUT", path, opts.with_params(params)).await
    }

    pub async fn delete(&self, path: &str, params: Option<Args>, opts: RequestOptions) -> Result<Value> {
        let opts = match params {
            Some(p) => opts.with_params(p),
            None => opts,
        };
        self.request("DELETE", path, opts).await
    }
}

impl Api for ScopedApi {
    fn request(&self, method: &str, path: &str, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
        let opts = merge(&self.defaults, opts);
        let (method, path) = (method.to_string(), path.to_string());
        async move { self.client.request_impl(&method, &path, opts).await }.boxed()
    }

    fn upload(&self, path: &str, fields: Map<String, Value>, file: UploadFile, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
        let opts = merge(&self.defaults, opts);
        let path = path.to_string();
        async move { self.client.upload_impl(&path, fields, file, opts).await }.boxed()
    }
}

/// What to do with an answer that may be a task id.
#[derive(Debug, Clone, Default)]
pub struct FinishOptions {
    /// Default true. False returns the task id straight away.
    pub wait: Option<bool>,
    /// Default PROXMOX_TASK_WAIT_SECONDS.
    pub wait_seconds: Option<u64>,
}

impl FinishOptions {
    pub fn no_wait() -> Self {
        FinishOptions { wait: Some(false), wait_seconds: None }
    }

    /// From the wait and wait_seconds arguments of a tool.
    pub fn from_args(args: &Args) -> Self {
        FinishOptions { wait: args.get("wait").and_then(Value::as_bool), wait_seconds: args.get("wait_seconds").and_then(Value::as_f64).map(|n| n as u64) }
    }
}

/// Task helpers bound to this tool call's API scope.
#[derive(Clone)]
pub struct TaskHelper {
    api: ScopedApi,
    default_wait_seconds: u64,
}

impl TaskHelper {
    pub fn new(api: ScopedApi, default_wait_seconds: u64) -> Self {
        TaskHelper { api, default_wait_seconds }
    }

    pub fn default_wait_seconds(&self) -> u64 {
        self.default_wait_seconds
    }

    /// Waits for a UPID. Fails with task_failed, or task_timeout when it is still running.
    pub async fn wait(&self, upid: &str, opts: WaitOptions) -> Result<TaskResult> {
        let opts = WaitOptions { timeout_ms: opts.timeout_ms.or(Some(self.default_wait_seconds * 1000)), ..opts };
        wait_for_task(&self.api, upid, &opts).await
    }

    /// Turns the answer of a write into a tool result. A UPID is waited for: a failed task
    /// fails, and one that outlasts the delay comes back as still running, which is not an
    /// error. Anything else is returned as it is.
    pub async fn finish(&self, value: Value, opts: FinishOptions) -> Result<Args> {
        if !is_upid(Some(&value)) {
            return Ok(as_object(value));
        }
        let upid = value.as_str().unwrap().to_string();
        let node = parse_upid(&upid)?.node;
        if opts.wait == Some(false) {
            return Ok(obj! { "task" => &upid, "node" => &node, "next_step" => "pve_wait_task" });
        }
        let seconds = opts.wait_seconds.unwrap_or(self.default_wait_seconds);
        match wait_for_task(&self.api, &upid, &WaitOptions { timeout_ms: Some(seconds * 1000), ..Default::default() }).await {
            Ok(result) => Ok(match result.to_json() {
                Value::Object(m) => m,
                _ => unreachable!(),
            }),
            Err(e) if e.kind == kind::TASK_TIMEOUT => Ok(obj! { "task" => &upid, "node" => &node, "still_running" => true, "next_step" => "pve_wait_task" }),
            Err(e) => Err(e),
        }
    }
}

/// A tool result is always an object.
pub fn as_object(value: Value) -> Args {
    match value {
        Value::Object(m) => m,
        Value::Array(rows) => {
            let count = rows.len();
            obj! { "rows" => Value::Array(rows), "count" => count }
        }
        Value::Null => obj! { "ok" => true },
        other => obj! { "result" => other },
    }
}

pub struct ToolContext {
    pub api: ScopedApi,
    pub instance: Arc<InstanceConfig>,
    pub server: Arc<ServerConfig>,
    pub dry_run: bool,
    pub dry_run_log: DryRunLog,
    pub tasks: TaskHelper,
    pub nodes: Arc<NodeResolver>,
    pub ssh: ScopedSsh,
    pub runtime: Arc<Runtime>,
}

pub type ArgFn<T> = Arc<dyn Fn(&Args) -> T + Send + Sync>;
pub type Handler = Arc<dyn Fn(Args, Arc<ToolContext>) -> BoxFuture<'static, Result<Value>> + Send + Sync>;

#[derive(Clone)]
pub struct ToolDef {
    pub name: String,
    pub title: String,
    pub description: String,
    pub domain: &'static str,
    /// What the instance must allow for this tool to appear and to run.
    pub gate: Gate,
    /// A higher gate for these arguments: refused before anyone is asked. The client enforces it anyway.
    pub gate_when: Option<ArgFn<Option<Gate>>>,
    /// Says what raised the gate, in the refusal.
    pub gate_note: Option<ArgFn<Option<String>>>,
    /// The handler gets the arguments the schema does not list, and deals with them itself.
    pub accepts_extra_args: bool,
    /// Refuses bad arguments the schema cannot judge, before anyone is asked to confirm them.
    pub check_args: Option<ArgFn<Result<()>>>,
    /// Masks what the name of an argument does not say is secret, for the audit log and the question to a human.
    pub redact_args: Option<ArgFn<Args>>,
    /// Asks a human first when the client can, and announces destructiveHint.
    pub destructive: bool,
    /// Same, but depending on the arguments: force=1 on a guest create.
    pub destructive_when: Option<ArgFn<bool>>,
    /// Announces readOnlyHint, takes no dry_run, and any write it tries is refused. Default: from the gate.
    pub read_only: Option<bool>,
    pub idempotent: bool,
    /// The tool reaches beyond Proxmox itself.
    pub open_world: bool,
    /// Other domains that need this tool, for PROXMOX_TOOLSETS.
    pub also: Vec<&'static str>,
    pub input: Shape,
    /// Message for the human, for a destructive tool whose client supports elicitation.
    pub confirmation: Option<ArgFn<String>>,
    pub handler: Handler,
}

impl ToolDef {
    pub fn new(name: &str, title: &str, domain: &'static str, gate: Gate, description: impl Into<String>) -> Self {
        ToolDef {
            name: name.to_string(),
            title: title.to_string(),
            description: description.into(),
            domain,
            gate,
            gate_when: None,
            gate_note: None,
            accepts_extra_args: false,
            check_args: None,
            redact_args: None,
            destructive: false,
            destructive_when: None,
            read_only: None,
            idempotent: false,
            open_world: false,
            also: Vec::new(),
            input: Vec::new(),
            confirmation: None,
            handler: Arc::new(|_, _| async { Err(PveError::internal("no handler")) }.boxed()),
        }
    }

    pub fn input(mut self, shape: Shape) -> Self {
        self.input = shape;
        self
    }

    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    pub fn open_world(mut self) -> Self {
        self.open_world = true;
        self
    }

    pub fn read_only(mut self, value: bool) -> Self {
        self.read_only = Some(value);
        self
    }

    pub fn also(mut self, domains: &[&'static str]) -> Self {
        self.also = domains.to_vec();
        self
    }

    pub fn accepts_extra_args(mut self) -> Self {
        self.accepts_extra_args = true;
        self
    }

    pub fn gate_when(mut self, f: impl Fn(&Args) -> Option<Gate> + Send + Sync + 'static) -> Self {
        self.gate_when = Some(Arc::new(f));
        self
    }

    pub fn gate_note(mut self, f: impl Fn(&Args) -> Option<String> + Send + Sync + 'static) -> Self {
        self.gate_note = Some(Arc::new(f));
        self
    }

    pub fn check_args(mut self, f: impl Fn(&Args) -> Result<()> + Send + Sync + 'static) -> Self {
        self.check_args = Some(Arc::new(f));
        self
    }

    pub fn redact_args(mut self, f: impl Fn(&Args) -> Args + Send + Sync + 'static) -> Self {
        self.redact_args = Some(Arc::new(f));
        self
    }

    pub fn destructive_when(mut self, f: impl Fn(&Args) -> bool + Send + Sync + 'static) -> Self {
        self.destructive_when = Some(Arc::new(f));
        self
    }

    pub fn confirmation(mut self, f: impl Fn(&Args) -> String + Send + Sync + 'static) -> Self {
        self.confirmation = Some(Arc::new(f));
        self
    }

    /// The work. Return an object; anything else is wrapped as {result: value}.
    pub fn handler<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Args, Arc<ToolContext>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        self.handler = Arc::new(move |args, ctx| f(args, ctx).boxed());
        self
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.unwrap_or(matches!(self.gate, Gate::Read | Gate::Sensitive | Gate::SshRead))
    }
}

/// The result shape of every listing: render_result can cut it and say where to go on.
pub fn page_rows(rows: Vec<Value>, limit: Option<usize>, offset: Option<usize>) -> Args {
    let total = rows.len();
    let start = offset.unwrap_or(0);
    let page: Vec<Value> = match limit {
        None => rows.into_iter().skip(start).collect(),
        Some(limit) => rows.into_iter().skip(start).take(limit).collect(),
    };
    let count = page.len();
    let end = start.min(total) + count;
    let has_more = end < total;
    let mut out = obj! { "rows" => Value::Array(page), "total" => total, "count" => count, "offset" => start, "has_more" => has_more };
    if has_more {
        out.insert("next_offset".into(), Value::from(end));
    }
    out
}

/// The page_limit and page_offset arguments, as numbers.
pub fn paging_args(args: &Args) -> (Option<usize>, Option<usize>) {
    (args.get("page_limit").and_then(Value::as_f64).map(|n| n as usize), args.get("page_offset").and_then(Value::as_f64).map(|n| n as usize))
}

pub fn page_limit() -> Schema {
    z::int().min(1).max(10_000).optional().describe("Rows per page. Default: as many as fit in the answer.")
}

pub fn page_offset() -> Schema {
    z::int().min(0).optional().describe("Rows to skip. Use next_offset from the previous page.")
}

pub fn vmid() -> Schema {
    z::int().min(1).max(999_999_999).describe("The guest id.")
}

pub fn node_name() -> Schema {
    z::string().regex(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*$", "Expected a node name").max(64)
}

/// A boxed source for gather.
pub type Source<'a> = (&'a str, BoxFuture<'a, Result<Value>>);

/// Reads several endpoints where each may be missing or forbidden, and reports which ones were.
pub async fn gather(sources: Vec<Source<'_>>) -> (Args, Args) {
    let (names, futures): (Vec<&str>, Vec<_>) = sources.into_iter().unzip();
    let results = futures::future::join_all(futures).await;
    let mut data = Map::new();
    let mut unavailable = Map::new();
    for (name, result) in names.into_iter().zip(results) {
        match result {
            Ok(v) => {
                data.insert(name.to_string(), v);
            }
            Err(e) => {
                unavailable.insert(name.to_string(), Value::String(e.reason()));
            }
        }
    }
    (data, unavailable)
}

/// Convenient access to arguments, already checked against the schema.
pub trait ArgsExt {
    fn str(&self, key: &str) -> Option<&str>;
    fn string(&self, key: &str) -> Option<String>;
    fn i64(&self, key: &str) -> Option<i64>;
    fn u64(&self, key: &str) -> Option<u64>;
    fn f64(&self, key: &str) -> Option<f64>;
    fn bool(&self, key: &str) -> Option<bool>;
    fn flag(&self, key: &str) -> bool;
    fn strings(&self, key: &str) -> Option<Vec<String>>;
    fn object(&self, key: &str) -> Option<&Map<String, Value>>;
    fn has(&self, key: &str) -> bool;
}

impl ArgsExt for Args {
    fn str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }
    fn string(&self, key: &str) -> Option<String> {
        self.str(key).map(str::to_string)
    }
    fn i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(Value::as_f64).map(|n| n as i64)
    }
    fn u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(Value::as_f64).map(|n| n as u64)
    }
    fn f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(Value::as_f64)
    }
    fn bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(Value::as_bool)
    }
    fn flag(&self, key: &str) -> bool {
        self.bool(key) == Some(true)
    }
    fn strings(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
    }
    fn object(&self, key: &str) -> Option<&Map<String, Value>> {
        self.get(key).and_then(Value::as_object)
    }
    fn has(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| !v.is_null())
    }
}

/// Every tool: one per API method, then what the API alone does not offer. Built once.
pub static ALL_TOOLS: LazyLock<Vec<Arc<ToolDef>>> = LazyLock::new(|| {
    let mut all = Vec::new();
    all.extend(info::info_tools());
    all.extend(workflows::workflow_tools());
    all.extend(endpoints::endpoint_tools());
    all.extend(ssh_node::ssh_node_tools());
    all.extend(ssh_lxc::ssh_lxc_tools());
    all.extend(ssh_guest::ssh_guest_tools());
    all.extend(ssh_session::ssh_session_tools());
    all.extend(api::api_tools());
    all.into_iter().map(Arc::new).collect()
});

/// Checks tool definitions against reference/all.tools.json, which the TypeScript version wrote with
/// every toolset and gate on and a single instance. Key order does not count, the rest does.
#[cfg(test)]
pub mod reference {
    use super::ToolDef;
    use serde_json::{Value, json};

    pub fn tool_json(def: &ToolDef) -> Value {
        let mut input = def.input.clone();
        if !def.is_read_only() {
            input.push(("dry_run".into(), crate::schema::z::boolean().optional().describe("Show what would be sent without sending anything.")));
        }
        json!({
            "name": def.name,
            "title": def.title,
            "description": def.description,
            "inputSchema": crate::schema::tool_input_schema(&input, def.accepts_extra_args),
            "annotations": {
                "title": def.title,
                "readOnlyHint": def.is_read_only(),
                "destructiveHint": def.destructive || def.destructive_when.is_some(),
                "idempotentHint": def.idempotent,
                "openWorldHint": def.open_world,
            },
            "execution": { "taskSupport": "forbidden" },
        })
    }

    fn load() -> Vec<Value> {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/all.tools.json")).expect("reference/all.tools.json");
        let v: Value = serde_json::from_str(&text).unwrap();
        v.get("tools").cloned().unwrap_or(v).as_array().unwrap().clone()
    }

    /// Where two values differ, as paths; empty when they are the same.
    pub fn diff(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for (k, v) in x {
                    match y.get(k) {
                        Some(w) => diff(v, w, &format!("{path}.{k}"), out),
                        None => out.push(format!("{path}.{k}: only in Rust ({v})")),
                    }
                }
                for (k, w) in y {
                    if !x.contains_key(k) {
                        out.push(format!("{path}.{k}: only in TypeScript ({w})"));
                    }
                }
            }
            (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
                for (i, (v, w)) in x.iter().zip(y).enumerate() {
                    diff(v, w, &format!("{path}[{i}]"), out);
                }
            }
            (Value::Number(x), Value::Number(y)) if x.as_f64() == y.as_f64() => {}
            _ if a == b => {}
            _ => out.push(format!("{path}: Rust {a} / TypeScript {b}")),
        }
    }

    /// Panics with every difference, for each of these tools.
    pub fn assert_matches(defs: &[ToolDef]) {
        let reference = load();
        let mut problems = Vec::new();
        for def in defs {
            match reference.iter().find(|t| t["name"] == def.name.as_str()) {
                None => problems.push(format!("{}: not in the reference", def.name)),
                Some(want) => diff(&tool_json(def), want, &def.name, &mut problems),
            }
        }
        assert!(problems.is_empty(), "{} differences:\n{}", problems.len(), problems.join("\n"));
    }
}
