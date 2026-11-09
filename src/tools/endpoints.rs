//! Every API method becomes a tool, generated from the catalog at startup. What cannot be one
//! is listed here with the reason. Those methods stay reachable through pve_api_write only if
//! the operator lists them in PROXMOX_UNBLOCK, where the policy blocks them.

use super::naming::{domain_of, tool_name};
use super::{Args, ArgsExt, FinishOptions, ToolContext, ToolDef, as_object, node_name, page_rows};
use crate::catalog::{CATALOG, CatalogEndpoint, CatalogParam, template_params};
use crate::errors::{PveError, Result};
use crate::js::{js_slice_start, js_string};
use crate::obj;
use crate::proxmox::localpath::resolve_local_path;
use crate::proxmox::nodes::GuestLocation;
use crate::proxmox::params::{indexed_name, is_indexed_param};
use crate::proxmox::policy::{Gate, classify, describe_host_access, destructive_args, has_destructive_args, host_access_arg, host_access_params};
use crate::proxmox::redact::redact_request;
use crate::proxmox::{Api, RequestOptions, UploadFile};
use crate::schema::{Schema, Shape, z};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

pub const EXCLUDED_ENDPOINTS: &[(&str, &str)] = &[
    ("GET /nodes/{node}/vncwebsocket", "Websocket console: a tool call cannot hold it."),
    ("GET /nodes/{node}/qemu/{vmid}/vncwebsocket", "Websocket console: a tool call cannot hold it."),
    ("GET /nodes/{node}/lxc/{vmid}/vncwebsocket", "Websocket console: a tool call cannot hold it."),
    ("GET /nodes/{node}/qemu/{vmid}/mtunnelwebsocket", "Migration tunnel, internal to remote_migrate."),
    ("GET /nodes/{node}/lxc/{vmid}/mtunnelwebsocket", "Migration tunnel, internal to remote_migrate."),
    ("POST /nodes/{node}/qemu/{vmid}/mtunnel", "Migration tunnel, internal to remote_migrate."),
    ("POST /nodes/{node}/lxc/{vmid}/mtunnel", "Migration tunnel, internal to remote_migrate."),
    ("POST /nodes/{node}/execute", "Runs a batch of API calls, which would bypass the policy."),
    ("GET /access/ticket", "Dummy endpoint for the login form: authentication is handled by the client."),
    ("POST /access/ticket", "Authentication is handled by the client."),
    ("POST /access/openid/login", "Interactive browser login."),
    ("POST /nodes/{node}/storage/{storage}/upload", "Needs a multipart body: pve_upload_to_storage is the tool for it."),
];

pub fn excluded(method: &str, path: &str) -> Option<&'static str> {
    let key = format!("{method} {path}");
    EXCLUDED_ENDPOINTS.iter().find(|(k, _)| *k == key).map(|(_, why)| *why)
}

pub const UPLOAD_ENDPOINT: &str = "POST /nodes/{node}/storage/{storage}/upload";

const PATH_VALUE_MAX: usize = 512;
const RESERVED: &[&str] = &["instance", "dry_run", "wait", "wait_seconds", "page_limit", "page_offset"];
/// Arguments of the tool rather than of the API: never sent, even on an endpoint that does not use them.
const SERVER_ARGS: &[&str] = &["wait", "wait_seconds", "page_limit", "page_offset"];

fn rx(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

/// PUT is idempotent on paper. These are not: the second call does something again or fails.
static NOT_IDEMPOTENT_PUT: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"/(?:sendkey|resize|wipedisk|unlink)$|^/nodes/\{node\}/network$|^/cluster/sdn$|/certificates/acme/certificate$|/apt/repositories$|^/access/users/\{userid\}/token/\{tokenid\}$")
});

/// What makes the node talk to something outside the cluster.
static OPEN_WORLD: LazyLock<Regex> = LazyLock::new(|| {
    let parts = [
        r"/nodes/\{node\}/storage/\{storage\}/(?:download-url|oci-registry-pull)",
        r"/nodes/\{node\}/aplinfo",
        r"/nodes/\{node\}/query-(?:url-metadata|oci-repo-tags)",
        r"/nodes/\{node\}/scan/(?:cifs|iscsi|nfs|pbs)",
        r"/nodes/\{node\}/apt/(?:update|changelog)",
        r"/nodes/\{node\}/subscription",
        r"/nodes/\{node\}/certificates/acme/certificate",
        r"/nodes/\{node\}/(?:qemu|lxc)/\{vmid\}/remote_migrate",
        r"/cluster/acme/(?:meta|tos|account(?:/\{name\})?)",
        r"/cluster/notifications/targets/\{name\}/test",
        r"/access/domains/\{realm\}/sync",
    ];
    rx(&format!("^(?:{})$", parts.join("|")))
});

static BOOL_TRUE: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)^\s*(?:1|true|yes|on)\s*$"));
static BOOL_FALSE: LazyLock<Regex> = LazyLock::new(|| rx(r"(?i)^\s*(?:0|false|no|off)\s*$"));
static NUMERIC: LazyLock<Regex> = LazyLock::new(|| rx(r"^\s*[+-]?\d+(?:\.\d+)?\s*$"));
static LIST_SPLIT: LazyLock<Regex> = LazyLock::new(|| rx(r"[,;\s]+"));
static FLAT_INDEXED: LazyLock<Regex> = LazyLock::new(|| rx(r"^(.+?)\[?(\d+)\]?$"));
static ROOT_PAM: LazyLock<Regex> = LazyLock::new(|| rx(r"root@pam"));

/*
 * What a caller may send for a value. Proxmox reads all of its parameters from text, so it takes
 * 1, "1", true, on and yes for a boolean, and "2048" and 2048 alike for a number or a string.
 * Anything these do not recognise goes through as it is, and fails on the schema behind them.
 */
pub fn to_boolean(value: Value) -> Value {
    match &value {
        Value::Number(n) if n.as_f64() == Some(1.0) => Value::Bool(true),
        Value::Number(n) if n.as_f64() == Some(0.0) => Value::Bool(false),
        Value::String(s) if BOOL_TRUE.is_match(s) => Value::Bool(true),
        Value::String(s) if BOOL_FALSE.is_match(s) => Value::Bool(false),
        _ => value,
    }
}

pub fn to_number(value: Value) -> Value {
    let Value::String(s) = &value else { return value };
    if !NUMERIC.is_match(s) {
        return value;
    }
    match crate::js::js_number_str(s) {
        Some(n) if n.trunc().abs() <= crate::schema::SAFE_INTEGER => crate::js::num(n),
        _ => value,
    }
}

pub fn to_text(value: Value) -> Value {
    match value {
        Value::Number(_) => Value::String(js_string(&value)),
        Value::Bool(b) => Value::String(if b { "1" } else { "0" }.into()),
        other => other,
    }
}

/// Not .int(): that writes the limits of a double into the schema of every whole number of 680 tools.
fn whole_number(minimum: Option<f64>, maximum: Option<f64>) -> Schema {
    let mut n = z::whole();
    if let Some(m) = minimum {
        n = n.min(m);
    }
    if let Some(m) = maximum {
        n = n.max(m);
    }
    n
}

fn flexible_boolean() -> Schema {
    z::boolean().preprocess(to_boolean)
}

fn flexible_whole(minimum: Option<f64>, maximum: Option<f64>) -> Schema {
    whole_number(minimum, maximum).preprocess(to_number)
}

fn wait_args() -> Shape {
    vec![
        ("wait".into(), flexible_boolean().optional().describe("If the call starts a task, wait for its end (default true). A failed task is reported as an error.")),
        ("wait_seconds".into(), flexible_whole(Some(0.0), Some(3600.0)).optional().describe("How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30). Past this it keeps running: see pve_wait_task.")),
    ]
}

fn trim_description(text: Option<&str>, fallback: &str) -> String {
    match text.map(str::trim) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => fallback.to_string(),
    }
}

/// Description of one parameter: the schema's text plus what zod cannot say.
fn param_description(api_name: &str, param: &CatalogParam) -> String {
    let mut parts = vec![trim_description(param.description.as_deref(), api_name)];
    if let Some(d) = &param.default {
        parts.push(format!("Default: {}.", js_string(d)));
    }
    if let Some(t) = &param.typetext {
        if !param.property_string && crate::js::js_len(t) <= 120 {
            parts.push(format!("Format: {t}."));
        }
    }
    if let Some(p) = &param.pattern {
        parts.push(format!("Pattern: {p}"));
    }
    if let Some(r) = &param.requires {
        parts.push(format!("Needs {r}."));
    }
    if let Some(types) = &param.instance_types {
        parts.push(format!("Only for {}: {}.", param.type_property.as_deref().unwrap_or("type"), types.join(", ")));
    }
    parts.join(" ")
}

fn schema_for(api_name: &str, param: &CatalogParam) -> Schema {
    let description = param_description(api_name, param);
    match param.kind.as_str() {
        "boolean" => flexible_boolean().describe(description),
        "integer" | "number" => {
            let allowed = param.enum_values.as_ref().map(|e| format!(" One of: {}.", e.join(", "))).unwrap_or_default();
            if param.kind == "integer" {
                return flexible_whole(param.minimum, param.maximum).describe(format!("{description}{allowed}"));
            }
            let mut n = z::number();
            if let Some(m) = param.minimum {
                n = n.min(m);
            }
            if let Some(m) = param.maximum {
                n = n.max(m);
            }
            n.preprocess(to_number).describe(format!("{description}{allowed}"))
        }
        "array" => {
            let whole = param.items.as_ref().is_some_and(|i| i.kind == "integer");
            let choices = param.items.as_ref().and_then(|i| i.enum_values.clone()).filter(|c| !c.is_empty());
            let item = if whole {
                flexible_whole(None, None)
            } else {
                match &choices {
                    Some(c) => z::enumeration(c).preprocess(to_text),
                    None => z::string().preprocess(to_text),
                }
            };
            // Sent as repeated parameters. A list of ids is often written 100,101, and a single value as such.
            z::array(item)
                .preprocess(move |value| match value {
                    Value::Array(_) | Value::Null => value,
                    Value::String(s) if whole => Value::Array(LIST_SPLIT.split(&s).filter(|p| !p.is_empty()).map(|p| Value::String(p.to_string())).collect()),
                    other => Value::Array(vec![other]),
                })
                .describe(description)
        }
        _ => {
            if let Some(values) = param.enum_values.as_ref().filter(|e| !e.is_empty()) {
                return z::enumeration(values).preprocess(to_text).describe(description);
            }
            let mut s = z::string();
            if let Some(m) = param.min_length {
                s = s.min(m);
            }
            if let Some(m) = param.max_length {
                s = s.max(m);
            }
            s.preprocess(to_text).describe(description)
        }
    }
}

/// Why a node may be left out, if it may. Only where it says which node should do the work.
fn optional_node(name: &str, template: &str, path_names: &[String]) -> Option<&'static str> {
    if name != "node" || !template.starts_with("/nodes/{node}") {
        return None;
    }
    Some(if path_names.iter().any(|n| n == "vmid") { "Optional: found from the vmid when left out." } else { "Optional when there is a default node or only one node." })
}

fn path_param_schema(name: &str, declared: Option<&CatalogParam>, optional_because: Option<&str>) -> Schema {
    if name == "node" {
        let schema = node_name().preprocess(to_text).describe(format!("The cluster node name.{}", optional_because.map(|b| format!(" {b}")).unwrap_or_default()));
        return if optional_because.is_some() { schema.optional() } else { schema };
    }
    if let Some(d) = declared {
        if d.kind == "integer" {
            return flexible_whole(d.minimum, d.maximum).describe(trim_description(d.description.as_deref(), name));
        }
        if let Some(values) = d.enum_values.as_ref().filter(|e| !e.is_empty()) {
            return z::enumeration(values).preprocess(to_text).describe(trim_description(d.description.as_deref(), name));
        }
    }
    let s = z::string().min(1).max(PATH_VALUE_MAX as f64).regex(r"^[^\u0000-\u001f]+$", "Control characters are not allowed");
    let format = declared.and_then(|d| d.typetext.as_ref()).filter(|t| crate::js::js_len(t) < 80).map(|t| format!(" Format: {t}.")).unwrap_or_default();
    s.preprocess(to_text).describe(format!("{}{format}", trim_description(declared.and_then(|d| d.description.as_deref()), &format!("The {name} from the path."))))
}

struct GeneratedInput {
    input: Shape,
    /// Tool argument name to API parameter, for those that differ.
    indexed: HashMap<String, String>,
    path_names: Vec<String>,
    paged: bool,
    waits: bool,
}

fn build_input(endpoint: &CatalogEndpoint) -> GeneratedInput {
    let (method, path, params) = (&endpoint.method, &endpoint.path, &endpoint.params);
    let path_names = template_params(path);
    let mut input: Shape = Vec::new();
    let mut indexed = HashMap::new();
    for name in &path_names {
        input.push((name.clone(), path_param_schema(name, params.get(name), optional_node(name, path, &path_names))));
    }
    for (api_name, param) in params {
        if path_names.contains(api_name) {
            continue;
        }
        assert!(!RESERVED.contains(&api_name.as_str()), "{method} {path}: parameter {api_name} collides with a server parameter.");
        if is_indexed_param(api_name) {
            let name = indexed_name(api_name, |n| params.contains_key(n));
            indexed.insert(name.clone(), api_name.clone());
            let example = if api_name == "net[n]" { r#"{"0": "virtio,bridge=vmbr0"}"# } else { r#"{"0": "..."}"# };
            let base = &api_name[..api_name.len() - 3];
            let schema = z::map_of(z::string().preprocess(to_text), Some((r"^\d+$", "Expected a number as the key, such as \"0\"")))
                .optional()
                .describe(format!("{} Numbered items, such as {example}: key 0 is {base}0 in Proxmox, and {base}0 is also accepted as an argument.", trim_description(param.description.as_deref(), api_name)));
            input.push((name, schema));
            continue;
        }
        let schema = schema_for(api_name, param);
        input.push((api_name.clone(), if param.optional { schema.optional() } else { schema }));
    }
    // Also next to the native start and limit of some endpoints: an answer cut to size says to go on with page_offset.
    let paged = method == "GET" && endpoint.returns.kind == "array";
    if paged {
        input.push(("page_limit".into(), super::page_limit().preprocess(to_number)));
        input.push(("page_offset".into(), super::page_offset().preprocess(to_number)));
    }
    let waits = method != "GET" && endpoint.returns.kind == "string";
    if waits {
        input.extend(wait_args());
    }
    GeneratedInput { input, indexed, path_names, paged, waits }
}

fn describe_endpoint(endpoint: &CatalogEndpoint, gate: Gate, destructive: bool, returns_secret: bool, conditional: bool) -> String {
    let mut facts = vec![format!("{} {}", endpoint.method, endpoint.path)];
    if let Some(p) = &endpoint.permissions {
        let shown = if crate::js::js_len(p) > 220 {
            // lastIndexOf(' ', 220): the space may be at 220 itself.
            let head = js_slice_start(p, 221);
            match head.rfind(' ') {
                Some(cut) => format!("{} ...", &p[..cut]),
                // -1: slice(0, -1) drops the last character.
                None => format!("{} ...", &p[..p.char_indices().last().map_or(0, |(i, _)| i)]),
            }
        } else {
            p.clone()
        };
        facts.push(format!("Needs: {shown}"));
    }
    if ROOT_PAM.is_match(&format!("{} {}", endpoint.description, endpoint.permissions.as_deref().unwrap_or(""))) {
        facts.push("Requires root@pam".into());
    }
    if destructive {
        facts.push("Destructive".into());
    } else if conditional {
        facts.push("Destructive with some argument values".into());
    }
    let host_access = host_access_params(|p| endpoint.params.contains_key(p), &endpoint.method, &endpoint.path);
    if gate == Gate::Write && !host_access.is_empty() {
        facts.push(format!("These reach the host itself and need PROXMOX_ALLOW_ELEVATED: {}", host_access.join(", ")));
    }
    if endpoint.method == "POST" && endpoint.path == "/nodes/{node}/lxc" {
        facts.push("Pass unprivileged=1: left out, Proxmox creates a privileged container, which counts as host access".into());
    }
    if returns_secret {
        facts.push("The secret in the answer is only shown with PROXMOX_ALLOW_SENSITIVE=true: otherwise it is lost".into());
    }
    format!("{} [{}.]", trim_description(Some(&endpoint.description), &endpoint.name), facts.join(". "))
}

fn title_of(name: &str) -> String {
    let words: Vec<&str> = name.strip_prefix("pve_").unwrap_or(name).split('_').collect();
    words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if i == 0 {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn assert_guest_type(endpoint: &CatalogEndpoint, guest: &GuestLocation) -> Result<()> {
    let wanted = if endpoint.path.starts_with("/nodes/{node}/qemu") {
        Some("qemu")
    } else if endpoint.path.starts_with("/nodes/{node}/lxc") {
        Some("lxc")
    } else {
        None
    };
    if let Some(wanted) = wanted {
        if wanted != guest.kind {
            let is = if guest.kind == "lxc" { "a container" } else { "a VM" };
            let for_ = if wanted == "lxc" { "containers" } else { "VMs" };
            return Err(PveError::invalid(format!("Guest {} is {is}, and this tool is for {for_}.", guest.vmid)).hint(format!("Use the matching tool for {}.", if guest.kind == "lxc" { "lxc" } else { "vm" })));
        }
    }
    Ok(())
}

async fn resolve_node(endpoint: &CatalogEndpoint, args: &Args, path_names: &[String], ctx: &ToolContext) -> Result<Option<String>> {
    if !path_names.iter().any(|n| n == "node") {
        return Ok(None);
    }
    let given = args.string("node");
    if !endpoint.path.starts_with("/nodes/{node}") {
        return Ok(given);
    }
    if let (Some(vmid), true) = (args.get("vmid").and_then(Value::as_f64), path_names.iter().any(|n| n == "vmid")) {
        if given.is_some() {
            return Ok(given);
        }
        let guest = ctx.nodes.resolve_guest(vmid as i64).await?;
        assert_guest_type(endpoint, &guest)?;
        return Ok(Some(guest.node));
    }
    match given {
        Some(n) => Ok(Some(n)),
        None => Ok(Some(ctx.nodes.default_node().await?)),
    }
}

/// A spelling of an argument that differs only by dashes, underscores or case.
fn nearest_argument<'a>(key: &str, known: impl IntoIterator<Item = &'a String>) -> Option<&'a String> {
    let plain = |t: &str| t.replace(['-', '_'], "").to_lowercase();
    known.into_iter().find(|name| plain(name) == plain(key))
}

/// net0, or net[0], for the parameter net[n]: this is how Proxmox writes them.
fn flat_indexed_name(key: &str, endpoint: &CatalogEndpoint) -> Option<String> {
    let m = FLAT_INDEXED.captures(key)?;
    endpoint.params.contains_key(&format!("{}[n]", &m[1])).then(|| format!("{}{}", &m[1], &m[2]))
}

struct Generated {
    endpoint: &'static CatalogEndpoint,
    name: String,
    indexed: HashMap<String, String>,
    path_names: Vec<String>,
    known: Vec<String>,
}

impl Generated {
    /// The parameters of the API call, from the arguments of the tool. Refuses what it does not know.
    fn api_params(&self, args: &Args) -> Result<Args> {
        let mut params = Map::new();
        let mut unknown = Vec::new();
        for (key, value) in args {
            if self.path_names.contains(key) || SERVER_ARGS.contains(&key.as_str()) {
                continue;
            }
            if let Some(api_name) = self.indexed.get(key) {
                // Spelled out here: numa[n] sits next to a plain numa on VM configs.
                if let Value::Object(items) = value {
                    for (index, item) in items {
                        params.insert(format!("{}{index}", &api_name[..api_name.len() - 3]), item.clone());
                    }
                }
            } else if self.known.contains(key) {
                params.insert(key.clone(), value.clone());
            } else {
                match flat_indexed_name(key, self.endpoint) {
                    None => unknown.push(key.clone()),
                    Some(_) if value.is_object() || value.is_array() || value.is_null() => {
                        return Err(PveError::invalid(format!("{}: \"{key}\" takes a string, such as a property string: virtio,bridge=vmbr0.", self.name)));
                    }
                    Some(wire) => {
                        params.insert(wire, to_text(value.clone()));
                    }
                }
            }
        }
        if !unknown.is_empty() {
            let near: String = unknown.iter().filter_map(|k| nearest_argument(k, &self.known).map(|m| format!("For \"{k}\", use \"{m}\". "))).collect();
            return Err(PveError::invalid(format!("{} has no argument {}: nothing was sent.", self.name, unknown.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ")))
                .hint(format!("{near}The schema of the tool lists its arguments.")));
        }
        Ok(params)
    }
}

fn generate(endpoint: &'static CatalogEndpoint) -> ToolDef {
    let (method, path) = (endpoint.method.clone(), endpoint.path.clone());
    let GeneratedInput { input, indexed, path_names, paged, waits } = build_input(endpoint);
    let name = tool_name(&method, &path);
    // Path values are irrelevant to classification: every rule works on the template.
    let placeholders: Map<String, Value> = path_names.iter().map(|n| (n.clone(), Value::String("x".into()))).collect();
    let decision = classify(&method, &path, Some(&placeholders)).expect("catalog paths classify");
    let domain = domain_of(&path);
    let conditional = has_destructive_args(|p| endpoint.params.contains_key(p), &method, &path);
    let known: Vec<String> = input.iter().map(|(k, _)| k.clone()).collect();
    let generated = Arc::new(Generated { endpoint, name: name.clone(), indexed, path_names, known });

    let mut def = ToolDef::new(&name, &title_of(&name), domain.domain, decision.gate, describe_endpoint(endpoint, decision.gate, decision.destructive, decision.returns_secret, conditional));
    if let Some(also) = domain.also {
        def.also = also;
    }
    if decision.gate == Gate::Write && !host_access_params(|p| endpoint.params.contains_key(p), &method, &path).is_empty() {
        let (m1, p1, m2, p2, n2) = (method.clone(), path.clone(), method.clone(), path.clone(), name.clone());
        def = def
            .gate_when(move |args| host_access_arg(&m1, Some(&p1), Some(args)).map(|_| Gate::Elevated))
            .gate_note(move |args| host_access_arg(&m2, Some(&p2), Some(args)).map(|arg| describe_host_access(&n2, arg)));
    }
    def.destructive = decision.destructive;
    if conditional {
        let (m, p) = (method.clone(), path.clone());
        def = def.destructive_when(move |args| destructive_args(&m, &p, args));
    }
    def.read_only = Some(method == "GET");
    def.idempotent = method == "GET" || method == "DELETE" || (method == "PUT" && !NOT_IDEMPOTENT_PUT.is_match(&path));
    def.open_world = OPEN_WORLD.is_match(&path);
    def.accepts_extra_args = true;
    let redact_path = path.clone();
    def = def.redact_args(move |args| match redact_request(&redact_path, &Value::Object(args.clone())) {
        Value::Object(m) => m,
        _ => Map::new(),
    });
    def.input = input;
    let checker = generated.clone();
    def = def.check_args(move |args| checker.api_params(args).map(|_| ()));
    def.handler(move |args, ctx| {
        let g = generated.clone();
        let (method, path) = (method.clone(), path.clone());
        async move {
            let mut path_params = Map::new();
            let node = resolve_node(g.endpoint, &args, &g.path_names, &ctx).await?;
            for p in &g.path_names {
                let value = if p == "node" { node.clone().map(Value::String) } else { args.get(p).cloned() };
                match value {
                    Some(v) => {
                        path_params.insert(p.clone(), v);
                    }
                    None => return Err(PveError::invalid(format!("{}: \"{p}\" is required.", g.name))),
                }
            }
            let params = g.api_params(&args)?;
            let value = ctx.api.request(&method, &path, RequestOptions { path_params: Some(path_params), params: Some(params), ..Default::default() }).await?;
            if method == "GET" {
                if let Value::Array(rows) = value {
                    let (limit, offset) = if paged { super::paging_args(&args) } else { (None, None) };
                    return Ok(Value::Object(page_rows(rows, limit, offset)));
                }
                return Ok(Value::Object(as_object(value)));
            }
            let opts = if waits { FinishOptions::from_args(&args) } else { FinishOptions::no_wait() };
            Ok(Value::Object(ctx.tasks.finish(value, opts).await?))
        }
    })
}

fn upload_tool() -> ToolDef {
    let path = "/nodes/{node}/storage/{storage}/upload";
    ToolDef::new(
        "pve_upload_to_storage",
        "Upload to storage",
        "storage",
        Gate::Write,
        format!("Uploads a file from this server's PROXMOX_LOCAL_DIR to a storage: an ISO, a container template or a disk image to import. Refused when PROXMOX_LOCAL_DIR is not set, or when the file is outside it. [POST {path}. Needs: Datastore.AllocateTemplate on /storage/{{storage}}.]"),
    )
    .input(crate::shape![
        "node" => node_name().optional().describe("The cluster node name. Optional when there is a default node or only one node."),
        "storage" => z::string().min(1).max(PATH_VALUE_MAX as f64).describe("The storage identifier."),
        "content" => z::enumeration(&["iso", "vztmpl", "import"]).describe("Content type of the file."),
        "local_path" => z::string().min(1).max(4096).describe("The file, relative to PROXMOX_LOCAL_DIR."),
        "filename" => z::string().min(1).max(255).optional().describe("Name to give the file on the storage. Default: its name here."),
        "checksum" => z::string().max(512).optional().describe("Expected checksum of the file."),
        "checksum-algorithm" => z::enumeration(&["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]).optional().describe("Algorithm of the checksum."),
        "wait" => z::boolean().preprocess(to_boolean).optional().describe("Wait for the task that imports the file (default true)."),
        "wait_seconds" => z::int().min(0).max(3600).preprocess(to_number).optional().describe("How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30)."),
    ])
    .handler(move |args, ctx| async move {
        let local_path = resolve_local_path(ctx.instance.local_dir.as_deref(), args.str("local_path").unwrap_or(""), true)?;
        let node = match args.string("node") {
            Some(n) => n,
            None => ctx.nodes.default_node().await?,
        };
        let mut fields = obj! { "content" => args.get("content").cloned().unwrap_or(Value::Null) };
        if let Some(c) = args.str("checksum").filter(|s| !s.is_empty()) {
            fields.insert("checksum".into(), Value::String(c.into()));
        }
        if let Some(c) = args.str("checksum-algorithm").filter(|s| !s.is_empty()) {
            fields.insert("checksum-algorithm".into(), Value::String(c.into()));
        }
        let file = UploadFile { local_path, filename: args.string("filename").filter(|s| !s.is_empty()), field: None };
        let value = ctx.api.upload(path, fields, file, RequestOptions::path(obj! { "node" => node, "storage" => args.get("storage").cloned().unwrap_or(Value::Null) })).await?;
        Ok(Value::Object(ctx.tasks.finish(value, FinishOptions::from_args(&args)).await?))
    })
}

/// Built once: in HTTP mode each request has its own server over the same definitions.
pub fn endpoint_tools() -> Vec<ToolDef> {
    let mut out: Vec<ToolDef> = CATALOG.endpoints.iter().filter(|e| excluded(&e.method, &e.path).is_none()).map(generate).collect();
    out.push(upload_tool());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&endpoint_tools());
    }
}
