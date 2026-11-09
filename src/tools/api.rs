//! The whole API by path: search, describe, and calls for what is not in the tool list.

use super::endpoints::{UPLOAD_ENDPOINT, excluded};
use super::naming::{domain_of, tool_name};
use super::{ArgsExt, FinishOptions, ToolDef, as_object, page_rows, paging_args};
use crate::catalog::{CATALOG, CatalogEndpoint, find_endpoint, match_path, raw_endpoint};
use crate::errors::{PveError, kind};
use crate::obj;
use crate::proxmox::policy::{Gate, classify, normalize_path};
use crate::proxmox::redact::redact_request;
use crate::proxmox::{Api, RequestOptions};
use crate::schema::{Schema, z};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

fn path_arg() -> Schema {
    z::string()
        .min(1)
        .max(4096)
        .describe("API path, without /api2/json, such as /nodes/pve1/qemu/100/config. It may also be a template with {placeholders}, filled from path_params.")
}

fn path_params_arg() -> Schema {
    z::map_of(z::union(vec![z::string(), z::number()]), None)
        .optional()
        .describe("Values for {placeholders} in the path. The way to pass a value holding a slash, such as a volume id: path /nodes/pve1/storage/local/content/{volume}, path_params {\"volume\": \"local:iso/x.iso\"}.")
}

fn params_arg() -> Schema {
    z::loose_object(vec![]).optional().describe("Parameters. Booleans become 1/0, arrays repeat the key, and {\"0\": \"...\"} under net becomes net0.")
}

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{([^}]+)\}").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

fn placeholder_values(template: &str) -> Map<String, Value> {
    PLACEHOLDER.captures_iter(template).map(|m| (m[1].to_string(), Value::String("x".into()))).collect()
}

fn summary(e: &CatalogEndpoint) -> Map<String, Value> {
    let decision = classify(&e.method, &e.path, Some(&placeholder_values(&e.path))).expect("catalog paths classify");
    let key = format!("{} {}", e.method, e.path);
    let tool = if key == UPLOAD_ENDPOINT {
        Value::String("pve_upload_to_storage".into())
    } else if excluded(&e.method, &e.path).is_some() {
        Value::Null
    } else {
        Value::String(tool_name(&e.method, &e.path))
    };
    let mut out = obj! { "method" => &e.method, "path" => &e.path, "description" => &e.description, "gate" => decision.gate.as_str() };
    if decision.destructive {
        out.insert("destructive".into(), Value::Bool(true));
    }
    out.insert("domain".into(), Value::String(domain_of(&e.path).domain.into()));
    out.insert("tool".into(), tool);
    out
}

fn request_opts(args: &super::Args) -> RequestOptions {
    RequestOptions { path_params: args.object("path_params").cloned(), params: args.object("params").cloned(), ..Default::default() }
}

pub fn api_tools() -> Vec<ToolDef> {
    let methods = ["GET", "POST", "PUT", "DELETE"];
    vec![
        ToolDef::new(
            "pve_api_search",
            "Search the Proxmox API",
            "api",
            Gate::Read,
            format!(
                "Searches the catalog of {} Proxmox API methods: path, description and parameter names. Each result gives the tool that calls it, and the gate this server applies. Every method has its own tool, but tool lists are filtered by PROXMOX_TOOLSETS and by what the instance allows: a result whose tool is not in your list can still be called with pve_api_read or pve_api_write, under the same policy.",
                CATALOG.endpoints.len()
            ),
        )
        .idempotent()
        .input(crate::shape![
            "query" => z::string().min(2).max(200).describe("Words that must all appear, such as \"lxc snapshot\" or \"firewall ipset\"."),
            "method" => z::enumeration(&methods).optional().describe("Only this HTTP method."),
            "page_limit" => z::int().min(1).max(200).optional().describe("Results per page (default 30)."),
            "page_offset" => z::int().min(0).optional().describe("Results to skip. Use next_offset from the previous page."),
        ])
        .handler(|args, _ctx| async move {
            let query = args.str("query").unwrap_or("").to_lowercase();
            let words: Vec<&str> = WHITESPACE.split(&query).filter(|w| !w.is_empty()).collect();
            let method = args.str("method").filter(|m| !m.is_empty());
            let hits: Vec<Value> = CATALOG
                .endpoints
                .iter()
                .filter(|e| {
                    if method.is_some_and(|m| m != e.method) {
                        return false;
                    }
                    let names: Vec<&str> = e.params.keys().map(String::as_str).collect();
                    let haystack = format!("{} {} {} {} {}", e.method, e.path, e.description, names.join(" "), tool_name(&e.method, &e.path)).to_lowercase();
                    words.iter().all(|w| haystack.contains(w))
                })
                .map(|e| Value::Object(summary(e)))
                .collect();
            let (limit, offset) = paging_args(&args);
            Ok(Value::Object(page_rows(hits, Some(limit.unwrap_or(30)), offset)))
        }),
        ToolDef::new(
            "pve_api_describe",
            "Describe an API method",
            "api",
            Gate::Read,
            "Gives everything known about one API method: all parameters with types and allowed values, privileges needed, what it returns, the gate this server applies and the tool that calls it. Use this before a call that failed validation, or to build a property string such as net0.",
        )
        .idempotent()
        .input(crate::shape![
            "method" => z::enumeration(&methods).describe("HTTP method."),
            "path" => z::string().min(1).max(4096).describe("The template (/nodes/{node}/qemu), or a concrete path (/nodes/pve1/qemu)."),
        ])
        .handler(|args, _ctx| async move {
            let (method, path) = (args.str("method").unwrap_or(""), args.str("path").unwrap_or(""));
            let endpoint = match find_endpoint(method, path) {
                Some(e) => Some(e),
                None if path.contains('{') => None,
                None => match_path(&normalize_path(path, None)?).and_then(|m| find_endpoint(method, &m.template)),
            };
            let Some(endpoint) = endpoint else {
                return Err(PveError::new(kind::NOT_FOUND, format!("{method} {path} is not in the API catalog.")).hint("pve_api_search finds methods by keyword."));
            };
            let raw = raw_endpoint(&endpoint.method, &endpoint.path).expect("indexed endpoint");
            let mut out = summary(endpoint);
            out.insert("name".into(), Value::String(endpoint.name.clone()));
            out.insert("permissions".into(), endpoint.permissions.clone().map(Value::String).unwrap_or(Value::Null));
            // allowtoken is left out of the JSON when it is not set, like undefined in JavaScript.
            if let Some(v) = raw.get("allowtoken") {
                out.insert("allow_token".into(), v.clone());
            }
            out.insert("returns".into(), raw["returns"].clone());
            out.insert("params".into(), raw["params"].clone());
            Ok(Value::Object(out))
        }),
        ToolDef::new(
            "pve_api_read",
            "Read any API path",
            "api",
            Gate::Read,
            "Calls any GET method by path, under the same policy as the dedicated tools: gate read, or sensitive when that is allowed. For what is not in your tool list. A path that is not in the catalog counts as sensitive. Secrets are redacted.",
        )
        .idempotent()
        .input(crate::shape![
            "path" => path_arg(),
            "path_params" => path_params_arg(),
            "params" => params_arg(),
            "page_limit" => z::int().min(1).max(10_000).optional().describe("Rows per page, when the answer is a list."),
            "page_offset" => z::int().min(0).optional().describe("Rows to skip. Use next_offset from the previous page."),
        ])
        .handler(|args, ctx| async move {
            let path = args.str("path").unwrap_or("");
            let decision = classify("GET", path, args.object("path_params"))?;
            if !matches!(decision.gate, Gate::Read | Gate::Sensitive | Gate::Blocked) {
                return Err(PveError::new(
                    kind::NOT_READ_ONLY,
                    format!("pve_api_read only takes methods of gate read or sensitive, and GET {} has gate {}.", decision.path, decision.gate.as_str()),
                )
                .hint("Use its dedicated tool: pve_api_describe gives the name."));
            }
            let value = ctx.api.get(path, request_opts(&args)).await?;
            Ok(Value::Object(match value {
                Value::Array(rows) => {
                    let (limit, offset) = paging_args(&args);
                    page_rows(rows, limit, offset)
                }
                other => as_object(other),
            }))
        }),
        ToolDef::new(
            "pve_api_write",
            "Write to any API path",
            "api",
            Gate::Write,
            "Calls any POST, PUT or DELETE method by path, for what is not in your tool list. The same policy applies: the gate of the method is checked, including elevated, guest_exec and console, and blocked endpoints stay blocked. A path that is not in the catalog counts as elevated. A task id in the answer is waited for. Prefer a dedicated tool whenever one exists.",
        )
        .destructive()
        .input(crate::shape![
            "method" => z::enumeration(&["POST", "PUT", "DELETE"]).describe("HTTP method."),
            "path" => path_arg(),
            "path_params" => path_params_arg(),
            "params" => params_arg(),
            "wait" => z::boolean().optional().describe("If the call starts a task, wait for its end (default true)."),
            "wait_seconds" => z::int().min(0).max(3600).optional().describe("How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30)."),
        ])
        .redact_args(|args| {
            let mut out = args.clone();
            if let Some(params) = args.get("params").filter(|p| !p.is_null()) {
                out.insert("params".into(), redact_request(&crate::js::js_string_opt(args.get("path")), params));
            }
            out
        })
        .confirmation(|args| {
            let keys: Vec<Value> = args.object("params").map(|p| p.keys().map(|k| Value::String(k.clone())).collect()).unwrap_or_default();
            format!(
                "Call {} {} on Proxmox, with {}?",
                crate::js::js_string_opt(args.get("method")),
                crate::js::js_string_opt(args.get("path")),
                Value::Array(keys)
            )
        })
        .handler(|args, ctx| async move {
            let value = ctx.api.request(args.str("method").unwrap_or(""), args.str("path").unwrap_or(""), request_opts(&args)).await?;
            Ok(Value::Object(ctx.tasks.finish(value, FinishOptions::from_args(&args)).await?))
        }),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&super::api_tools());
    }
}
