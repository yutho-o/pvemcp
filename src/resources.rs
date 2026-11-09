//! The same reads as the tools, for clients that let the user attach context directly.

use crate::errors::Result;
use crate::proxmox::{Api, RequestOptions};
use crate::runtime::{InstanceRuntime, Runtime};
use crate::tools::gather;
use futures::FutureExt;
use serde_json::{Map, Value, json};

const MAX_TASKS: usize = 200;

struct ResourceDef {
    name: &'static str,
    description: String,
}

fn resources() -> Vec<ResourceDef> {
    [
        ("cluster", "Version, cluster status with quorum, and HA status".to_string()),
        ("nodes", "The nodes, with state and usage".to_string()),
        ("guests", "VMs and containers of the whole cluster".to_string()),
        ("storage", "Storages as each node sees them, with usage".to_string()),
        ("tasks", format!("The latest {MAX_TASKS} tasks of the cluster, newest first")),
    ]
    .into_iter()
    .map(|(name, description)| ResourceDef { name, description })
    .collect()
}

async fn get(rt: &InstanceRuntime, path: &str, params: Option<Map<String, Value>>) -> Result<Value> {
    rt.client.get(path, RequestOptions { read_only: Some(true), params, ..Default::default() }).await
}

fn of_type(kind: &str) -> Option<Map<String, Value>> {
    let mut m = Map::new();
    m.insert("type".into(), Value::String(kind.into()));
    Some(m)
}

async fn read_one(rt: &InstanceRuntime, name: &str) -> Result<Value> {
    match name {
        "cluster" => {
            let (mut data, unavailable) = gather(vec![
                ("version", get(rt, "/version", None).boxed()),
                ("status", get(rt, "/cluster/status", None).boxed()),
                ("ha", get(rt, "/cluster/ha/status/current", None).boxed()),
            ])
            .await;
            data.insert("complete".into(), Value::Bool(unavailable.is_empty()));
            data.insert("unavailable".into(), Value::Object(unavailable));
            Ok(Value::Object(data))
        }
        "nodes" => get(rt, "/nodes", None).await,
        "guests" => get(rt, "/cluster/resources", of_type("vm")).await,
        "storage" => get(rt, "/cluster/resources", of_type("storage")).await,
        _ => {
            let rows = get(rt, "/cluster/tasks", None).await?;
            let mut list = match rows {
                Value::Array(r) => r,
                _ => Vec::new(),
            };
            let total = list.len();
            let start = |v: &Value| v.get("starttime").and_then(Value::as_f64).unwrap_or(0.0);
            list.sort_by(|a, b| start(b).partial_cmp(&start(a)).unwrap_or(std::cmp::Ordering::Equal));
            list.truncate(MAX_TASKS);
            Ok(json!({ "total": total, "tasks": list }))
        }
    }
}

/// resources/list: five per instance.
pub fn list(runtime: &Runtime) -> Vec<Value> {
    let mut out = Vec::new();
    for rt in runtime.instances.values() {
        for def in resources() {
            let name = &rt.config.name;
            out.push(json!({
                "name": format!("{name}-{}", def.name),
                "title": format!("{} ({name})", def.description),
                "uri": format!("proxmox://{name}/{}", def.name),
                "description": format!("{}. Untrusted data from Proxmox and its guests.", def.description),
                "mimeType": "application/json",
            }));
        }
    }
    out
}

/// resources/read. None when no resource has this uri.
pub async fn read(runtime: &Runtime, uri: &str) -> Option<Result<Value>> {
    for rt in runtime.instances.values() {
        for def in resources() {
            if uri == format!("proxmox://{}/{}", rt.config.name, def.name) {
                return Some(read_one(rt, def.name).await.map(|value| json!({ "uri": uri, "mimeType": "application/json", "text": value.to_string() })));
            }
        }
    }
    None
}
