//! Finds where guests live, so that agents can speak in vmids and not have to know the node.

use super::{Api, RequestOptions};
use crate::errors::{PveError, Result, kind};
use crate::obj;
use indexmap::IndexMap;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct GuestLocation {
    pub vmid: i64,
    pub node: String,
    /// qemu or lxc.
    pub kind: String,
    pub name: Option<String>,
    pub status: String,
    pub template: bool,
    pub tags: Option<String>,
}

impl GuestLocation {
    pub fn to_json(&self) -> Value {
        Value::Object(obj! {
            "vmid" => self.vmid,
            "node" => &self.node,
            "type" => &self.kind,
            "status" => &self.status,
            "name" => self.name.clone(),
            "template" => if self.template { Some(true) } else { None },
            "tags" => self.tags.clone(),
        })
    }
}

pub struct NodeResolverOptions {
    pub default_node: Option<String>,
    /// Host of the API URL, the last resort when reaching a node by SSH.
    pub api_host: String,
    /// Node name to address, from PROXMOX_SSH_NODES.
    pub ssh_nodes: IndexMap<String, String>,
    pub cache_ms: Option<u64>,
}

const GUEST_CACHE_MS: u64 = 10_000;

struct Cache {
    at: Instant,
    rows: IndexMap<i64, GuestLocation>,
}

pub struct NodeResolver {
    api: Arc<dyn Api>,
    options: NodeResolverOptions,
    guests: Mutex<Option<Cache>>,
}

fn read_only() -> RequestOptions {
    RequestOptions { read_only: Some(true), ..Default::default() }
}

impl NodeResolver {
    pub fn new(api: Arc<dyn Api>, options: NodeResolverOptions) -> Self {
        NodeResolver { api, options, guests: Mutex::new(None) }
    }

    fn ttl(&self) -> Duration {
        Duration::from_millis(self.options.cache_ms.unwrap_or(GUEST_CACHE_MS))
    }

    /// Called after every write: the guest may have moved, or may be gone.
    pub fn invalidate(&self) {
        *self.guests.lock().unwrap() = None;
    }

    pub async fn list_guests(&self) -> Result<Vec<GuestLocation>> {
        Ok(self.guest_map().await?.into_values().collect())
    }

    async fn guest_map(&self) -> Result<IndexMap<i64, GuestLocation>> {
        {
            let guard = self.guests.lock().unwrap();
            if let Some(cache) = guard.as_ref() {
                if cache.at.elapsed() < self.ttl() {
                    return Ok(cache.rows.clone());
                }
            }
        }
        let rows = self.api.get("/cluster/resources", read_only().with_params(obj! { "type" => "vm" })).await?;
        let mut map = IndexMap::new();
        for row in rows.as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(vmid), Some(node)) = (row.get("vmid").and_then(Value::as_f64), row.get("node").and_then(Value::as_str)) else { continue };
            let vmid = vmid as i64;
            let name = row.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
            let tags = row.get("tags").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
            map.insert(
                vmid,
                GuestLocation {
                    vmid,
                    node: node.to_string(),
                    kind: if row.get("type").and_then(Value::as_str) == Some("lxc") { "lxc".into() } else { "qemu".into() },
                    status: row.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string(),
                    name,
                    template: crate::js::truthy_js(row.get("template")),
                    tags,
                },
            );
        }
        *self.guests.lock().unwrap() = Some(Cache { at: Instant::now(), rows: map.clone() });
        Ok(map)
    }

    pub async fn resolve_guest(&self, vmid: i64) -> Result<GuestLocation> {
        let fresh = {
            let guard = self.guests.lock().unwrap();
            match guard.as_ref() {
                Some(cache) => {
                    let fresh = cache.at.elapsed() < self.ttl();
                    if let (Some(found), true) = (cache.rows.get(&vmid), fresh) {
                        return Ok(found.clone());
                    }
                    fresh
                }
                None => false,
            }
        };
        // A miss in a live cache may just be a guest created a moment ago: look again.
        if fresh {
            self.invalidate();
        }
        self.guest_map().await?.get(&vmid).cloned().ok_or_else(|| {
            PveError::new(kind::NOT_FOUND, format!("No guest with vmid {vmid} in this cluster.")).hint("pve_list_cluster_resources lists all guests. A token only sees the guests it has VM.Audit on.")
        })
    }

    pub async fn list_nodes(&self) -> Result<Vec<String>> {
        let rows = self.api.get("/nodes", read_only()).await?;
        let mut nodes: Vec<String> = rows.as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|r| r.get("node").and_then(Value::as_str).map(str::to_string)).collect();
        nodes.sort();
        Ok(nodes)
    }

    /// PROXMOX_DEFAULT_NODE, else the only node there is. With several, an agent has to choose.
    pub async fn default_node(&self) -> Result<String> {
        if let Some(node) = &self.options.default_node {
            return Ok(node.clone());
        }
        let nodes = self.list_nodes().await?;
        match nodes.len() {
            1 => Ok(nodes[0].clone()),
            0 => Err(PveError::new(kind::NOT_FOUND, "This API token sees no node in the cluster.").hint("It may lack Sys.Audit on /nodes. Give the node name explicitly, or set PROXMOX_DEFAULT_NODE.")),
            _ => Err(PveError::new(kind::INVALID_INPUT, format!("This cluster has several nodes, so \"node\" is required: {}.", nodes.join(", ")))
                .hint("Pass node, or have the operator set PROXMOX_DEFAULT_NODE.")
                .details(json!({ "nodes": nodes }))),
        }
    }

    /// PROXMOX_SSH_NODES, else the address the cluster reports, else the API host on a single node.
    pub async fn ssh_host(&self, node: &str) -> Result<String> {
        if let Some(pinned) = self.options.ssh_nodes.get(node).filter(|s| !s.is_empty()) {
            return Ok(pinned.clone());
        }
        let rows = self.api.get("/cluster/status", read_only()).await.unwrap_or(Value::Null);
        let entries = rows.as_array().cloned().unwrap_or_default();
        let is_node = |r: &Value| r.get("type").and_then(Value::as_str) == Some("node");
        if let Some(ip) = entries.iter().find(|r| is_node(r) && r.get("name").and_then(Value::as_str) == Some(node)).and_then(|r| r.get("ip")).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Ok(ip.to_string());
        }
        if entries.iter().filter(|r| is_node(r)).count() <= 1 {
            return Ok(self.options.api_host.clone());
        }
        Err(PveError::new(kind::INVALID_INPUT, format!("No address known for node \"{node}\".")).hint("The operator can set PROXMOX_SSH_NODES, such as pve1=10.0.0.1,pve2=10.0.0.2."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxmox::tasks::mock::MockApi;
    use std::sync::Mutex as StdMutex;

    struct Cluster {
        nodes: Vec<&'static str>,
        guests: StdMutex<Vec<Value>>,
        status: Option<Value>,
    }

    fn cluster(nodes: &[&'static str], guests: Vec<Value>) -> Arc<Cluster> {
        Arc::new(Cluster { nodes: nodes.to_vec(), guests: StdMutex::new(guests), status: None })
    }

    fn default_guests() -> Vec<Value> {
        vec![json!({ "vmid": 100, "node": "pve1", "type": "qemu", "name": "web", "status": "running" })]
    }

    fn resolver(c: Arc<Cluster>, configure: impl FnOnce(&mut NodeResolverOptions)) -> (Arc<MockApi>, NodeResolver) {
        let api = Arc::new(MockApi::new(move |call| {
            Ok(match call.path.as_str() {
                "/cluster/resources" => Value::Array(c.guests.lock().unwrap().clone()),
                "/nodes" => Value::Array(c.nodes.iter().map(|n| json!({ "node": n, "status": "online" })).collect()),
                "/cluster/status" => c.status.clone().unwrap_or_else(|| {
                    let mut rows = vec![json!({ "type": "cluster", "name": "test" })];
                    rows.extend(c.nodes.iter().enumerate().map(|(i, n)| json!({ "type": "node", "name": n, "ip": format!("192.0.2.{}", i + 1) })));
                    Value::Array(rows)
                }),
                other => panic!("unexpected {other}"),
            })
        }));
        let mut options = NodeResolverOptions { default_node: None, api_host: "api.example".into(), ssh_nodes: IndexMap::new(), cache_ms: None };
        configure(&mut options);
        (api.clone(), NodeResolver::new(api, options))
    }

    #[tokio::test]
    async fn finds_a_guest_and_caches_the_answer() {
        let c = cluster(&["pve1", "pve2"], vec![json!({ "vmid": 100, "node": "pve2", "type": "lxc", "name": "db", "status": "stopped" })]);
        let (api, nodes) = resolver(c, |_| {});
        let guest = nodes.resolve_guest(100).await.unwrap();
        assert_eq!(guest.to_json(), json!({ "vmid": 100, "node": "pve2", "type": "lxc", "name": "db", "status": "stopped" }));
        nodes.resolve_guest(100).await.unwrap();
        let reads = api.calls_to("/cluster/resources");
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].params["type"], "vm");
        assert_eq!(reads[0].read_only, Some(true));
    }

    #[tokio::test]
    async fn reads_again_after_invalidate_and_after_the_cache_expires() {
        let c = cluster(&["pve1"], default_guests());
        let (api, nodes) = resolver(c.clone(), |_| {});
        nodes.resolve_guest(100).await.unwrap();
        c.guests.lock().unwrap()[0]["node"] = json!("pve9");
        nodes.invalidate();
        assert_eq!(nodes.resolve_guest(100).await.unwrap().node, "pve9");
        assert_eq!(api.calls_to("/cluster/resources").len(), 2);

        let (quick_api, quick) = resolver(cluster(&["pve1"], default_guests()), |o| o.cache_ms = Some(0));
        quick.resolve_guest(100).await.unwrap();
        quick.resolve_guest(100).await.unwrap();
        assert_eq!(quick_api.calls_to("/cluster/resources").len(), 2);
    }

    #[tokio::test]
    async fn looks_again_before_saying_that_a_guest_does_not_exist() {
        let c = cluster(&["pve1"], default_guests());
        let (_, nodes) = resolver(c.clone(), |_| {});
        nodes.resolve_guest(100).await.unwrap();
        c.guests.lock().unwrap().push(json!({ "vmid": 300, "node": "pve1", "type": "qemu", "status": "stopped" }));
        assert_eq!(nodes.resolve_guest(300).await.unwrap().vmid, 300);
        assert_eq!(nodes.resolve_guest(999).await.unwrap_err().kind, kind::NOT_FOUND);
    }

    #[tokio::test]
    async fn uses_the_default_node_else_the_only_one_else_lists_them() {
        let (_, chosen) = resolver(cluster(&["a", "b"], Vec::new()), |o| o.default_node = Some("b".into()));
        assert_eq!(chosen.default_node().await.unwrap(), "b");
        let (_, single) = resolver(cluster(&["only"], Vec::new()), |_| {});
        assert_eq!(single.default_node().await.unwrap(), "only");
        let (_, several) = resolver(cluster(&["a", "b"], Vec::new()), |_| {});
        let err = several.default_node().await.unwrap_err();
        assert_eq!(err.kind, kind::INVALID_INPUT);
        assert!(err.message.contains("a, b"), "{}", err.message);
    }

    #[tokio::test]
    async fn finds_the_ssh_host_pinned_else_from_the_cluster_else_the_api_host_on_one_node() {
        let (_, pinned) = resolver(cluster(&["a", "b"], Vec::new()), |o| {
            o.ssh_nodes.insert("a".into(), "10.0.0.1".into());
        });
        assert_eq!(pinned.ssh_host("a").await.unwrap(), "10.0.0.1");
        assert_eq!(pinned.ssh_host("b").await.unwrap(), "192.0.2.2");
        assert!(pinned.ssh_host("c").await.unwrap_err().message.contains("No address known"));

        let c = Arc::new(Cluster { nodes: vec!["pve1"], guests: StdMutex::new(Vec::new()), status: Some(json!([{ "type": "cluster", "name": "x" }, { "type": "node", "name": "pve1" }])) });
        let (_, single) = resolver(c, |_| {});
        assert_eq!(single.ssh_host("pve1").await.unwrap(), "api.example");
    }
}
