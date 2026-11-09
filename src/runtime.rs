//! What outlives a single MCP connection: API clients, SSH connections and interactive
//! sessions. In HTTP mode each request has its own MCP server over this.

use crate::config::{InstanceConfig, ServerConfig};
use crate::errors::{PveError, Result, kind};
use crate::js::now_iso;
use crate::proxmox::Api;
use crate::proxmox::client::{OnWrite, ProxmoxClient, WriteRecord};
use crate::proxmox::nodes::{NodeResolver, NodeResolverOptions};
use crate::ssh::{SshTransport, TransportGetter};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::any::Any;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

pub struct InstanceRuntime {
    pub config: Arc<InstanceConfig>,
    pub client: Arc<ProxmoxClient>,
    pub nodes: Arc<NodeResolver>,
    /// Lazy: nothing connects, or is even set up, before the first SSH command.
    pub ssh: TransportGetter,
}

pub type TransportFactory = Arc<dyn Fn(Arc<InstanceConfig>, Arc<NodeResolver>) -> Arc<dyn SshTransport> + Send + Sync>;
pub type Notify = Arc<dyn Fn(&str, &str) + Send + Sync>;
pub type ShutdownHook = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

tokio::task_local! {
    /// The writes of the tool call running in this task, for the audit log.
    static WRITE_SCOPE: Arc<Mutex<Vec<Value>>>;
}

pub struct Runtime {
    pub config: Arc<ServerConfig>,
    pub instances: IndexMap<String, InstanceRuntime>,
    listeners: Mutex<Vec<(u64, Notify)>>,
    next_listener: Mutex<u64>,
    shared: Mutex<HashMap<String, Arc<dyn Any + Send + Sync>>>,
    shutdown_hooks: Mutex<Vec<ShutdownHook>>,
    transports: Arc<Mutex<HashMap<String, Arc<dyn SshTransport>>>>,
}

impl Runtime {
    pub fn new(config: ServerConfig, ssh_factory: Option<TransportFactory>) -> Result<Arc<Runtime>> {
        if let Some(path) = &config.audit_log {
            assert_audit_writable(path)?;
        }
        let factory: TransportFactory = ssh_factory.unwrap_or_else(|| Arc::new(|instance, nodes| crate::ssh::transport::create_ssh_transport(instance, nodes)));
        let config = Arc::new(config);
        let mut failure = None;
        let runtime = Arc::new_cyclic(|weak: &Weak<Runtime>| {
            let transports: Arc<Mutex<HashMap<String, Arc<dyn SshTransport>>>> = Arc::new(Mutex::new(HashMap::new()));
            let mut instances = IndexMap::new();
            for (name, instance) in &config.instances {
                let instance = Arc::new(instance.clone());
                let nodes_cell: Arc<OnceLock<Arc<NodeResolver>>> = Arc::new(OnceLock::new());
                let on_write: OnWrite = {
                    let (weak, name, nodes_cell) = (weak.clone(), name.clone(), nodes_cell.clone());
                    Arc::new(move |record: WriteRecord| {
                        if let Some(nodes) = nodes_cell.get() {
                            nodes.invalidate();
                        }
                        if let Some(rt) = weak.upgrade() {
                            rt.on_write(&name, record);
                        }
                    })
                };
                let client = match ProxmoxClient::new((*instance).clone(), config.unblocked.clone(), Some(on_write)) {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        failure.get_or_insert(e);
                        continue;
                    }
                };
                let api_host = url::Url::parse(&instance.url).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())).unwrap_or_default();
                let nodes = Arc::new(NodeResolver::new(
                    client.clone() as Arc<dyn Api>,
                    NodeResolverOptions { default_node: instance.default_node.clone(), api_host, ssh_nodes: instance.ssh.nodes.clone(), cache_ms: None },
                ));
                let _ = nodes_cell.set(nodes.clone());
                let ssh: TransportGetter = {
                    let (transports, name, instance, nodes, factory) = (transports.clone(), name.clone(), instance.clone(), nodes.clone(), factory.clone());
                    Arc::new(move || {
                        let mut map = transports.lock().unwrap();
                        map.entry(name.clone()).or_insert_with(|| factory(instance.clone(), nodes.clone())).clone()
                    })
                };
                instances.insert(name.clone(), InstanceRuntime { config: instance, client, nodes, ssh });
            }
            Runtime {
                config: config.clone(),
                instances,
                listeners: Mutex::new(Vec::new()),
                next_listener: Mutex::new(0),
                shared: Mutex::new(HashMap::new()),
                shutdown_hooks: Mutex::new(Vec::new()),
                transports,
            }
        });
        match failure {
            Some(e) => Err(e),
            None => Ok(runtime),
        }
    }

    pub fn instance(&self, name: Option<&str>) -> Result<&InstanceRuntime> {
        let key = name.unwrap_or(&self.config.default_instance);
        self.instances.get(key).ok_or_else(|| {
            PveError::new(kind::INVALID_INPUT, format!("Unknown instance \"{key}\".")).hint(format!("Known instances: {}", self.instances.keys().cloned().collect::<Vec<_>>().join(", ")))
        })
    }

    /// One value per key for the life of the server, for state that has to survive stateless HTTP
    /// requests, such as SSH sessions. Use on_shutdown to clean it up.
    pub fn state<T: Any + Send + Sync>(&self, key: &str, create: impl FnOnce() -> Arc<T>) -> Arc<T> {
        let mut shared = self.shared.lock().unwrap();
        let entry = shared.entry(key.to_string()).or_insert_with(|| create() as Arc<dyn Any + Send + Sync>).clone();
        entry.downcast::<T>().expect("state of the same key has the same type")
    }

    pub fn on_shutdown(&self, hook: ShutdownHook) {
        self.shutdown_hooks.lock().unwrap().push(hook);
    }

    /// Returns an id to remove the listener with.
    pub fn add_listener(&self, listener: Notify) -> u64 {
        let mut next = self.next_listener.lock().unwrap();
        *next += 1;
        self.listeners.lock().unwrap().push((*next, listener));
        *next
    }

    pub fn remove_listener(&self, id: u64) {
        self.listeners.lock().unwrap().retain(|(i, _)| *i != id);
    }

    /// Runs a tool while collecting the requests that change something, for the audit log.
    pub async fn collect_writes<F: std::future::Future>(&self, writes: Arc<Mutex<Vec<Value>>>, run: F) -> F::Output {
        WRITE_SCOPE.scope(writes, run).await
    }

    /// What a tool is doing that is not an HTTP write: SSH commands.
    pub fn record_write(&self, instance: &str, entry: WriteRecord) {
        self.on_write(instance, entry);
    }

    pub fn audit(&self, entry: Map<String, Value>) {
        let Some(path) = &self.config.audit_log else { return };
        let mut line = Map::new();
        line.insert("ts".into(), Value::String(now_iso()));
        for (k, v) in entry {
            line.insert(k, v);
        }
        let text = format!("{}\n", Value::Object(line));
        let path = path.clone();
        let write = move || {
            let result = std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(text.as_bytes()));
            if let Err(e) = result {
                eprintln!("[pvemcp] could not write the audit log: {e}");
            }
        };
        // Small and in order: a line per call, never interleaved.
        write();
    }

    pub fn notify(&self, level: &str, message: &str) {
        eprintln!("[pvemcp] {level}: {message}");
        let listeners: Vec<Notify> = self.listeners.lock().unwrap().iter().map(|(_, l)| l.clone()).collect();
        for listener in listeners {
            listener(level, message);
        }
    }

    pub async fn shutdown(&self) {
        let hooks: Vec<ShutdownHook> = std::mem::take(&mut *self.shutdown_hooks.lock().unwrap());
        let transports: Vec<Arc<dyn SshTransport>> = self.transports.lock().unwrap().drain().map(|(_, t)| t).collect();
        let mut closing: Vec<BoxFuture<'static, ()>> = hooks.iter().map(|h| h()).collect();
        for t in transports {
            closing.push(Box::pin(async move { t.close().await }));
        }
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, futures::future::join_all(closing)).await;
    }

    fn on_write(&self, instance: &str, entry: WriteRecord) {
        let entry = Value::Object(entry);
        let in_scope = WRITE_SCOPE.try_with(|scope| scope.lock().unwrap().push(entry.clone())).is_ok();
        // Outside a tool call, this is something running on its own.
        if !in_scope {
            let mut audit = Map::new();
            audit.insert("instance".into(), Value::String(instance.to_string()));
            audit.insert("tool".into(), Value::String("(background)".into()));
            audit.insert("writes".into(), Value::Array(vec![entry]));
            self.audit(audit);
        }
    }
}

/// A log that cannot be written should stop the server now, not fail unnoticed later.
fn assert_audit_writable(path: &str) -> Result<()> {
    std::fs::OpenOptions::new().create(true).append(true).open(path).map(|_| ()).map_err(|e| PveError::config(format!("PROXMOX_AUDIT_LOG: cannot write to {path}: {e}")))
}
