pub mod client;
pub mod localpath;
pub mod nodes;
pub mod params;
pub mod policy;
pub mod redact;
pub mod tasks;

use crate::errors::Result;
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex};

/// What a dry run would have sent, shared between a tool and the calls it makes.
pub type DryRunLog = Arc<Mutex<Vec<Value>>>;

#[derive(Default, Clone)]
pub struct RequestOptions {
    /// Query string for GET and DELETE, form body for POST and PUT.
    pub params: Option<Map<String, Value>>,
    /// Fills {placeholders} in the path, encoded. The way to pass values such as local:iso/x.iso.
    pub path_params: Option<Map<String, Value>>,
    /// Set for read tools: anything that changes state is refused.
    pub read_only: Option<bool>,
    /// Record this write instead of sending it.
    pub dry_run: Option<bool>,
    /// Filled with the requests a dry run would have sent.
    pub dry_run_log: Option<DryRunLog>,
    pub timeout_ms: Option<u64>,
    /// Keep secrets in the answer. Only honoured when the instance allows sensitive data.
    pub include_sensitive: bool,
}

impl RequestOptions {
    pub fn params(params: Map<String, Value>) -> Self {
        RequestOptions { params: Some(params), ..Default::default() }
    }

    pub fn path(path_params: Map<String, Value>) -> Self {
        RequestOptions { path_params: Some(path_params), ..Default::default() }
    }

    pub fn with_params(mut self, params: Map<String, Value>) -> Self {
        self.params = Some(params);
        self
    }

    pub fn with_path(mut self, path_params: Map<String, Value>) -> Self {
        self.path_params = Some(path_params);
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
}

/// A file to send as multipart, which is what storage upload takes.
#[derive(Clone)]
pub struct UploadFile {
    pub local_path: String,
    pub filename: Option<String>,
    /// Name of the file part in the form.
    pub field: Option<String>,
}

/// The API handle that tools, tasks and the node resolver see: the client, or a ScopedApi over it.
pub trait Api: Send + Sync {
    fn request(&self, method: &str, path: &str, opts: RequestOptions) -> BoxFuture<'_, Result<Value>>;

    fn upload(&self, path: &str, fields: Map<String, Value>, file: UploadFile, opts: RequestOptions) -> BoxFuture<'_, Result<Value>>;

    fn get(&self, path: &str, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
        self.request("GET", path, opts)
    }
}
