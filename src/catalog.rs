//! The Proxmox API schema, from pve-docs, and a router over its paths.

use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

#[derive(Debug, Clone, Deserialize)]
pub struct ItemSchema {
    #[serde(rename = "type")]
    pub kind: String,
    pub format: Option<String>,
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<Value>, D::Error> {
    <Value as serde::Deserialize>::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogParam {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: Option<String>,
    #[serde(default)]
    pub optional: bool,
    /// A default of null is still a default: the description says "Default: null.".
    #[serde(default, deserialize_with = "present")]
    pub default: Option<Value>,
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_length: Option<f64>,
    pub max_length: Option<f64>,
    pub pattern: Option<String>,
    pub typetext: Option<String>,
    pub format: Option<String>,
    /// The value is a Proxmox property string (key=value,...); the description lists its keys.
    #[serde(default)]
    pub property_string: bool,
    pub items: Option<ItemSchema>,
    pub requires: Option<String>,
    pub instance_types: Option<Vec<String>>,
    pub type_property: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReturns {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: Option<String>,
    pub properties: Option<Vec<String>>,
    pub item_properties: Option<Vec<String>>,
    #[serde(default)]
    pub links: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogEndpoint {
    pub method: String,
    pub path: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub allowtoken: bool,
    pub params: IndexMap<String, CatalogParam>,
    pub returns: CatalogReturns,
    #[serde(default)]
    pub protected: bool,
    pub proxyto: Option<String>,
    #[serde(default)]
    pub expose_credentials: bool,
    #[serde(default)]
    pub download_allowed: bool,
    pub permissions: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub source: String,
    /// When the schema was published or fetched.
    pub schema_date: String,
    pub schema_sha256: String,
    pub counts: IndexMap<String, u64>,
    pub endpoints: Vec<CatalogEndpoint>,
}

static FILE: &str = include_str!("catalog/endpoints.json");

pub static CATALOG: LazyLock<Catalog> = LazyLock::new(|| serde_json::from_str(FILE).expect("the bundled API catalog parses"));

#[derive(Default)]
struct TrieNode {
    literal: HashMap<String, TrieNode>,
    placeholder: Option<Box<TrieNode>>,
    template: Option<String>,
    /// Method to index in CATALOG.endpoints.
    methods: IndexMap<String, usize>,
}

struct Index {
    root: TrieNode,
    by_key: HashMap<String, usize>,
}

fn placeholder_name(segment: &str) -> Option<&str> {
    segment.strip_prefix('{')?.strip_suffix('}').filter(|s| !s.is_empty())
}

static INDEX: LazyLock<Index> = LazyLock::new(|| {
    let mut root = TrieNode::default();
    let mut by_key = HashMap::new();
    for (i, endpoint) in CATALOG.endpoints.iter().enumerate() {
        by_key.insert(format!("{} {}", endpoint.method, endpoint.path), i);
        let mut node = &mut root;
        for segment in endpoint.path.split('/').filter(|s| !s.is_empty()) {
            if placeholder_name(segment).is_some() {
                node = node.placeholder.get_or_insert_with(Default::default);
            } else {
                node = node.literal.entry(segment.to_string()).or_default();
            }
        }
        node.template = Some(endpoint.path.clone());
        node.methods.insert(endpoint.method.clone(), i);
    }
    Index { root, by_key }
});

/// The endpoints as they are in the file, for pve_api_describe: every key, in its order.
static RAW: LazyLock<Vec<Value>> = LazyLock::new(|| {
    let v: Value = serde_json::from_str(FILE).expect("the bundled API catalog parses");
    v["endpoints"].as_array().cloned().unwrap_or_default()
});

/// The endpoint at this index of CATALOG.endpoints, as JSON.
pub fn raw_endpoint(method: &str, template: &str) -> Option<&'static Value> {
    INDEX.by_key.get(&format!("{method} {template}")).map(|&i| &RAW[i])
}

pub fn catalog() -> &'static Catalog {
    &CATALOG
}

pub fn find_endpoint(method: &str, template: &str) -> Option<&'static CatalogEndpoint> {
    INDEX.by_key.get(&format!("{method} {template}")).map(|&i| &CATALOG.endpoints[i])
}

pub struct PathMatch {
    pub template: String,
    pub path_params: IndexMap<String, String>,
    pub methods: IndexMap<String, &'static CatalogEndpoint>,
}

/// Literal segments win over placeholders, with backtracking: the API router does the same.
pub fn match_path(segments: &[String]) -> Option<PathMatch> {
    fn walk<'a>(node: &'a TrieNode, segments: &[String], index: usize) -> Option<&'a TrieNode> {
        if index == segments.len() {
            return node.template.as_ref().map(|_| node);
        }
        if let Some(literal) = node.literal.get(&segments[index]) {
            if let Some(found) = walk(literal, segments, index + 1) {
                return Some(found);
            }
        }
        node.placeholder.as_ref().and_then(|p| walk(p, segments, index + 1))
    }
    let end = walk(&INDEX.root, segments, 0)?;
    let template = end.template.clone()?;
    let mut path_params = IndexMap::new();
    for (i, segment) in template.split('/').filter(|s| !s.is_empty()).enumerate() {
        if let Some(name) = placeholder_name(segment) {
            path_params.insert(name.to_string(), segments[i].clone());
        }
    }
    let methods = end.methods.iter().map(|(m, &i)| (m.clone(), &CATALOG.endpoints[i])).collect();
    Some(PathMatch { template, path_params, methods })
}

/// Path parameter names, always from the template: the schema does not declare them all.
pub fn template_params(template: &str) -> Vec<String> {
    template.split('/').filter_map(placeholder_name).map(str::to_string).collect()
}

/// Every distinct path template.
pub fn templates() -> BTreeSet<&'static str> {
    CATALOG.endpoints.iter().map(|e| e.path.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_matches() {
        assert_eq!(CATALOG.endpoints.len(), 680);
        let segments: Vec<String> = ["nodes", "pve1", "qemu", "100", "status", "current"].iter().map(|s| s.to_string()).collect();
        let m = match_path(&segments).unwrap();
        assert_eq!(m.template, "/nodes/{node}/qemu/{vmid}/status/current");
        assert_eq!(m.path_params["vmid"], "100");
        assert!(find_endpoint("GET", "/version").is_some());
    }
}
