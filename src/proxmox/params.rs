//! Tool parameters to the name=value pairs Proxmox takes.

use crate::errors::{PveError, Result, kind};
use crate::js::{encode_uri_component, number_text};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

pub type Params = Map<String, Value>;

static QEMU_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/qemu(?:/|$)").unwrap());
static ALREADY_ENCODED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9%._~-]*$").unwrap());
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+$").unwrap());

/// qemu-server stores sshkeys URL-encoded and checks that they are on the way in, so the value
/// must be encoded once more on top of the form encoding, with %20 (never +) for spaces.
/// A value read back from a VM config is already encoded: it has no space, a real key always does.
pub fn encode_ssh_keys(value: &str) -> String {
    if ALREADY_ENCODED.is_match(value) && value.contains('%') {
        return value.to_string();
    }
    encode_uri_component(value)
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "object",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) | Value::Object(_) => "object",
    }
}

fn scalar(name: &str, value: &Value) -> Result<String> {
    match value {
        Value::Bool(b) => Ok(if *b { "1" } else { "0" }.into()),
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (_, Some(u)) => u.to_string(),
            _ => number_text(n.as_f64().unwrap_or(f64::NAN)),
        }),
        other => Err(PveError::new(kind::INVALID_INPUT, format!("Parameter \"{name}\" has an unsupported value ({}).", type_name(other)))),
    }
}

/// Flattens tool-level parameters to the name=value pairs Proxmox takes. Booleans become 1/0,
/// arrays repeat the key, and { "0": "a", "1": "b" } under net becomes net0=a and net1=b.
/// Null is left out.
pub fn flatten_params(path: &str, params: Option<&Params>) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let Some(params) = params else { return Ok(out) };
    for (name, value) in params {
        match value {
            Value::Null => continue,
            Value::Array(items) => {
                for item in items {
                    if !item.is_null() {
                        out.push((name.clone(), scalar(name, item)?));
                    }
                }
            }
            Value::Object(map) => {
                for (index, item) in map {
                    if !DIGITS.is_match(index) {
                        return Err(PveError::new(kind::INVALID_INPUT, format!("Parameter \"{name}\" takes numeric indexes such as {{\"0\": \"...\"}}, not \"{index}\".")));
                    }
                    if !item.is_null() {
                        let key = format!("{name}{index}");
                        let v = scalar(&key, item)?;
                        out.push((key, v));
                    }
                }
            }
            Value::String(s) if name == "sshkeys" && QEMU_PATH.is_match(path) => out.push((name.clone(), encode_ssh_keys(s))),
            _ => out.push((name.clone(), scalar(name, value)?)),
        }
    }
    Ok(out)
}

/// Spaces go out as %20: URLSearchParams would write +, which sshkeys cannot have.
pub fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", encode_uri_component(k), encode_uri_component(v))).collect::<Vec<_>>().join("&")
}

/// Tool parameter name to API name. "numa[n]" lives next to a plain "numa" on VM configs.
pub fn indexed_name(api_name: &str, taken: impl Fn(&str) -> bool) -> String {
    let base = &api_name[..api_name.len() - 3];
    if taken(base) { format!("{base}_n") } else { base.to_string() }
}

pub fn is_indexed_param(api_name: &str) -> bool {
    api_name.ends_with("[n]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flattens() {
        let p = json!({"net": {"0": "virtio", "1": "e1000"}, "onboot": true, "tags": ["a", "b"], "x": null, "sshkeys": "ssh-ed25519 AAA a@b"});
        let pairs = flatten_params("/nodes/a/qemu/1/config", p.as_object()).unwrap();
        assert_eq!(pairs[0], ("net0".into(), "virtio".into()));
        assert_eq!(pairs[2], ("onboot".into(), "1".into()));
        assert_eq!(pairs[5], ("sshkeys".into(), "ssh-ed25519%20AAA%20a%40b".into()));
        assert_eq!(encode_pairs(&[("a b".into(), "c d".into())]), "a%20b=c%20d");
    }

    // Ported from test/redact-params.test.ts.

    fn flat(params: Value, path: &str) -> Result<Vec<(String, String)>> {
        flatten_params(path, params.as_object())
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn booleans_numbers_and_null() {
        let got = flat(json!({ "a": true, "b": false, "c": 5, "d": "x", "f": null }), "/nodes/{node}/lxc").unwrap();
        assert_eq!(got, pairs(&[("a", "1"), ("b", "0"), ("c", "5"), ("d", "x")]));
    }

    #[test]
    fn repeats_the_key_for_arrays_and_spreads_indexed_params() {
        assert_eq!(flat(json!({ "command": ["ls", "-l"] }), "/nodes/{node}/lxc").unwrap(), pairs(&[("command", "ls"), ("command", "-l")]));
        assert_eq!(flat(json!({ "net": { "0": "virtio,bridge=vmbr0", "2": "e1000" } }), "/nodes/{node}/lxc").unwrap(), pairs(&[("net0", "virtio,bridge=vmbr0"), ("net2", "e1000")]));
    }

    #[test]
    fn refuses_a_non_numeric_index() {
        let e = flat(json!({ "net": { "x&y=1": "a" } }), "/nodes/{node}/lxc").unwrap_err();
        assert!(e.message.contains("numeric indexes"), "{}", e.message);
    }

    #[test]
    fn encodes_qemu_sshkeys_one_extra_time() {
        let key = "ssh-ed25519 AAAA+B/C= me@host\n";
        let got = flat(json!({ "sshkeys": key }), "/nodes/{node}/qemu/{vmid}/config").unwrap();
        assert_eq!(got, pairs(&[("sshkeys", "ssh-ed25519%20AAAA%2BB%2FC%3D%20me%40host%0A")]));
        let wire = encode_pairs(&got);
        assert_eq!(wire, "sshkeys=ssh-ed25519%2520AAAA%252BB%252FC%253D%2520me%2540host%250A");
        assert!(!wire.contains('+'));
        let decode = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8().unwrap().into_owned();
        assert_eq!(decode(&decode(&wire["sshkeys=".len()..])), key);
        assert_eq!(flat(json!({ "sshkeys": key }), "/nodes/{node}/qemu").unwrap()[0].1, got[0].1);
    }

    #[test]
    fn does_not_double_encode_a_value_read_back() {
        assert_eq!(encode_ssh_keys("ssh-ed25519%20AAAA%2BB%0A"), "ssh-ed25519%20AAAA%2BB%0A");
    }

    #[test]
    fn leaves_lxc_keys_plain() {
        let key = "ssh-ed25519 AAAA+B me@host";
        assert_eq!(flat(json!({ "ssh-public-keys": key }), "/nodes/{node}/lxc").unwrap(), pairs(&[("ssh-public-keys", key)]));
        assert_eq!(flat(json!({ "sshkeys": key }), "/nodes/{node}/lxc/{vmid}/config").unwrap(), pairs(&[("sshkeys", key)]));
    }

    #[test]
    fn form_encodes_spaces_as_percent_20() {
        assert_eq!(encode_pairs(&pairs(&[("a b", "c d&e=f")])), "a%20b=c%20d%26e%3Df");
    }
}
