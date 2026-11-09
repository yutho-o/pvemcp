//! Secrets never leave this server: key-based masking, path rules, and scrubbing of free text.

use crate::errors::{PveError, Result, kind};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const REDACTED: &str = "[REDACTED]";
/// What Proxmox itself shows instead of cipassword and the like.
const PROXMOX_MASK: &str = "**********";

const EXACT: &[&str] = &["password", "secret", "key", "keys", "keyring", "ticket", "csrfpreventiontoken", "token", "cookie", "authorization", "cert", "certkey", "recovery", "otp", "totp"];

const SUBSTRINGS: &[&str] = &[
    "password", "passwd", "passphrase", "secret", "credential", "private_key", "privatekey", "private-key", "authkey", "auth_key", "apikey", "api_key", "api-key", "hmac", "ticket", "csrf", "bindpw", "lock-token", "lock_token", "encryption-key", "encryption_key", "client-key", "client_key", "psk", "otel-headers",
];

/// Keys that match a pattern above but hold nothing secret. Agents need these.
const NOT_SECRET: &[&str] = &[
    "tokenid", "full-tokenid", "token-coefficient", "tokens", "sshkeys", "ssh-public-keys", "pubkey", "public_key", "public-key", "publickey", "fingerprint", "keyboard", "verify-certificate", "generate-password", "passwordauth", "hostkey", "host_key",
];

pub fn is_sensitive_key(key: &str) -> bool {
    // Capitalised, this is the name of an APT repository option: {"Key": "Types", "Values": [...]}.
    if key == "Key" {
        return false;
    }
    let k = key.to_lowercase();
    if NOT_SECRET.contains(&k.as_str()) {
        return false;
    }
    if EXACT.contains(&k.as_str()) {
        return true;
    }
    if SUBSTRINGS.iter().any(|s| k.contains(s)) {
        return true;
    }
    (k.ends_with("_key") || k.ends_with("-key")) && !k.contains("pub") && !k.contains("host")
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

static PEM_PRIVATE: LazyLock<Regex> = LazyLock::new(|| re(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)"));
static ANSI: LazyLock<Regex> = LazyLock::new(|| re(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\^_])"));
static CONTROL_CHARS: LazyLock<Regex> = LazyLock::new(|| re(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u{80}-\u{9F}]"));
/// http://user:password@proxy: /cluster/options and storage URLs can hold this.
static URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@"));
/// An API token as an Authorization header writes it, or the cookie of a login.
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| re(r#"\b(PVEAPIToken=|PVEAuthCookie=)[^\s;"',]+"#));
/// PVE:root@pam:65A1B2C3::signature, and PVEVNC:65A1B2C3::signature for a console.
static PVE_TICKET: LazyLock<Regex> = LazyLock::new(|| re(r#"\bPVE[A-Z]*:[^\s"',;]*::[A-Za-z0-9+/=_-]+"#));

/// Removes key material from any free text and strips escape sequences and control characters:
/// logs, guest names and command output can carry attacker-chosen bytes.
pub fn scrub_text(text: &str) -> String {
    let out = PEM_PRIVATE.replace_all(text, REDACTED);
    let out = URL_CREDENTIALS.replace_all(&out, format!("${{1}}{REDACTED}@").as_str());
    let out = AUTH_HEADER.replace_all(&out, format!("${{1}}{REDACTED}").as_str());
    let out = PVE_TICKET.replace_all(&out, REDACTED);
    let out = ANSI.replace_all(&out, "");
    CONTROL_CHARS.replace_all(&out, "").into_owned()
}

pub fn is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
        _ => false,
    }
}

pub fn redact_json(value: &Value, keep: &HashSet<&str>) -> Value {
    match value {
        Value::String(s) => Value::String(scrub_text(s)),
        Value::Array(items) => Value::Array(items.iter().map(|v| redact_json(v, keep)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let masked = !keep.contains(k.as_str()) && is_sensitive_key(k) && !is_empty(Some(v));
                out.insert(k.clone(), if masked { Value::String(REDACTED.into()) } else { redact_json(v, keep) });
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn redact_value(value: &Value) -> Value {
    redact_json(value, &HashSet::new())
}

static WEBHOOK: LazyLock<Regex> = LazyLock::new(|| re(r"^/cluster/notifications/endpoints/webhook(?:/|$)"));
static CONFIG_ROWS: LazyLock<Regex> = LazyLock::new(|| re(r"^/nodes/[^/]+/(?:qemu|lxc)/[^/]+/pending$|^/nodes/[^/]+/qemu/[^/]+/cloudinit$"));

struct Rule {
    pattern: Regex,
    keys: &'static [&'static str],
}

/// Fields whose name says nothing, but whose content is a secret on this path:
/// a plugin's "data" holds DNS API credentials, a new token's "value" is the token itself.
static PATH_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule { pattern: re(r"^/cluster/acme/plugins(?:/|$)"), keys: &["data"] },
        Rule { pattern: re(r"^/access/users/[^/]+/token/[^/]+$"), keys: &["value"] },
        Rule { pattern: re(r"^/cluster/config/join$"), keys: &["corosync_authkey"] },
        Rule { pattern: re(r"^/nodes/[^/]+/ceph/"), keys: &["keyring"] },
        Rule { pattern: WEBHOOK.clone(), keys: &["header", "body"] },
        Rule { pattern: re(r"^/nodes/[^/]+/subscription$"), keys: &["signature"] },
    ]
});

/// Fields whose name looks secret, but that are something else on this path, where masking them
/// makes the answer useless.
static KEEP_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule { pattern: CONFIG_ROWS.clone(), keys: &["key"] },
        Rule { pattern: re(r"^/nodes/[^/]+/storage/[^/]+/import-metadata$"), keys: &["key"] },
        Rule { pattern: re(r"^/cluster/config/totem$"), keys: &["token"] },
    ]
});

/// In these rows the setting is named by "key": cipassword must not show because it is called "value" there.
fn mask_config_rows(rows: Value) -> Value {
    let Value::Array(items) = rows else { return rows };
    Value::Array(
        items
            .into_iter()
            .map(|row| {
                let Value::Object(mut map) = row else { return row };
                let sensitive = matches!(map.get("key"), Some(Value::String(k)) if is_sensitive_key(k));
                if sensitive {
                    for field in ["value", "pending"] {
                        if !is_empty(map.get(field)) {
                            map.insert(field.into(), Value::String(REDACTED.into()));
                        }
                    }
                }
                Value::Object(map)
            })
            .collect(),
    )
}

static URL_PATH: LazyLock<Regex> = LazyLock::new(|| re(r"(?is)^([a-z][a-z0-9+.-]*://[^/?#]+)[/?#].*$"));

/// The address stays, for a human to recognise it. Its path is the credential on most chat services.
fn mask_url_path(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(URL_PATH.replace(&s, format!("${{1}}/{REDACTED}").as_str()).into_owned()),
        other => other,
    }
}

fn mask_webhook_urls(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(mask_webhook_urls).collect()),
        Value::Object(mut map) => {
            if let Some(url) = map.get_mut("url") {
                *url = mask_url_path(url.take());
            }
            Value::Object(map)
        }
        other => other,
    }
}

fn mask_keys(value: Value, keys: &[&str]) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(|v| mask_keys(v, keys)).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let v = if keys.contains(&k.as_str()) && !is_empty(Some(&v)) { Value::String(REDACTED.into()) } else { mask_keys(v, keys) };
                    (k, v)
                })
                .collect(),
        ),
        other => other,
    }
}

/// Key-based redaction plus the rules for this path, given as a template or a concrete path.
pub fn redact_response(path: &str, value: &Value) -> Value {
    let keep: HashSet<&str> = KEEP_RULES.iter().find(|r| r.pattern.is_match(path)).map(|r| r.keys.iter().copied().collect()).unwrap_or_default();
    let mut out = redact_json(value, &keep);
    if CONFIG_ROWS.is_match(path) {
        out = mask_config_rows(out);
    }
    if WEBHOOK.is_match(path) {
        out = mask_webhook_urls(out);
    }
    for rule in PATH_RULES.iter() {
        if rule.pattern.is_match(path) {
            out = mask_keys(out, rule.keys);
        }
    }
    out
}

/// Parameters of a write that hold what they should not show in the audit log or a dry run.
static REQUEST_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule { pattern: re(r"^/cluster/acme/plugins(?:/|$)"), keys: &["data"] },
        Rule { pattern: re(r"^/nodes/[^/]+/qemu/[^/]+/agent/file-write$"), keys: &["content"] },
        Rule { pattern: re(r"^/nodes/[^/]+/qemu/[^/]+/agent/exec$"), keys: &["input-data"] },
        Rule { pattern: re(r"^/access/tfa/[^/]+(?:/[^/]+)?$"), keys: &["value"] },
        Rule { pattern: WEBHOOK.clone(), keys: &["header", "body"] },
    ]
});

/// What a write sent, as it may be logged or shown back. Takes a template or a concrete path.
pub fn redact_request(path: &str, params: &Value) -> Value {
    let mut out = redact_value(params);
    if WEBHOOK.is_match(path) {
        out = mask_webhook_urls(out);
    }
    for rule in REQUEST_RULES.iter() {
        if rule.pattern.is_match(path) {
            out = mask_keys(out, rule.keys);
        }
    }
    out
}

/// A placeholder written back as a real value would overwrite the secret it stands for.
pub fn assert_no_redacted_value(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::String(s) => {
            if s.contains(REDACTED) || s.contains(PROXMOX_MASK) {
                let which = if s.contains(REDACTED) { REDACTED } else { PROXMOX_MASK };
                return Err(PveError::new(kind::INVALID_INPUT, format!("The request to {path} contains a redaction placeholder ({which}), which would overwrite a real secret.")).hint("Leave the field out to keep its current value."));
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(|v| assert_no_redacted_value(v, path)),
        Value::Object(map) => map.values().try_for_each(|v| assert_no_redacted_value(v, path)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masks() {
        assert!(is_sensitive_key("password"));
        assert!(!is_sensitive_key("tokenid"));
        assert!(is_sensitive_key("ssl_key"));
        assert!(!is_sensitive_key("hostkey"));
        assert_eq!(scrub_text("see http://u:p@h/x"), "see http://[REDACTED]@h/x");
        assert_eq!(scrub_text("a\x1b[31mred\x07"), "ared");
        assert_eq!(scrub_text("PVEAPIToken=root@pam!x=abc"), "PVEAPIToken=[REDACTED]");
        let v = redact_response("/cluster/notifications/endpoints/webhook/x", &json!({"url": "https://hooks.example/abc/def", "header": [1]}));
        assert_eq!(v, json!({"url": "https://hooks.example/[REDACTED]", "header": "[REDACTED]"}));
        let rows = redact_response("/nodes/a/qemu/1/pending", &json!([{"key": "cipassword", "value": "x"}, {"key": "cores", "value": 2}]));
        assert_eq!(rows, json!([{"key": "cipassword", "value": "[REDACTED]"}, {"key": "cores", "value": 2}]));
    }

    // Ported from test/redact-params.test.ts.

    fn rj(v: Value) -> Value {
        redact_json(&v, &HashSet::new())
    }

    #[test]
    fn treats_these_as_secret() {
        for key in [
            "password", "secret", "token", "eab-hmac-key", "key", "cipassword", "encryption-key", "keyring", "keys", "cert", "certkey", "client-key", "confirmation-password", "lock-token",
            "corosync_authkey", "ticket", "CSRFPreventionToken", "vncticket", "smtp_password",
        ] {
            assert!(is_sensitive_key(key), "{key}");
        }
    }

    #[test]
    fn keeps_what_an_agent_needs() {
        for key in [
            "sshkeys", "ssh-public-keys", "fingerprint", "public_key", "public-key", "tokenid", "full-tokenid", "tokens", "keyboard", "token-coefficient", "verify-certificate", "keyctl",
            "pre-enrolled-keys", "master-pubkey", "privsep", "privs", "unprivileged", "digest", "description", "Key", "totp-locked", "public-key-bits", "public-key-type", "pve_fp", "pem",
            "filename", "certificates",
        ] {
            assert!(!is_sensitive_key(key), "{key}");
        }
    }

    #[test]
    fn masks_nested_secrets_keeps_empty_ones_visible() {
        assert_eq!(
            rj(json!({ "a": { "password": "x", "name": "n" }, "list": [{ "secret": "s" }], "cipassword": "" })),
            json!({ "a": { "password": REDACTED, "name": "n" }, "list": [{ "secret": REDACTED }], "cipassword": "" })
        );
        let users = json!([{ "userid": "root@pam", "keys": "x", "tokens": [{ "tokenid": "mcp", "privsep": 1, "expire": 0 }] }]);
        assert_eq!(rj(users), json!([{ "userid": "root@pam", "keys": REDACTED, "tokens": [{ "tokenid": "mcp", "privsep": 1, "expire": 0 }] }]));
        let repo = json!({ "options": [{ "Key": "Types", "Values": ["deb"] }] });
        assert_eq!(rj(repo.clone()), repo);
    }

    #[test]
    fn applies_path_rules_to_fields_whose_name_says_nothing() {
        assert_eq!(redact_response("/cluster/acme/plugins", &json!([{ "plugin": "cf", "data": "CF_Token=abc" }])), json!([{ "plugin": "cf", "data": REDACTED }]));
        assert_eq!(redact_response("/cluster/acme/plugins/{id}", &json!({ "plugin": "cf", "data": "CF_Token=abc" })), json!({ "plugin": "cf", "data": REDACTED }));
        assert_eq!(
            redact_response("/access/users/{userid}/token/{tokenid}", &json!({ "full-tokenid": "a@b!c", "value": "uuid" })),
            json!({ "full-tokenid": "a@b!c", "value": REDACTED })
        );
        assert_eq!(redact_response("/cluster/config/join", &json!({ "corosync_authkey": "x", "pve_fp": "AA" })), json!({ "corosync_authkey": REDACTED, "pve_fp": "AA" }));
        assert_eq!(redact_response("/nodes/{node}/rrddata", &json!({ "data": "x", "value": "y" })), json!({ "data": "x", "value": "y" }));
    }

    #[test]
    fn scrubs_pem_private_keys_even_unterminated() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(scrub_text(&format!("before {pem} after")), format!("before {REDACTED} after"));
        assert_eq!(scrub_text("x -----BEGIN RSA PRIVATE KEY-----\nabc"), format!("x {REDACTED}"));
        assert!(scrub_text("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----").contains("BEGIN CERTIFICATE"));
        assert_eq!(rj(json!({ "log": pem })), json!({ "log": REDACTED }));
    }

    #[test]
    fn strips_escapes_and_control_characters_keeps_line_structure() {
        assert_eq!(scrub_text("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(scrub_text("\u{1b}]0;title\u{7}ok"), "ok");
        assert_eq!(scrub_text("a\u{0}b\u{8}c\u{9b}d"), "abcd");
        assert_eq!(scrub_text("line1\nline2\tx\r\n"), "line1\nline2\tx\r\n");
    }

    #[test]
    fn removes_credentials_from_urls() {
        assert_eq!(scrub_text("http_proxy: http://user:pw@proxy:3128/x"), format!("http_proxy: http://{REDACTED}@proxy:3128/x"));
        assert_eq!(scrub_text("https://example.com:8006/api"), "https://example.com:8006/api");
    }

    #[test]
    fn refuses_a_placeholder_written_back_as_a_real_value() {
        for v in [json!(REDACTED), json!("**********"), json!({ "a": { "b": [REDACTED] } }), json!({ "cipassword": "**********" }), json!({ "prop": format!("user=x,password={REDACTED}") })] {
            assert!(assert_no_redacted_value(&v, "/x").is_err(), "{v}");
        }
        assert!(assert_no_redacted_value(&json!({ "a": "fine", "n": 1, "t": true }), "/x").is_ok());
    }

    fn sorted_names(lists: impl Iterator<Item = String>) -> Vec<String> {
        let set: std::collections::BTreeSet<String> = lists.collect();
        set.into_iter().collect()
    }

    #[test]
    fn masks_exactly_these_returned_fields_of_the_whole_api() {
        let fields = sorted_names(crate::catalog::CATALOG.endpoints.iter().flat_map(|e| {
            e.returns.properties.clone().unwrap_or_default().into_iter().chain(e.returns.item_properties.clone().unwrap_or_default())
        }));
        assert!(fields.len() > 300);
        let secret: Vec<&str> = fields.iter().map(String::as_str).filter(|k| is_sensitive_key(k)).collect();
        assert_eq!(secret, vec!["CSRFPreventionToken", "cert", "cipassword", "corosync_authkey", "key", "keys", "lock-token", "password", "recovery", "secret", "ticket"]);
    }

    #[test]
    fn masks_exactly_these_parameters_of_the_whole_api() {
        let params = sorted_names(crate::catalog::CATALOG.endpoints.iter().flat_map(|e| e.params.keys().cloned()));
        let secret: Vec<&str> = params.iter().map(String::as_str).filter(|k| is_sensitive_key(k)).collect();
        assert_eq!(
            secret,
            vec![
                "cert", "certkey", "cipassword", "client-key", "confirmation-password", "eab-hmac-key", "encryption-key", "key", "keyring", "keys", "lock-token", "otel-headers", "otp", "password",
                "secret", "ticket", "token", "totp", "vncticket",
            ]
        );
    }

    #[test]
    fn keeps_setting_names_in_pending_changes_and_masks_secret_values() {
        let rows = json!([{ "key": "cores", "value": 2, "pending": 4 }, { "key": "cipassword", "value": "old", "pending": "new" }, { "key": "memory", "delete": 1 }]);
        let expected = json!([{ "key": "cores", "value": 2, "pending": 4 }, { "key": "cipassword", "value": REDACTED, "pending": REDACTED }, { "key": "memory", "delete": 1 }]);
        for path in ["/nodes/{node}/qemu/{vmid}/pending", "/nodes/pve1/qemu/100/pending", "/nodes/{node}/lxc/{vmid}/pending", "/nodes/{node}/qemu/{vmid}/cloudinit"] {
            assert_eq!(redact_response(path, &rows), expected, "{path}");
        }
        assert_eq!(redact_response("/nodes/{node}/subscription", &json!({ "key": "pve2c-abc" })), json!({ "key": REDACTED }));
        let answer = json!({ "warnings": [{ "type": "ignored", "key": "cores", "value": "2" }] });
        assert_eq!(redact_response("/nodes/{node}/storage/{storage}/import-metadata", &answer), answer);
    }

    #[test]
    fn keeps_the_corosync_token_timeout() {
        assert_eq!(redact_response("/cluster/config/totem", &json!({ "token": 3000, "version": 2 })), json!({ "token": 3000, "version": 2 }));
        assert_eq!(redact_response("/cluster/metrics/server/{id}", &json!({ "token": "abc" })), json!({ "token": REDACTED }));
    }

    #[test]
    fn masks_metric_headers_and_webhooks() {
        assert_eq!(
            redact_response("/cluster/metrics/server/{id}", &json!({ "otel-headers": "QXV0aDogeA==", "otel-path": "/v1/metrics" })),
            json!({ "otel-headers": REDACTED, "otel-path": "/v1/metrics" })
        );
        let hook = json!({ "name": "chat", "url": "https://hooks.example.com/services/T00/B00/XXXX?x=1", "method": "post", "header": ["name=Authorization,value=abc"], "body": "e30=", "secret": ["name=x"] });
        let masked = json!({ "name": "chat", "url": format!("https://hooks.example.com/{REDACTED}"), "method": "post", "header": REDACTED, "body": REDACTED, "secret": REDACTED });
        assert_eq!(redact_response("/cluster/notifications/endpoints/webhook/{name}", &hook), masked);
        assert_eq!(redact_response("/cluster/notifications/endpoints/webhook", &json!([hook])), json!([masked]));
        assert_eq!(redact_response("/cluster/notifications/endpoints/webhook/{name}", &json!({ "url": "https://hooks.example.com" })), json!({ "url": "https://hooks.example.com" }));
        let apl = json!([{ "location": "http://x/y", "url": "http://x/y" }]);
        assert_eq!(redact_response("/nodes/{node}/aplinfo", &apl), apl);
        assert_eq!(
            redact_response("/nodes/{node}/subscription", &json!({ "status": "active", "signature": "abc", "serverid": "X" })),
            json!({ "status": "active", "signature": REDACTED, "serverid": "X" })
        );
    }

    #[test]
    fn scrubs_tokens_and_tickets_quoted_in_free_text() {
        assert_eq!(scrub_text("Authorization: PVEAPIToken=root@pam!mcp=aaaa-bbbb"), format!("Authorization: PVEAPIToken={REDACTED}"));
        assert_eq!(scrub_text("Cookie: PVEAuthCookie=PVE:root@pam:65A1B2C3::c2ln; x=1"), format!("Cookie: PVEAuthCookie={REDACTED}; x=1"));
        assert_eq!(scrub_text("ticket PVE:root@pam:65A1B2C3::c2ln+/= end"), format!("ticket {REDACTED} end"));
        assert_eq!(scrub_text("vnc PVEVNC:65A1B2C3::c2ln end"), format!("vnc {REDACTED} end"));
        let upid = "UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:";
        assert_eq!(scrub_text(upid), upid);
        assert_eq!(scrub_text("PVE: all good"), "PVE: all good");
    }

    #[test]
    fn shows_a_write_as_it_may_be_logged() {
        let cases = [
            ("/cluster/acme/plugins", json!({ "id": "cf", "data": "CF_Token=abc" }), json!({ "id": "cf", "data": REDACTED })),
            ("/cluster/acme/plugins/cf", json!({ "data": "CF_Token=abc" }), json!({ "data": REDACTED })),
            ("/nodes/pve1/qemu/100/agent/file-write", json!({ "file": "/etc/x", "content": "hunter2" }), json!({ "file": "/etc/x", "content": REDACTED })),
            ("/nodes/pve1/qemu/100/agent/exec", json!({ "command": ["cat"], "input-data": "hunter2" }), json!({ "command": ["cat"], "input-data": REDACTED })),
            ("/access/tfa/root@pam", json!({ "type": "totp", "value": "123456", "totp": "otpauth://x" }), json!({ "type": "totp", "value": REDACTED, "totp": REDACTED })),
            (
                "/cluster/notifications/endpoints/webhook",
                json!({ "name": "x", "url": "https://h.example/secret", "header": ["a"], "body": "b" }),
                json!({ "name": "x", "url": format!("https://h.example/{REDACTED}"), "header": REDACTED, "body": REDACTED }),
            ),
            (
                "/cluster/metrics/server/x",
                json!({ "server": "h", "port": 1, "otel-headers": "abc", "token": "t" }),
                json!({ "server": "h", "port": 1, "otel-headers": REDACTED, "token": REDACTED }),
            ),
            (
                "/storage",
                json!({ "storage": "s", "type": "dir", "content": "iso,backup", "password": "p" }),
                json!({ "storage": "s", "type": "dir", "content": "iso,backup", "password": REDACTED }),
            ),
            ("/nodes/pve1/hosts", json!({ "data": "127.0.0.1 localhost" }), json!({ "data": "127.0.0.1 localhost" })),
            ("/cluster/ceph/flags/noout", json!({ "value": 1 }), json!({ "value": 1 })),
        ];
        for (path, params, expected) in cases {
            assert_eq!(redact_request(path, &params), expected, "{path}");
        }
    }
}
