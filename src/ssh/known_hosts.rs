//! known_hosts, pinned fingerprints and the host key policy: the verdict on a key a host presents.

use super::HostKeyInfo;
use crate::config::HostKeyPolicy;
use crate::errors::{PveError, Result, kind};
use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, STANDARD_NO_PAD};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Revoked,
    CertAuthority,
}

#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    pub marker: Option<Marker>,
    /// The host field as written: a comma list, patterns, or one |1|salt|hash.
    pub hosts: String,
    pub key_type: String,
    pub key: Vec<u8>,
}

static BASE64_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap());
static PUBLIC_KEY_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s|$)").unwrap());

/// Base64 as Node's Buffer.from reads it: lenient about padding and about the unused low bits
/// of the last character.
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent));

fn decode_base64(text: &str) -> Vec<u8> {
    LENIENT_BASE64.decode(text.trim_end_matches('=')).unwrap_or_default()
}

/// Ignores what it cannot read: a bad line must not make the other entries count for less.
pub fn parse_known_hosts(text: &str) -> Vec<KnownHostEntry> {
    let mut entries = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields: Vec<&str> = line.split_whitespace().collect();
        let mut marker = None;
        if fields[0].starts_with('@') {
            let name = fields.remove(0);
            marker = match name {
                "@revoked" => Some(Marker::Revoked),
                "@cert-authority" => Some(Marker::CertAuthority),
                _ => continue,
            };
        }
        let (Some(hosts), Some(key_type), Some(encoded)) = (fields.first(), fields.get(1), fields.get(2)) else { continue };
        if !BASE64_FIELD.is_match(encoded) {
            continue;
        }
        let key = decode_base64(encoded);
        if key.is_empty() {
            continue;
        }
        entries.push(KnownHostEntry { marker, hosts: hosts.to_string(), key_type: key_type.to_string(), key });
    }
    entries
}

/// The name known_hosts uses: the host alone on port 22, [host]:port otherwise.
pub fn known_hosts_name(host: &str, port: u16) -> String {
    let lower = host.to_lowercase();
    if port == 22 { lower } else { format!("[{lower}]:{port}") }
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut body = String::new();
    for c in pattern.chars() {
        match c {
            '*' => body.push_str(".*"),
            '?' => body.push('.'),
            other => body.push_str(&regex::escape(&other.to_string())),
        }
    }
    Regex::new(&format!("(?i)^{body}$")).is_ok_and(|r| r.is_match(name))
}

fn hashed_matches(field: &str, name: &str) -> bool {
    let parts: Vec<&str> = field.split('|').collect();
    if parts.len() != 4 || parts[1] != "1" {
        return false;
    }
    let expected = decode_base64(parts[3]);
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&decode_base64(parts[2])) else { return false };
    mac.update(name.as_bytes());
    let actual = mac.finalize().into_bytes();
    expected.len() == actual.len() && expected.as_slice() == actual.as_slice()
}

/// Same rules as OpenSSH: any matching negated pattern excludes the host, whatever else matches.
pub fn host_field_matches(field: &str, name: &str) -> bool {
    if field.starts_with('|') {
        return hashed_matches(field, name);
    }
    let mut matched = false;
    for pattern in field.split(',') {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_matches(negated, name) {
                return false;
            }
        } else if glob_matches(pattern, name) {
            matched = true;
        }
    }
    matched
}

/// SHA256:base64 without padding, as ssh-keygen prints it, of the wire-format key blob.
pub fn fingerprint_of(key: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(key)))
}

/// The algorithm name at the start of an SSH public key blob.
pub fn key_type_of(key: &[u8]) -> String {
    if key.len() < 4 {
        return "unknown".into();
    }
    let length = u32::from_be_bytes([key[0], key[1], key[2], key[3]]) as usize;
    if length > 0 && 4 + length <= key.len() {
        // latin1, as Node reads it.
        key[4..4 + length].iter().map(|&b| b as char).collect()
    } else {
        "unknown".into()
    }
}

pub fn normalize_fingerprint(value: &str) -> String {
    value.trim().trim_end_matches('=').to_string()
}

/// Public key lines to blobs: "ssh-ed25519 AAAA... comment", as in ssh_host_*_key.pub.
pub fn parse_public_key_lines(text: &str) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        let Some(m) = PUBLIC_KEY_LINE.captures(line) else { continue };
        let key = decode_base64(&m[2]);
        if key_type_of(&key) == m[1] {
            keys.push(key);
        }
    }
    keys
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostStatus {
    Known,
    Revoked,
    Changed,
    OtherType,
    Unknown,
}

pub fn check_known_hosts(entries: &[KnownHostEntry], name: &str, key: &[u8]) -> (KnownHostStatus, Vec<String>) {
    let kind = key_type_of(key);
    let for_host: Vec<&KnownHostEntry> = entries.iter().filter(|e| e.marker != Some(Marker::CertAuthority) && host_field_matches(&e.hosts, name)).collect();
    // Revocation goes by the key itself, and comes before any entry that would accept it.
    if for_host.iter().any(|e| e.marker == Some(Marker::Revoked) && e.key == key) {
        return (KnownHostStatus::Revoked, Vec::new());
    }
    let plain: Vec<&&KnownHostEntry> = for_host.iter().filter(|e| e.marker != Some(Marker::Revoked)).collect();
    if plain.iter().any(|e| e.key == key) {
        return (KnownHostStatus::Known, Vec::new());
    }
    let same_type: Vec<String> = plain.iter().filter(|e| key_type_of(&e.key) == kind).map(|e| fingerprint_of(&e.key)).collect();
    if !same_type.is_empty() {
        return (KnownHostStatus::Changed, same_type);
    }
    if !plain.is_empty() {
        return (KnownHostStatus::OtherType, plain.iter().map(|e| fingerprint_of(&e.key)).collect());
    }
    (KnownHostStatus::Unknown, Vec::new())
}

/// What every host key check needs to know.
#[derive(Debug, Clone)]
pub struct HostKeyCheck {
    /// For messages: node pve1, guest 101.
    pub label: String,
    pub host: String,
    pub port: u16,
    pub policy: HostKeyPolicy,
    pub known_hosts_file: String,
    /// SHA256:... set by the operator or given on the call.
    pub pinned: Option<String>,
    /// The keys the host must present, read through a path already authenticated.
    pub allowed_keys: Option<Vec<Vec<u8>>>,
}

fn read_entries(file: &str) -> Vec<KnownHostEntry> {
    // Unreadable means nothing is known, and an unknown host is refused.
    std::fs::read_to_string(file).map(|t| parse_known_hosts(&t)).unwrap_or_default()
}

const VERIFY_HINT: &str = "Do not retry until a human has compared this fingerprint with the one on the host itself, from its console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. The operator can then pin it with PROXMOX_SSH_FINGERPRINTS or add it to known_hosts.";

fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().map(|s| Value::String(s.clone())).collect())
}

fn mismatch(check: &HostKeyCheck, key: &[u8], why: &str, expected: &[String]) -> PveError {
    let mut details = Map::new();
    details.insert("presented".into(), Value::String(fingerprint_of(key)));
    details.insert("key_type".into(), Value::String(key_type_of(key)));
    if !expected.is_empty() {
        details.insert("expected".into(), strings(expected));
    }
    PveError::new(kind::HOST_KEY_MISMATCH, format!("The host key of {} ({}:{}) {why}: nothing was sent to it.", check.label, check.host, check.port))
        .hint("This can be a reinstalled host or someone in the middle. Do not retry. A human has to check the host, and update what is known about it.")
        .details(Value::Object(details))
}

fn unknown(check: &HostKeyCheck, key: &[u8], why: &str, hint: &str, expected: &[String]) -> PveError {
    let mut details = Map::new();
    details.insert("fingerprint".into(), Value::String(fingerprint_of(key)));
    details.insert("key_type".into(), Value::String(key_type_of(key)));
    if !expected.is_empty() {
        details.insert("known_with_other_types".into(), strings(expected));
    }
    PveError::new(kind::HOST_KEY_UNKNOWN, format!("The host key of {} ({}:{}) {why}: nothing was sent to it.", check.label, check.host, check.port)).hint(hint).details(Value::Object(details))
}

fn append_entry(file: &str, name: &str, key: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = std::path::Path::new(file).parent().filter(|d| !d.as_os_str().is_empty()) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(dir)?;
    }
    let prefix = match std::fs::read_to_string(file) {
        Ok(current) if !current.is_empty() && !current.ends_with('\n') => "\n",
        _ => "",
    };
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(file)?;
    f.write_all(format!("{prefix}{name} {} {}\n", key_type_of(key), STANDARD.encode(key)).as_bytes())
}

/// The verdict on a key presented by a host. Fails unless it is accepted, and nothing is sent
/// before this has run: the handshake stops here, ahead of authentication.
///
/// A revoked key and a pin that does not match are refused even under policy off: those are
/// explicit statements by the operator, and off only waives what is not stated anywhere.
pub fn verify_host_key(check: &HostKeyCheck, key: &[u8]) -> Result<HostKeyInfo> {
    let info = HostKeyInfo { kind: key_type_of(key), fingerprint: fingerprint_of(key) };
    let name = known_hosts_name(&check.host, check.port);
    let (status, expected) = check_known_hosts(&read_entries(&check.known_hosts_file), &name, key);
    if status == KnownHostStatus::Revoked {
        return Err(mismatch(check, key, "is marked @revoked in known_hosts", &[]));
    }
    if let Some(pinned) = &check.pinned {
        if normalize_fingerprint(pinned) != info.fingerprint {
            return Err(mismatch(check, key, "does not match the pinned fingerprint", std::slice::from_ref(pinned)));
        }
    }
    if let Some(allowed) = &check.allowed_keys {
        if allowed.iter().any(|k| k == key) {
            return Ok(info);
        }
        let fps: Vec<String> = allowed.iter().map(|k| fingerprint_of(k)).collect();
        return Err(mismatch(check, key, "is not one of the keys found inside the guest", &fps));
    }
    if check.pinned.is_some() || check.policy == HostKeyPolicy::Off {
        return Ok(info);
    }
    match status {
        KnownHostStatus::Known => return Ok(info),
        KnownHostStatus::Changed => return Err(mismatch(check, key, "differs from the one in known_hosts", &expected)),
        KnownHostStatus::OtherType => {
            // An attacker could offer another key type to look new: this is never trusted on first use.
            return Err(unknown(check, key, "is of a type that known_hosts does not list for this host", &format!("known_hosts has other types of key for this host. {VERIFY_HINT}"), &expected));
        }
        _ => {}
    }
    if check.policy != HostKeyPolicy::AcceptNew {
        return Err(unknown(check, key, "is not in known_hosts", VERIFY_HINT, &[]));
    }
    if let Err(e) = append_entry(&check.known_hosts_file, &name, key) {
        return Err(unknown(check, key, &format!("could not be recorded in {} ({e})", check.known_hosts_file), VERIFY_HINT, &[]));
    }
    Ok(info)
}

/// What ssh2 offered when nothing is known about the host, in its own default order.
pub const DEFAULT_HOST_KEY_ALGORITHMS: [&str; 7] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"];

/// Asks first for the key types already known for this host, as OpenSSH does. Otherwise a host
/// recorded with its RSA key would present ed25519 and look unknown.
pub fn host_key_algorithms(check: &HostKeyCheck) -> Option<Vec<String>> {
    let name = known_hosts_name(&check.host, check.port);
    let keys: Vec<Vec<u8>> = match &check.allowed_keys {
        Some(k) => k.clone(),
        None => read_entries(&check.known_hosts_file).into_iter().filter(|e| e.marker.is_none() && host_field_matches(&e.hosts, &name)).map(|e| e.key).collect(),
    };
    let mut preferred: Vec<String> = Vec::new();
    for key in &keys {
        let kind = key_type_of(key);
        let algorithms: Vec<&str> = if kind == "ssh-rsa" { vec!["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"] } else { vec![kind.as_str()] };
        for a in algorithms {
            if DEFAULT_HOST_KEY_ALGORITHMS.contains(&a) && !preferred.iter().any(|p| p == a) {
                preferred.push(a.to_string());
            }
        }
    }
    if preferred.is_empty() {
        return None;
    }
    let rest: Vec<String> = DEFAULT_HOST_KEY_ALGORITHMS.iter().filter(|a| !preferred.iter().any(|p| p == *a)).map(|a| a.to_string()).collect();
    preferred.extend(rest);
    Some(preferred)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(kind: &str, seed: u8) -> Vec<u8> {
        let mut out = (kind.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind.as_bytes());
        out.extend_from_slice(&32u32.to_be_bytes());
        out.extend((0..32).map(|i| seed.wrapping_add(i)));
        out
    }

    fn line(key: &[u8]) -> String {
        format!("{} {}", key_type_of(key), STANDARD.encode(key))
    }

    fn hashed_field(name: &str) -> String {
        let salt: Vec<u8> = (0..20).map(|i| i * 7).collect();
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(name.as_bytes());
        format!("|1|{}|{}", STANDARD.encode(&salt), STANDARD.encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn reads_entries_markers_comments_and_blank_lines() {
        let key = blob("ssh-ed25519", 1);
        let l = line(&key);
        let entries = parse_known_hosts(&format!("# a comment\n\nhost1 {l} a trailing comment\n  host2 {l}\n@revoked host3 {l}\n@cert-authority *.example.org {l}\n"));
        let got: Vec<(Option<Marker>, &str)> = entries.iter().map(|e| (e.marker, e.hosts.as_str())).collect();
        assert_eq!(got, vec![(None, "host1"), (None, "host2"), (Some(Marker::Revoked), "host3"), (Some(Marker::CertAuthority), "*.example.org")]);
        assert_eq!(entries[0].key, key);
        let crlf = parse_known_hosts(&format!("host1 {l}\r\nhost2 {l}\r\n"));
        assert_eq!(crlf.iter().map(|e| e.hosts.as_str()).collect::<Vec<_>>(), vec!["host1", "host2"]);
        let junk = parse_known_hosts(&format!("junk\nhost1 {l}\nhost2 ssh-ed25519 not*base64\n@unknown-marker host3 {l}\nhost4\n"));
        assert_eq!(junk.iter().map(|e| e.hosts.as_str()).collect::<Vec<_>>(), vec!["host1"]);
    }

    #[test]
    fn names_and_patterns() {
        assert_eq!(known_hosts_name("PVE1", 22), "pve1");
        assert_eq!(known_hosts_name("10.0.0.1", 2222), "[10.0.0.1]:2222");
        assert_eq!(known_hosts_name("2001:db8::1", 22), "2001:db8::1");
        assert_eq!(known_hosts_name("2001:db8::1", 2222), "[2001:db8::1]:2222");
        assert!(host_field_matches("pve1,pve2", "pve2"));
        assert!(!host_field_matches("pve1,pve2", "pve3"));
        assert!(host_field_matches("PVE1", "pve1"));
        assert!(host_field_matches("*.example.org", "a.example.org"));
        assert!(!host_field_matches("*.example.org", "example.org"));
        assert!(host_field_matches("pve?", "pve1"));
        assert!(!host_field_matches("pve?", "pve12"));
        assert!(!host_field_matches("*,!pve1", "pve1"));
        assert!(host_field_matches("*,!pve1", "pve2"));
        assert!(!host_field_matches("10.0.0.1", "10x0x0x1"));
        assert!(host_field_matches("[10.0.0.1]:2222", "[10.0.0.1]:2222"));
        let field = hashed_field("pve1");
        assert!(host_field_matches(&field, "pve1"));
        assert!(!host_field_matches(&field, "pve2"));
        assert!(!host_field_matches(&field.replace("|1|", "|2|"), "pve1"));
        assert!(!host_field_matches("|1|notenoughparts", "pve1"));
    }

    #[test]
    fn fingerprints_and_types() {
        let key = blob("ssh-ed25519", 3);
        let fp = fingerprint_of(&key);
        assert!(Regex::new(r"^SHA256:[A-Za-z0-9+/]{43}$").unwrap().is_match(&fp));
        assert_eq!(fp, format!("SHA256:{}", STANDARD.encode(Sha256::digest(&key)).trim_end_matches('=')));
        assert_eq!(key_type_of(&blob("ecdsa-sha2-nistp256", 1)), "ecdsa-sha2-nistp256");
        assert_eq!(key_type_of(&[0, 0, 0, 9, 1]), "unknown");
        assert_eq!(key_type_of(&[0, 0]), "unknown");
    }

    #[test]
    fn statuses() {
        let key = blob("ssh-ed25519", 1);
        let other = blob("ssh-ed25519", 2);
        let entries = parse_known_hosts(&format!("pve1 {}\n", line(&key)));
        assert_eq!(check_known_hosts(&entries, "pve1", &key).0, KnownHostStatus::Known);
        assert_eq!(check_known_hosts(&entries, "pve1", &other).0, KnownHostStatus::Changed);
        assert_eq!(check_known_hosts(&entries, "pve2", &key).0, KnownHostStatus::Unknown);
        let ecdsa = parse_known_hosts(&format!("pve1 {}\n", line(&blob("ecdsa-sha2-nistp256", 4))));
        assert_eq!(check_known_hosts(&ecdsa, "pve1", &key).0, KnownHostStatus::OtherType);
        let revoked = parse_known_hosts(&format!("@revoked * {}\npve1 {}\n", line(&key), line(&key)));
        assert_eq!(check_known_hosts(&revoked, "pve1", &key).0, KnownHostStatus::Revoked);
    }

    #[test]
    fn public_key_lines() {
        let key = blob("ssh-ed25519", 9);
        let keys = parse_public_key_lines(&format!("{} root@host\nsomething else\nssh-rsa {} wrong type\n", line(&key), STANDARD.encode(&key)));
        assert_eq!(keys, vec![key]);
    }

    #[test]
    fn verdicts() {
        let dir = std::env::temp_dir().join(format!("pvemcp-kh-{}", uuid::Uuid::new_v4()));
        let file = dir.join("sub").join("known_hosts").to_string_lossy().into_owned();
        let key = blob("ssh-ed25519", 5);
        let check = |policy, pinned: Option<&str>| HostKeyCheck { label: "node pve1".into(), host: "127.0.0.1".into(), port: 2222, policy, known_hosts_file: file.clone(), pinned: pinned.map(str::to_string), allowed_keys: None };
        assert_eq!(verify_host_key(&check(HostKeyPolicy::Strict, None), &key).unwrap_err().kind, "host_key_unknown");
        assert!(verify_host_key(&check(HostKeyPolicy::Off, None), &key).is_ok());
        assert!(verify_host_key(&check(HostKeyPolicy::AcceptNew, None), &key).is_ok());
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text, format!("[127.0.0.1]:2222 {}\n", line(&key)));
        assert!(verify_host_key(&check(HostKeyPolicy::Strict, None), &key).is_ok());
        let other = blob("ssh-ed25519", 6);
        let e = verify_host_key(&check(HostKeyPolicy::AcceptNew, None), &other).unwrap_err();
        assert_eq!(e.kind, "host_key_mismatch");
        assert_eq!(e.details.unwrap()["expected"][0], fingerprint_of(&key));
        let fp = fingerprint_of(&other);
        assert!(verify_host_key(&check(HostKeyPolicy::Strict, Some(&format!("{fp}="))), &other).is_ok());
        assert_eq!(verify_host_key(&check(HostKeyPolicy::Off, Some(&fp)), &key).unwrap_err().kind, "host_key_mismatch");
        assert_eq!(host_key_algorithms(&check(HostKeyPolicy::Strict, None)).unwrap()[0], "ssh-ed25519");
        let _ = std::fs::remove_dir_all(dir);
    }
}
