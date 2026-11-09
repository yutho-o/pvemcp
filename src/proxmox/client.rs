//! The chokepoint: every call to the Proxmox API goes through here and through the policy.

use super::params::{encode_pairs, flatten_params};
use super::policy::{Decision, Gate, assert_not_protected, authorize, AuthorizeOptions};
use super::redact::{assert_no_redacted_value, redact_request, redact_response, scrub_text};
use super::tasks::DRY_RUN_UPID;
use super::{Api, RequestOptions, UploadFile};
use crate::catalog::find_endpoint;
use crate::config::InstanceConfig;
use crate::errors::{PveError, Result, kind};
use crate::js::encode_uri_component;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use regex::Regex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

const MAX_RETRIES: u32 = 2;
const MAX_CONCURRENCY: usize = 4;
const MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;
/// A ticket lasts two hours: renewing well before that means no request ever meets a dead one.
const TICKET_RENEW: Duration = Duration::from_secs(90 * 60);
const UPLOAD_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const PIN_MARK: &str = "pvemcp-pin-mismatch:";

/// A write that went out, or failed to: for the audit log and the node cache.
pub type WriteRecord = Map<String, Value>;
pub type OnWrite = Arc<dyn Fn(WriteRecord) + Send + Sync>;

struct RawResponse {
    status: u16,
    reason: String,
    content_type: String,
    body: String,
}

struct Ticket {
    ticket: String,
    csrf: String,
    at: Instant,
}

enum Body {
    Empty,
    Form(String),
    Upload { prefix: Vec<u8>, suffix: Vec<u8>, path: String, size: u64 },
}

struct WireRequest {
    method: &'static str,
    url: String,
    headers: Vec<(String, String)>,
    body: Body,
    timeout_ms: u64,
    /// Label for messages.
    label: String,
}

/// Connects, checks the pin, and only then lets the request out: no credential is ever written
/// to a server that fails it.
#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

fn fingerprint256(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let seen = fingerprint256(end_entity);
        if seen == self.pin { Ok(ServerCertVerified::assertion()) } else { Err(rustls::Error::General(format!("{PIN_MARK}{seen}"))) }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// PROXMOX_VERIFY_SSL=false: any certificate, still a real handshake.
#[derive(Debug)]
struct NoVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The CA file, or the system roots. A certificate that is itself in the CA file is trusted as
/// the server certificate too, as Node did: that is how a self-signed pve-ssl.pem is pinned by file.
/// Its host name is still checked.
#[derive(Debug)]
struct CaVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    trusted: Vec<CertificateDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for CaVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(end_entity, intermediates, name, ocsp, now) {
            Ok(ok) => Ok(ok),
            Err(err) if self.trusted.iter().any(|c| c.as_ref() == end_entity.as_ref()) => {
                let parsed = rustls::server::ParsedCertificate::try_from(end_entity).map_err(|_| err)?;
                rustls::client::verify_server_name(&parsed, name)?;
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn ca_certs(config: &InstanceConfig) -> Result<Vec<CertificateDer<'static>>> {
    let ca = config.ca.as_deref().unwrap_or("");
    let mut reader = std::io::BufReader::new(ca.as_bytes());
    rustls_pemfile::certs(&mut reader).map(|c| c.map_err(|e| PveError::config(format!("The CA file of instance \"{}\" cannot be read: {e}", config.name)))).collect()
}

pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_config(config: &InstanceConfig) -> Result<rustls::ClientConfig> {
    let provider = crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| PveError::config(format!("TLS setup failed: {e}")))?;
    let tls = if let Some(pin) = &config.fingerprint {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(PinVerifier { pin: pin.clone(), provider })).with_no_client_auth()
    } else if !config.verify_ssl {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerifier(provider))).with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(ca) = &config.ca {
            let mut reader = std::io::BufReader::new(ca.as_bytes());
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| PveError::config(format!("The CA file of instance \"{}\" cannot be read: {e}", config.name)))?;
                roots.add(cert).map_err(|e| PveError::config(format!("The CA file of instance \"{}\" holds an invalid certificate: {e}", config.name)))?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let trusted: Vec<CertificateDer<'static>> = if config.ca.is_some() { ca_certs(config)? } else { Vec::new() };
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| PveError::config(format!("TLS setup failed for instance \"{}\": {e}", config.name)))?;
        builder.dangerous().with_custom_certificate_verifier(Arc::new(CaVerifier { inner, trusted, provider })).with_no_client_auth()
    };
    Ok(tls)
}

/// Proxmox puts the real error in the reason phrase, and field errors in the body.
fn parse_error_body(body: &str) -> (Option<String>, Option<Map<String, Value>>) {
    let Ok(Value::Object(json)) = serde_json::from_str::<Value>(body) else { return (None, None) };
    let message = match json.get("message") {
        Some(Value::String(m)) => Some(scrub_text(m).trim().to_string()),
        _ => None,
    };
    let errors = match json.get("errors") {
        Some(Value::Object(errs)) => Some(errs.iter().map(|(k, v)| (k.clone(), Value::String(scrub_text(&crate::js::js_string(v)).trim().to_string()))).collect()),
        Some(Value::Array(items)) => Some(items.iter().enumerate().map(|(i, v)| (i.to_string(), Value::String(scrub_text(&crate::js::js_string(v)).trim().to_string()))).collect()),
        _ => None,
    };
    (message, errors)
}

static HTML_TYPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)text/html").unwrap());
static HTML_BODY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*<(!doctype|html)").unwrap());
static LOCK_TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\block|locked\b").unwrap());
static BOUNDARY_UNSAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["\r\n\\]"#).unwrap());

pub struct ProxmoxClient {
    pub config: InstanceConfig,
    unblocked: Vec<String>,
    on_write: Option<OnWrite>,
    keep_alive: reqwest::Client,
    single: reqwest::Client,
    base: String,
    token_header: Option<String>,
    ticket: AsyncMutex<Option<Ticket>>,
    slots: Semaphore,
}

impl ProxmoxClient {
    pub fn new(config: InstanceConfig, unblocked: Vec<String>, on_write: Option<OnWrite>) -> Result<Self> {
        let https = config.url.starts_with("https:");
        let build = |pool: bool| -> Result<reqwest::Client> {
            let mut b = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy();
            if !pool {
                b = b.pool_max_idle_per_host(0);
            } else {
                b = b.pool_max_idle_per_host(MAX_CONCURRENCY);
            }
            if https {
                b = b.use_preconfigured_tls(tls_config(&config)?);
            }
            b.build().map_err(|e| PveError::config(format!("HTTP client setup failed: {e}")))
        };
        let keep_alive = build(true)?;
        let single = build(false)?;
        let token_header = match (&config.token_id, &config.token_secret) {
            (Some(id), Some(secret)) => Some(format!("PVEAPIToken={id}={secret}")),
            _ => None,
        };
        let base = format!("{}/api2/json", config.url.trim_end_matches('/'));
        Ok(ProxmoxClient { config, unblocked, on_write, keep_alive, single, base, token_header, ticket: AsyncMutex::new(None), slots: Semaphore::new(MAX_CONCURRENCY) })
    }

    pub fn uses_token(&self) -> bool {
        self.token_header.is_some()
    }

    /// Everything before the first byte goes out: path, gates, token limits, protected guests, placeholders.
    fn prepare(&self, method: &str, path: &str, opts: &RequestOptions) -> Result<Decision> {
        let subject = self.config.subject();
        let decision = authorize(
            &subject,
            method,
            path,
            &self.unblocked,
            &AuthorizeOptions { read_only: opts.read_only.unwrap_or(false), dry_run: opts.dry_run.unwrap_or(false), path_params: opts.path_params.as_ref(), params: opts.params.as_ref() },
        )?;
        if let Some(template) = &decision.template {
            if let Some(endpoint) = find_endpoint(method, template) {
                if !endpoint.allowtoken && self.uses_token() {
                    return Err(PveError::new(kind::FORBIDDEN, format!("{method} {template} does not accept API tokens: Proxmox only allows it with a password login."))
                        .hint("Do not retry with a token. A human can do this in the web interface, or the operator can run this server with PROXMOX_USERNAME and PROXMOX_PASSWORD."));
                }
            }
        }
        assert_not_protected(&self.config.protected_vmids, method, &decision, opts.params.as_ref())?;
        if method != "GET" {
            if let Some(params) = &opts.params {
                assert_no_redacted_value(&Value::Object(params.clone()), &decision.path)?;
            }
        }
        Ok(decision)
    }

    pub async fn request_impl(&self, method: &str, path: &str, opts: RequestOptions) -> Result<Value> {
        let decision = self.prepare(method, path, &opts)?;
        let method = static_method(method);
        if method != "GET" && (opts.dry_run.unwrap_or(false) || self.config.dry_run) {
            return Ok(self.simulate_write(method, &decision, &opts, opts.params.as_ref()));
        }
        let pairs = flatten_params(decision.template.as_deref().unwrap_or(&decision.path), opts.params.as_ref())?;
        let wire = self.build_request(method, &decision, &pairs, &opts);
        let response = match self.send_authenticated(wire).await {
            Ok(r) => r,
            Err(e) => {
                self.record_write(method, &decision, opts.params.as_ref(), &format!("error: {}", e.message));
                return Err(e);
            }
        };
        self.record_write(method, &decision, opts.params.as_ref(), &response.status.to_string());
        self.parse(response, method, &decision, &opts)
    }

    /// POST with a multipart body read from a local file. Never retried, like any write.
    /// Fields come first: Proxmox reads them before spooling the file.
    pub async fn upload_impl(&self, path: &str, fields: Map<String, Value>, file: UploadFile, opts: RequestOptions) -> Result<Value> {
        let method = "POST";
        let mut prep_opts = opts.clone();
        prep_opts.params = Some(fields.clone());
        let decision = self.prepare(method, path, &prep_opts)?;
        let file_name = file.filename.clone().unwrap_or_else(|| std::path::Path::new(&file.local_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
        let mut logged = fields.clone();
        logged.insert("filename".into(), Value::String(file_name.clone()));
        if opts.dry_run.unwrap_or(false) || self.config.dry_run {
            return Ok(self.simulate_write(method, &decision, &opts, Some(&logged)));
        }
        let size = std::fs::metadata(&file.local_path).map_err(|e| PveError::new(kind::LOCAL_PATH_REFUSED, format!("The local path {} cannot be read: {e}.", file.local_path)))?.len();
        let boundary = format!("----pvemcp{:x}{:x}", crate::js::now_millis(), rand::random::<u64>());
        let safe_name = BOUNDARY_UNSAFE.replace_all(&file_name, "_");
        let mut head = String::new();
        for (name, value) in flatten_params(decision.template.as_deref().unwrap_or(&decision.path), Some(&fields))? {
            head.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        head.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{safe_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n", file.field.as_deref().unwrap_or("filename")));
        let prefix = head.into_bytes();
        let suffix = format!("\r\n--{boundary}--\r\n").into_bytes();
        let wire = WireRequest {
            method,
            url: format!("{}{}", self.base, decision.url_path),
            headers: vec![("Content-Type".into(), format!("multipart/form-data; boundary={boundary}")), ("Content-Length".into(), (prefix.len() as u64 + size + suffix.len() as u64).to_string())],
            body: Body::Upload { prefix, suffix, path: file.local_path.clone(), size },
            timeout_ms: opts.timeout_ms.unwrap_or(UPLOAD_TIMEOUT_MS),
            label: format!("{method} {}", decision.path),
        };
        let response = match self.send_authenticated(wire).await {
            Ok(r) => r,
            Err(e) => {
                self.record_write(method, &decision, Some(&logged), &format!("error: {}", e.message));
                return Err(e);
            }
        };
        self.record_write(method, &decision, Some(&logged), &response.status.to_string());
        self.parse(response, method, &decision, &opts)
    }

    fn build_request(&self, method: &'static str, decision: &Decision, pairs: &[(String, String)], opts: &RequestOptions) -> WireRequest {
        let encoded = encode_pairs(pairs);
        let mut url = format!("{}{}", self.base, decision.url_path);
        let mut headers = Vec::new();
        let body = if method == "POST" || method == "PUT" {
            headers.push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
            Body::Form(encoded)
        } else {
            if !encoded.is_empty() {
                url.push('?');
                url.push_str(&encoded);
            }
            Body::Empty
        };
        WireRequest { method, url, headers, body, timeout_ms: opts.timeout_ms.unwrap_or(self.config.timeout_ms), label: format!("{method} {}", decision.path) }
    }

    fn simulate_write(&self, method: &str, decision: &Decision, opts: &RequestOptions, params: Option<&Map<String, Value>>) -> Value {
        let params = params.filter(|p| !p.is_empty()).map(|p| redact_request(&decision.path, &Value::Object(p.clone())));
        if let Some(log) = &opts.dry_run_log {
            let mut entry = Map::new();
            entry.insert("method".into(), Value::String(method.into()));
            entry.insert("path".into(), Value::String(decision.path.clone()));
            if let Some(p) = params {
                entry.insert("params".into(), p);
            }
            log.lock().unwrap().push(Value::Object(entry));
        }
        let endpoint = decision.template.as_deref().and_then(|t| find_endpoint(method, t));
        // So that flows that go on to wait for a task still run: wait_for_task knows this one.
        if endpoint.is_some_and(|e| e.returns.kind == "string") { Value::String(DRY_RUN_UPID.into()) } else { json!({"dry_run": true}) }
    }

    fn record_write(&self, method: &str, decision: &Decision, params: Option<&Map<String, Value>>, status: &str) {
        if method == "GET" {
            return;
        }
        if let Some(on_write) = &self.on_write {
            let mut record = Map::new();
            record.insert("method".into(), Value::String(method.into()));
            record.insert("path".into(), Value::String(decision.path.clone()));
            if let Some(p) = params {
                record.insert("params".into(), redact_request(&decision.path, &Value::Object(p.clone())));
            }
            record.insert("status".into(), Value::String(scrub_text(status)));
            on_write(record);
        }
    }

    fn parse(&self, response: RawResponse, method: &str, decision: &Decision, opts: &RequestOptions) -> Result<Value> {
        if !(200..300).contains(&response.status) {
            return Err(self.error_for_status(&response, method, decision));
        }
        let label = format!("{method} {}", decision.path);
        if HTML_TYPE.is_match(&response.content_type) || HTML_BODY.is_match(&response.body) {
            return Err(PveError::new(kind::BAD_RESPONSE, format!("Proxmox answered {label} with an HTML page instead of JSON."))
                .hint("Check PROXMOX_URL: it should point at the Proxmox API, port 8006, without a reverse proxy login page in front."));
        }
        let keep_secrets = self.config.allow_sensitive && (opts.include_sensitive || matches!(decision.gate, Gate::Sensitive | Gate::Console) || decision.returns_secret);
        let json: Value = if response.body.is_empty() {
            Value::Object(Map::new())
        } else {
            match serde_json::from_str(&response.body) {
                Ok(v) => v,
                Err(_) => {
                    // Downloads (task log, journal, report) can answer in plain text.
                    if method == "GET" {
                        return Ok(Value::String(if keep_secrets { response.body } else { scrub_text(&response.body) }));
                    }
                    return Err(PveError::new(kind::BAD_RESPONSE, format!("Proxmox returned invalid JSON for {label}.")));
                }
            }
        };
        let Value::Object(mut obj) = json else {
            return Err(PveError::new(kind::BAD_RESPONSE, format!("Proxmox returned an unexpected shape for {label}: no data field.")));
        };
        let mut data = obj.remove("data").unwrap_or(Value::Null);
        crate::js::normalize_numbers(&mut data);
        Ok(if keep_secrets { data } else { redact_response(decision.template.as_deref().unwrap_or(&decision.path), &data) })
    }

    fn error_for_status(&self, response: &RawResponse, method: &str, decision: &Decision) -> PveError {
        let status = response.status;
        let (message, errors) = parse_error_body(&response.body);
        let reason = scrub_text(&response.reason).trim().to_string();
        let label = format!("{method} {}", decision.path);
        let text = message.unwrap_or(reason);
        let detail = if text.is_empty() { String::new() } else { format!(": {text}") };
        let fields = errors.map(|e| json!({ "fields": e }));
        match status {
            400 => {
                let e = PveError::new(kind::VALIDATION_FAILED, format!("Proxmox rejected the parameters of {label}{detail}")).status(status);
                let e = match fields {
                    Some(f) => e.details(f),
                    None => e,
                };
                e.hint("Fix the fields named here. pve_api_describe gives the full parameter list of an endpoint.")
            }
            401 => PveError::new(kind::AUTH_FAILED, format!("Proxmox rejected the credentials for {label}{detail}"))
                .status(status)
                .hint("Check the token or password, and that the user and token are enabled and not expired. Do not retry with the same credentials."),
            403 => {
                let permissions = decision.template.as_deref().and_then(|t| find_endpoint(method, t)).and_then(|e| e.permissions.clone());
                let needs = permissions.map(|p| format!(" It needs: {p}")).unwrap_or_default();
                PveError::new(kind::FORBIDDEN, format!("The API user has no permission for {label}{detail}"))
                    .status(status)
                    .hint(format!("The credentials are fine: this is a missing privilege. Do not retry.{needs} A token with privilege separation needs its own ACL on top of the user's."))
            }
            404 => PveError::new(kind::NOT_FOUND, format!("{label} was not found{detail}")).status(status).hint("The guest, node, storage or item may not exist. A list tool gives current ids."),
            501 => PveError::new(kind::NOT_SUPPORTED, format!("This Proxmox version does not have {label}{detail}"))
                .status(status)
                .hint("Do not retry. The endpoint comes from a newer API schema. pve_get_version gives the version of this server."),
            595 | 596 => PveError::new(kind::NODE_UNREACHABLE, format!("The API could not reach the node for {label}{detail}"))
                .status(status)
                .hint("The node may be down or out of quorum. pve_list_nodes shows which nodes are online."),
            _ => {
                if status == 500 && LOCK_TEXT.is_match(&text) {
                    return PveError::new(kind::GUEST_LOCKED, format!("The guest or its configuration is locked for {label}{detail}"))
                        .status(status)
                        .hint("Another task (backup, migration, snapshot) may hold the lock: wait for it, and look at pve_list_node_tasks. Do not remove a lock you did not create.");
                }
                let mut e = PveError::new(kind::UPSTREAM_ERROR, format!("Proxmox answered {label} with HTTP {status}{detail}")).status(status);
                if let Some(f) = fields {
                    e = e.details(f);
                }
                if status >= 500 {
                    e = e.hint("A server-side error. The node journal (pve_get_node_journal) may tell why.");
                }
                e
            }
        }
    }

    /// Adds credentials. With tickets, a 401 is safe to retry once: nothing was run.
    async fn send_authenticated(&self, mut wire: WireRequest) -> Result<RawResponse> {
        if let Some(token) = &self.token_header {
            wire.headers.push(("Authorization".into(), token.clone()));
            return self.send(&wire).await;
        }
        let base_headers = wire.headers.clone();
        wire.headers.extend(self.ticket_headers(wire.method, false).await?);
        let first = self.send(&wire).await?;
        if first.status != 401 {
            return Ok(first);
        }
        wire.headers = base_headers;
        wire.headers.extend(self.ticket_headers(wire.method, true).await?);
        self.send(&wire).await
    }

    async fn ticket_headers(&self, method: &str, renew: bool) -> Result<Vec<(String, String)>> {
        let mut guard = self.ticket.lock().await;
        if renew {
            *guard = None;
        }
        let fresh = guard.as_ref().is_some_and(|t| t.at.elapsed() < TICKET_RENEW);
        if !fresh {
            *guard = Some(self.login().await?);
        }
        let ticket = guard.as_ref().unwrap();
        let mut headers = vec![("Cookie".to_string(), format!("PVEAuthCookie={}", encode_uri_component(&ticket.ticket)))];
        if method != "GET" {
            headers.push(("CSRFPreventionToken".to_string(), ticket.csrf.clone()));
        }
        Ok(headers)
    }

    async fn login(&self) -> Result<Ticket> {
        let (Some(username), Some(password)) = (&self.config.username, &self.config.password) else {
            return Err(PveError::config(format!("Instance \"{}\" has no credentials.", self.config.name)).hint("Set PROXMOX_TOKEN, or PROXMOX_USERNAME and PROXMOX_PASSWORD."));
        };
        let body = encode_pairs(&[("username".into(), username.clone()), ("password".into(), password.clone())]);
        let response = self
            .send(&WireRequest {
                method: "POST",
                url: format!("{}/access/ticket", self.base),
                headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
                body: Body::Form(body),
                timeout_ms: self.config.timeout_ms,
                label: "POST /access/ticket".into(),
            })
            .await?;
        if response.status == 401 || response.status == 403 {
            return Err(PveError::new(kind::AUTH_FAILED, format!("Proxmox refused the login of {username}."))
                .status(response.status)
                .hint("Check PROXMOX_USERNAME (with its realm, such as root@pam) and PROXMOX_PASSWORD. Do not retry: repeated failures can lock the account."));
        }
        if !(200..300).contains(&response.status) {
            return Err(PveError::new(kind::UPSTREAM_ERROR, format!("Login to Proxmox failed with HTTP {}: {}", response.status, scrub_text(&response.reason))).status(response.status));
        }
        let data = serde_json::from_str::<Value>(&response.body).ok().and_then(|v| v.get("data").cloned());
        if crate::js::truthy_js(data.as_ref().and_then(|d| d.get("NeedTFA"))) {
            return Err(PveError::new(kind::AUTH_FAILED, format!("The account {username} requires two-factor authentication, which a password login here cannot complete."))
                .hint("Use an API token instead (PROXMOX_TOKEN): tokens are not subject to TFA."));
        }
        let ticket = data.as_ref().and_then(|d| d.get("ticket")).and_then(Value::as_str);
        let csrf = data.as_ref().and_then(|d| d.get("CSRFPreventionToken")).and_then(Value::as_str);
        match (ticket, csrf) {
            (Some(t), Some(c)) => Ok(Ticket { ticket: t.to_string(), csrf: c.to_string(), at: Instant::now() }),
            _ => Err(PveError::new(kind::BAD_RESPONSE, "The login answer has no ticket.").hint("Check PROXMOX_URL.")),
        }
    }

    async fn send(&self, wire: &WireRequest) -> Result<RawResponse> {
        let _slot = self.slots.acquire().await.map_err(|_| PveError::internal("client closed"))?;
        // Only reads are retried: repeating a write that may have gone through is not safe.
        let attempts = if wire.method == "GET" { MAX_RETRIES + 1 } else { 1 };
        let mut attempt = 1;
        loop {
            match self.send_once(wire).await {
                Ok(response) => {
                    if attempt < attempts && matches!(response.status, 502..=504) {
                        tokio::time::sleep(Duration::from_millis(attempt as u64 * 300)).await;
                        attempt += 1;
                        continue;
                    }
                    return Ok(response);
                }
                Err(err) => {
                    let code = err.details.as_ref().and_then(|d| d.get("code")).and_then(Value::as_str);
                    if attempt >= attempts || code != Some("ECONNRESET") {
                        return Err(err);
                    }
                    tokio::time::sleep(Duration::from_millis(attempt as u64 * 300)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn send_once(&self, wire: &WireRequest) -> Result<RawResponse> {
        // A kept-alive socket may have died unnoticed, and a write cannot be retried: writes get a new one.
        let client = if wire.method == "GET" { &self.keep_alive } else { &self.single };
        let method = reqwest::Method::from_bytes(wire.method.as_bytes()).unwrap();
        let mut req = client.request(method, &wire.url).header("Accept", "application/json");
        for (k, v) in &wire.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req = match &wire.body {
            Body::Empty => req,
            Body::Form(text) => req.body(text.clone()),
            Body::Upload { prefix, suffix, path, size } => {
                let file = tokio::fs::File::open(path).await.map_err(|e| PveError::new(kind::LOCAL_PATH_REFUSED, format!("The local path {path} cannot be read: {e}.")))?;
                let _ = size;
                let head = futures::stream::once(futures::future::ready(Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(prefix.clone()))));
                let tail = futures::stream::once(futures::future::ready(Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(suffix.clone()))));
                let middle = tokio_util::io::ReaderStream::new(file);
                req.body(reqwest::Body::wrap_stream(head.chain(middle).chain(tail)))
            }
        };
        let timeout = Duration::from_millis(wire.timeout_ms);
        let label = wire.label.clone();
        let exchange = async {
            let response = req.send().await.map_err(|e| self.network_error(&e, &label))?;
            let status = response.status();
            let reason = response.extensions().get::<hyper::ext::ReasonPhrase>().map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned()).unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
            let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| self.network_error(&e, &label))?;
                if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(PveError::new(kind::BAD_RESPONSE, format!("The answer to {label} is larger than {} MiB and was dropped.", MAX_RESPONSE_BYTES / 1_048_576)));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(RawResponse { status: status.as_u16(), reason, content_type, body: String::from_utf8_lossy(&body).into_owned() })
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(PveError::new(kind::TIMEOUT, format!("Proxmox did not answer {} within {} s.", wire.label, crate::js::js_round(wire.timeout_ms as f64 / 1000.0)))
                .hint(if wire.method == "GET" { "The node may be overloaded. Try a narrower request." } else { "The change may or may not have gone through: check the state before repeating it." })),
        }
    }

    fn network_error(&self, err: &reqwest::Error, label: &str) -> PveError {
        let (code, message, tls) = classify_network_error(err);
        if let Some(seen) = tls.as_deref().and_then(|t| t.strip_prefix(PIN_MARK)) {
            return PveError::new(kind::TLS_ERROR, format!("The TLS certificate of {} does not match PROXMOX_FINGERPRINT (it has {seen}). Nothing was sent.", self.config.url))
                .hint("Do not retry. Either the certificate was renewed, and the operator has to update the pin, or something is intercepting the connection.");
        }
        if let Some(tls) = tls {
            return PveError::new(kind::TLS_ERROR, format!("The TLS certificate of {} was refused ({tls}).", self.config.url)).hint(
                "Proxmox uses a self-signed certificate by default. Set PROXMOX_FINGERPRINT to its sha256 (pvenode cert info on the node shows it) or point PROXMOX_CA_FILE at the CA to keep verification on. PROXMOX_VERIFY_SSL=false is for a trusted network only.",
            );
        }
        let shown = if code.is_empty() { message } else { code.clone() };
        PveError::new(kind::UNREACHABLE, format!("Cannot reach Proxmox for {label} ({shown})."))
            .hint("Check the URL and port (8006 by default), and that this host may reach it.")
            .details(json!({ "code": code }))
    }
}

fn static_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        // authorize refuses it with the right message.
        _ => "INVALID",
    }
}

/// What Node would have called the error: ECONNREFUSED and the like, and whether TLS refused it.
fn classify_network_error(err: &reqwest::Error) -> (String, String, Option<String>) {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    let mut code = String::new();
    let mut tls = None;
    let mut deepest = err.to_string();
    while let Some(e) = source {
        if let Some(r) = e.downcast_ref::<rustls::Error>() {
            tls = Some(match r {
                rustls::Error::General(m) => m.clone(),
                rustls::Error::InvalidCertificate(c) => format!("{c:?}"),
                other => other.to_string(),
            });
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(r) = inner.downcast_ref::<rustls::Error>() {
                    tls = Some(match r {
                        rustls::Error::General(m) => m.clone(),
                        rustls::Error::InvalidCertificate(c) => format!("{c:?}"),
                        other => other.to_string(),
                    });
                }
            }
            if code.is_empty() {
                code = match io.kind() {
                    std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof => "ECONNRESET",
                    std::io::ErrorKind::TimedOut => "ETIMEDOUT",
                    std::io::ErrorKind::HostUnreachable => "EHOSTUNREACH",
                    std::io::ErrorKind::NetworkUnreachable => "ENETUNREACH",
                    std::io::ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
                    _ => "",
                }
                .to_string();
            }
        }
        if let Some(h) = e.downcast_ref::<hyper::Error>() {
            if (h.is_incomplete_message() || h.is_canceled()) && code.is_empty() {
                code = "ECONNRESET".into();
            }
        }
        let text = e.to_string();
        // The rustls error is not always reachable by downcast through the wrappers: its text is.
        if tls.is_none() {
            if let Some(at) = text.find(PIN_MARK) {
                let seen: String = text[at + PIN_MARK.len()..].chars().take_while(|c| c.is_ascii_hexdigit() || *c == ':').collect();
                tls = Some(format!("{PIN_MARK}{seen}"));
            } else if text.contains("invalid peer certificate") || text.contains("received fatal alert") || text.contains("peer is incompatible") || text.contains("peer misbehaved") {
                tls = Some(text.clone());
            }
        }
        if text.contains("dns error") && code.is_empty() {
            code = "ENOTFOUND".into();
        }
        deepest = text;
        source = e.source();
    }
    (code, deepest, tls)
}

impl Api for ProxmoxClient {
    fn request(&self, method: &str, path: &str, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
        let (method, path) = (method.to_string(), path.to_string());
        async move { self.request_impl(&method, &path, opts).await }.boxed()
    }

    fn upload(&self, path: &str, fields: Map<String, Value>, file: UploadFile, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
        let path = path.to_string();
        async move { self.upload_impl(&path, fields, file, opts).await }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Env, load_config};
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn client(extra: &[(&str, &str)]) -> ProxmoxClient {
        let mut env: Env = [("PROXMOX_URL", "https://127.0.0.1:1"), ("PROXMOX_TOKEN", "mcp@pve!test=00000000-0000-0000-0000-000000000000")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        for (k, v) in extra {
            if v.is_empty() {
                env.remove(*k);
            } else {
                env.insert(k.to_string(), v.to_string());
            }
        }
        let config = load_config(&env).unwrap();
        ProxmoxClient::new(config.instances.values().next().unwrap().clone(), Vec::new(), None).unwrap()
    }

    /// A fake Proxmox over plain HTTP: logins, /version, and a VM config holding a secret.
    async fn fake() -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let logins = Arc::new(AtomicUsize::new(0));
        let with_ticket = Arc::new(AtomicUsize::new(0));
        let (l, t) = (logins.clone(), with_ticket.clone());
        let app = Router::new()
            .route(
                "/api2/json/access/ticket",
                post(move || {
                    let n = l.fetch_add(1, Ordering::SeqCst);
                    async move { reply(json!({ "data": { "ticket": format!("PVE:root@pam:{n}"), "CSRFPreventionToken": "csrf", "username": "root@pam" } })) }
                }),
            )
            .route(
                "/api2/json/version",
                get(move |headers: HeaderMap| {
                    if headers.get("cookie").and_then(|c| c.to_str().ok()).is_some_and(|c| c.starts_with("PVEAuthCookie=")) {
                        t.fetch_add(1, Ordering::SeqCst);
                    }
                    async { reply(json!({ "data": { "version": "9.1.0" } })) }
                }),
            )
            .route("/api2/json/nodes/pve1/qemu/100/config", get(|| async { reply(json!({ "data": { "cipassword": "x", "name": "n" } })) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, logins, with_ticket)
    }

    fn reply(body: Value) -> ([(&'static str, &'static str); 1], String) {
        ([("content-type", "application/json")], body.to_string())
    }

    fn write(params: Option<Map<String, Value>>) -> RequestOptions {
        RequestOptions { params, ..Default::default() }
    }

    #[tokio::test]
    async fn refuses_a_write_on_a_read_only_instance_without_connecting() {
        // Port 1: anything that tried to connect would fail as unreachable instead.
        let c = client(&[]);
        let err = c.request_impl("POST", "/nodes/pve1/qemu/100/status/start", write(None)).await.unwrap_err();
        assert_eq!(err.kind, kind::WRITE_DISABLED);
        let file = UploadFile { local_path: "nope".into(), filename: None, field: None };
        let err = c.upload_impl("/nodes/{node}/storage/{storage}/upload", obj(&[("content", "iso")]), file, RequestOptions::path(obj(&[("node", "pve1"), ("storage", "local")]))).await.unwrap_err();
        assert_eq!(err.kind, kind::WRITE_DISABLED);
    }

    #[tokio::test]
    async fn refuses_a_write_from_a_read_scope_even_when_writes_are_on() {
        let c = client(&[("PROXMOX_ALLOW_WRITES", "true")]);
        let opts = RequestOptions { read_only: Some(true), ..Default::default() };
        let err = c.request_impl("POST", "/nodes/pve1/qemu/100/status/start", opts).await.unwrap_err();
        assert_eq!(err.kind, kind::NOT_READ_ONLY);
    }

    #[tokio::test]
    async fn records_a_dry_run_instead_of_sending_it_with_secrets_masked() {
        let c = client(&[]);
        let log: crate::proxmox::DryRunLog = Default::default();
        let opts = RequestOptions { dry_run: Some(true), dry_run_log: Some(log.clone()), path_params: Some(obj(&[("node", "pve1")])), params: Some(Map::from_iter([("vmid".to_string(), json!(200)), ("cipassword".to_string(), json!("hunter2"))])), ..Default::default() };
        assert_eq!(c.request_impl("POST", "/nodes/{node}/qemu", opts).await.unwrap(), json!(DRY_RUN_UPID));
        assert_eq!(*log.lock().unwrap(), vec![json!({ "method": "POST", "path": "/nodes/pve1/qemu", "params": { "vmid": 200, "cipassword": "[REDACTED]" } })]);
        let opts = RequestOptions { dry_run: Some(true), params: Some(Map::new()), ..Default::default() };
        assert_eq!(c.request_impl("PUT", "/nodes/pve1/qemu/100/config", opts).await.unwrap(), json!({ "dry_run": true }));
    }

    #[tokio::test]
    async fn only_hands_over_secrets_when_they_are_allowed_and_asked_for() {
        let (url, _, _) = fake().await;
        let get = |c: ProxmoxClient, include: bool| async move { c.request_impl("GET", "/nodes/pve1/qemu/100/config", RequestOptions { include_sensitive: include, ..Default::default() }).await.unwrap() };
        let open = || client(&[("PROXMOX_URL", url.as_str()), ("PROXMOX_ALLOW_SENSITIVE", "true")]);
        assert_eq!(get(open(), false).await, json!({ "cipassword": "[REDACTED]", "name": "n" }));
        assert_eq!(get(open(), true).await, json!({ "cipassword": "x", "name": "n" }));
        assert_eq!(get(client(&[("PROXMOX_URL", url.as_str())]), true).await, json!({ "cipassword": "[REDACTED]", "name": "n" }));
    }

    #[tokio::test]
    async fn renews_a_ticket_close_to_its_two_hour_expiry_without_waiting_for_a_401() {
        let (url, logins, with_ticket) = fake().await;
        let c = client(&[("PROXMOX_URL", url.as_str()), ("PROXMOX_TOKEN", ""), ("PROXMOX_USERNAME", "root@pam"), ("PROXMOX_PASSWORD", "secret")]);
        c.request_impl("GET", "/version", RequestOptions::default()).await.unwrap();
        let Some(old) = Instant::now().checked_sub(Duration::from_secs(100 * 60)) else { return };
        c.ticket.lock().await.as_mut().unwrap().at = old;
        c.request_impl("GET", "/version", RequestOptions::default()).await.unwrap();
        assert_eq!(logins.load(Ordering::SeqCst), 2);
        assert_eq!(with_ticket.load(Ordering::SeqCst), 2);
    }

    fn obj(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
    }
}
