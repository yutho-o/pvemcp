use serde_json::{Map, Value};
use std::fmt;

/// Every failure carries a type and, where it helps, a hint telling the agent what
/// to do next (and just as importantly what not to retry).
#[derive(Debug, Clone)]
pub struct PveError {
    /// One of the error types below, or internal_error.
    pub kind: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub status: Option<u16>,
    pub details: Option<Value>,
}

pub type Result<T> = std::result::Result<T, PveError>;

/// The types an agent can see, as the TypeScript version had them.
pub mod kind {
    // Refused by this server's own policy.
    pub const WRITE_DISABLED: &str = "write_disabled";
    pub const ELEVATED_DISABLED: &str = "elevated_disabled";
    pub const GUEST_EXEC_DISABLED: &str = "guest_exec_disabled";
    pub const SENSITIVE_DISABLED: &str = "sensitive_disabled";
    pub const SSH_DISABLED: &str = "ssh_disabled";
    pub const BLOCKED_ENDPOINT: &str = "blocked_endpoint";
    pub const NOT_READ_ONLY: &str = "not_read_only";
    pub const PROTECTED_GUEST: &str = "protected_guest";
    pub const INVALID_PATH: &str = "invalid_path";
    pub const INVALID_INPUT: &str = "invalid_input";
    pub const CONFIG_ERROR: &str = "config_error";
    pub const USER_CANCELLED: &str = "user_cancelled";
    pub const LOCAL_PATH_REFUSED: &str = "local_path_refused";
    // Answers from Proxmox.
    pub const VALIDATION_FAILED: &str = "validation_failed";
    pub const AUTH_FAILED: &str = "auth_failed";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const GUEST_LOCKED: &str = "guest_locked";
    pub const UPSTREAM_ERROR: &str = "upstream_error";
    pub const NODE_UNREACHABLE: &str = "node_unreachable";
    pub const BAD_RESPONSE: &str = "bad_response";
    // Transport.
    pub const TLS_ERROR: &str = "tls_error";
    pub const UNREACHABLE: &str = "unreachable";
    pub const TIMEOUT: &str = "timeout";
    // Tasks.
    pub const TASK_FAILED: &str = "task_failed";
    pub const TASK_TIMEOUT: &str = "task_timeout";
    // SSH.
    pub const HOST_KEY_UNKNOWN: &str = "host_key_unknown";
    pub const HOST_KEY_MISMATCH: &str = "host_key_mismatch";
    pub const SSH_AUTH_FAILED: &str = "ssh_auth_failed";
    pub const SSH_UNREACHABLE: &str = "ssh_unreachable";
    pub const SSH_TIMEOUT: &str = "ssh_timeout";
    pub const SSH_OUTPUT_TOO_LARGE: &str = "ssh_output_too_large";
    pub const GUEST_NOT_RUNNING: &str = "guest_not_running";
    // Not one of ours: a bug, or something unexpected below.
    pub const INTERNAL_ERROR: &str = "internal_error";
}

impl PveError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        PveError { kind, message: message.into(), hint: None, status: None, details: None }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn opt_hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }

    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn internal(message: impl Into<String>) -> Self {
        PveError::new(kind::INTERNAL_ERROR, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        PveError::new(kind::INVALID_INPUT, message)
    }

    pub fn config(message: impl Into<String>) -> Self {
        PveError::new(kind::CONFIG_ERROR, message)
    }

    /// Whether the type ends in _disabled: a gate refusal.
    pub fn is_disabled(&self) -> bool {
        self.kind.ends_with("_disabled")
    }

    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("error".into(), Value::String(self.message.clone()));
        out.insert("error_type".into(), Value::String(self.kind.to_string()));
        if let Some(status) = self.status {
            out.insert("http_status".into(), Value::from(status));
        }
        if let Some(hint) = &self.hint {
            if !hint.is_empty() {
                out.insert("hint".into(), Value::String(hint.clone()));
            }
        }
        if let Some(details) = &self.details {
            out.insert("details".into(), details.clone());
        }
        Value::Object(out)
    }

    /// "type: message", as gather and the reports show a failed section.
    pub fn reason(&self) -> String {
        format!("{}: {}", self.kind, self.message)
    }
}

impl fmt::Display for PveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PveError {}
