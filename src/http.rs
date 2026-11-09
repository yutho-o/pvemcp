//! Streamable HTTP without sessions: each request gets its own MCP server over the shared
//! runtime, which holds the API clients and the SSH sessions. Without a session there is
//! nobody to ask, so elicitation does not apply: the client has to rely on the destructive
//! annotation of the tools.

use crate::errors::{PveError, Result};
use crate::runtime::Runtime;
use crate::server::{McpServer, SUPPORTED_PROTOCOL_VERSIONS};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// What the SDK accepts as a request body.
const MAX_BODY: usize = 4 * 1024 * 1024;

pub struct HttpOptions {
    pub host: String,
    pub port: u16,
    /// Bearer token. Required unless the server only listens on the loopback interface.
    pub token: Option<String>,
    /// Extra values accepted in the Host header, for a reverse proxy.
    pub allowed_hosts: Vec<String>,
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn token_matches(header: Option<&HeaderValue>, token: &str) -> bool {
    let given = header.map(|h| h.as_bytes()).unwrap_or(b"");
    let wanted = format!("Bearer {token}");
    given.len() == wanted.len() && bool::from(given.ct_eq(wanted.as_bytes()))
}

struct HttpState {
    runtime: Arc<Runtime>,
    token: Option<String>,
    allowed: HashSet<String>,
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    Response::builder().status(status).header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap()
}

fn deny(status: StatusCode, message: &str) -> Response {
    json_response(status, &json!({ "error": message }))
}

fn rpc_error(status: StatusCode, code: i64, message: String, data: Option<String>) -> Response {
    let mut error = json!({ "code": code, "message": message });
    if let Some(d) = data {
        error["data"] = Value::String(d);
    }
    json_response(status, &json!({ "jsonrpc": "2.0", "error": error, "id": null }))
}

fn header_str<'a>(headers: &'a HeaderMap, name: header::HeaderName) -> &'a str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn is_message(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    if o.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    let id_ok = o.get("id").is_some_and(|i| i.is_string() || i.is_number());
    match o.get("method") {
        Some(m) => m.is_string() && (!o.contains_key("id") || id_ok),
        None => id_ok && (o.contains_key("result") || o.contains_key("error")),
    }
}

async fn handle(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let headers = request.headers().clone();
    // A web page can make a browser call a local address: checking Host stops DNS rebinding.
    if !state.allowed.contains(header_str(&headers, header::HOST)) {
        return deny(StatusCode::FORBIDDEN, "Host not allowed. See PROXMOX_MCP_ALLOWED_HOSTS.");
    }
    if let Some(token) = &state.token {
        if !token_matches(headers.get(header::AUTHORIZATION), token) {
            return deny(StatusCode::UNAUTHORIZED, "Invalid or missing bearer token.");
        }
    }
    if request.uri().path() != "/mcp" {
        return deny(StatusCode::NOT_FOUND, "Not found. The endpoint is /mcp.");
    }
    if request.method() != Method::POST {
        return deny(StatusCode::METHOD_NOT_ALLOWED, "This server keeps no session: only POST is supported.");
    }

    let accept = header_str(&headers, header::ACCEPT);
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        return rpc_error(StatusCode::NOT_ACCEPTABLE, -32000, "Not Acceptable: Client must accept both application/json and text/event-stream".into(), None);
    }
    if !header_str(&headers, header::CONTENT_TYPE).contains("application/json") {
        return rpc_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, -32000, "Unsupported Media Type: Content-Type must be application/json".into(), None);
    }
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY).await {
        Ok(b) => b,
        Err(e) => return rpc_error(StatusCode::BAD_REQUEST, -32700, "Parse error".into(), Some(e.to_string())),
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return rpc_error(StatusCode::BAD_REQUEST, -32700, "Parse error".into(), Some(format!("SyntaxError: {e}"))),
    };
    let messages: Vec<Value> = match parsed {
        Value::Array(items) => items,
        single => vec![single],
    };
    if !messages.iter().all(is_message) {
        return rpc_error(StatusCode::BAD_REQUEST, -32700, "Parse error".into(), Some("Invalid JSON-RPC message".into()));
    }
    let initializing = messages.iter().any(|m| m.get("method").and_then(Value::as_str) == Some("initialize") && m.get("id").is_some());
    if initializing && messages.len() > 1 {
        return rpc_error(StatusCode::BAD_REQUEST, -32600, "Invalid Request: Only one initialization request is allowed".into(), None);
    }
    if !initializing {
        if let Some(version) = headers.get("mcp-protocol-version").and_then(|v| v.to_str().ok()) {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
                return rpc_error(
                    StatusCode::BAD_REQUEST,
                    -32000,
                    format!("Bad Request: Unsupported protocol version: {version} (supported versions: {})", SUPPORTED_PROTOCOL_VERSIONS.join(", ")),
                    None,
                );
            }
        }
    }

    let server = match McpServer::new(state.runtime.clone(), None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[pvemcp] request failed: {}", e.message);
            return deny(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.");
        }
    };
    let has_requests = messages.iter().any(|m| m.get("method").is_some() && m.get("id").is_some());
    // Requests run together, as on stdio. A client that goes away drops this future, and the calls with it.
    let answers: Vec<Value> = futures::future::join_all(messages.into_iter().map(|m| {
        let server = server.clone();
        async move { server.handle(m).await }
    }))
    .await
    .into_iter()
    .flatten()
    .collect();
    server.close();
    if !has_requests {
        return Response::builder().status(StatusCode::ACCEPTED).body(Body::empty()).unwrap();
    }
    let body = if answers.len() == 1 { answers.into_iter().next().unwrap() } else { Value::Array(answers) };
    json_response(StatusCode::OK, &body)
}

/// Binds and serves until the process stops. Returns once the socket listens, with the server running.
pub async fn start_http(runtime: Arc<Runtime>, options: HttpOptions) -> Result<tokio::task::JoinHandle<()>> {
    let HttpOptions { host, port, token, allowed_hosts } = options;
    if token.is_none() && !is_loopback(&host) {
        return Err(PveError::config(format!("Refusing to listen on {host} without a token: anyone on the network could drive the cluster.")).hint("Set PROXMOX_MCP_TOKEN, or listen on 127.0.0.1."));
    }
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await.map_err(|e| PveError::config(format!("Cannot listen on {host}:{port}: {e}")))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let shown = if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) { format!("[{host}]") } else { host.clone() };
    let mut allowed: HashSet<String> = allowed_hosts.into_iter().collect();
    for name in [shown.as_str(), "localhost", "127.0.0.1", "[::1]"] {
        if name == shown || is_loopback(&host) {
            allowed.insert(format!("{name}:{port}"));
        }
    }
    let state = Arc::new(HttpState { runtime, token, allowed });
    let app = axum::Router::new().fallback(handle).with_state(state);
    eprintln!("[pvemcp] listening on http://{shown}:{port}/mcp");
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[pvemcp] HTTP server stopped: {e}");
        }
    }))
}
