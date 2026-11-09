//! Proxmox tasks: UPIDs, waiting for the end, and the tail of the log.

use super::{Api, RequestOptions};
use crate::errors::{PveError, Result, kind};
use crate::js::{js_round, js_slice_start, js_string};
use crate::obj;
use regex::Regex;
use serde_json::{Value, json};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// What a dry run returns where the real call would have started a task.
pub const DRY_RUN_UPID: &str = "UPID:dry-run:00000000:00000000:00000000:dryrun:0:dry-run@pam:";

#[derive(Debug, Clone)]
pub struct ParsedUpid {
    pub upid: String,
    pub node: String,
    pub pid: u64,
    pub pstart: u64,
    pub starttime: u64,
    pub kind: String,
    pub id: String,
    pub user: String,
}

static UPID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^UPID:([a-zA-Z0-9][a-zA-Z0-9.-]*):([0-9A-Fa-f]{8,}):([0-9A-Fa-f]{8,}):([0-9A-Fa-f]{8,}):([^:\s]+):([^:\s]*):([^:\s]+):$").unwrap());
static WARNINGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^WARNINGS: \d+$").unwrap());

pub fn is_upid(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(s)) if UPID_RE.is_match(s))
}

pub fn is_upid_str(value: &str) -> bool {
    UPID_RE.is_match(value)
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(u64::MAX)
}

pub fn parse_upid(upid: &str) -> Result<ParsedUpid> {
    let Some(m) = UPID_RE.captures(upid) else {
        return Err(PveError::new(kind::INVALID_INPUT, format!("\"{}\" is not a task id (UPID).", js_slice_start(upid, 200))).hint("A UPID looks like UPID:pve1:00001234:00ABCDEF:65000000:qmstart:100:root@pam:"));
    };
    Ok(ParsedUpid { upid: upid.to_string(), node: m[1].to_string(), pid: hex(&m[2]), pstart: hex(&m[3]), starttime: hex(&m[4]), kind: m[5].to_string(), id: m[6].to_string(), user: m[7].to_string() })
}

#[derive(Debug, Clone)]
pub struct TaskResult {
    pub upid: String,
    pub node: String,
    pub status: String,
    pub exitstatus: Option<String>,
    pub log_tail: Vec<String>,
    pub warning: Option<String>,
}

impl TaskResult {
    pub fn to_json(&self) -> Value {
        Value::Object(obj! {
            "upid" => &self.upid,
            "node" => &self.node,
            "status" => &self.status,
            "exitstatus" => self.exitstatus.clone().map(Value::String).unwrap_or(Value::Null),
            "log_tail" => self.log_tail.clone(),
            "warning" => self.warning.clone(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct WaitOptions {
    pub timeout_ms: Option<u64>,
    /// First delay between polls. It grows up to max_poll_ms.
    pub poll_ms: Option<u64>,
    pub max_poll_ms: Option<u64>,
    pub log_lines: Option<usize>,
}

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_POLL_MS: u64 = 500;
const DEFAULT_MAX_POLL_MS: u64 = 5_000;
pub const DEFAULT_LOG_LINES: usize = 20;
const LOG_PAGE: usize = 5000;
const LOG_MAX_PAGES: usize = 20;

fn task_params(node: &str, upid: &str) -> serde_json::Map<String, Value> {
    obj! { "node" => node, "upid" => upid }
}

/// Never fails: a task that cannot show its log still has a result to report.
pub async fn task_log_tail(api: &dyn Api, upid: &str, lines: usize) -> Vec<String> {
    let Ok(parsed) = parse_upid(upid) else { return Vec::new() };
    let path_params = task_params(&parsed.node, upid);
    let mut tail: Vec<Value> = Vec::new();
    let mut start = 0usize;
    for _ in 0..LOG_MAX_PAGES {
        // start and limit count from the top, and the answer does not say how long the log is.
        let rows = api.get("/nodes/{node}/tasks/{upid}/log", RequestOptions::path(path_params.clone()).with_params(obj! { "start" => start, "limit" => LOG_PAGE })).await;
        let rows = match rows {
            Ok(Value::Array(rows)) => rows,
            Ok(_) => break,
            Err(_) => return Vec::new(),
        };
        if rows.is_empty() {
            break;
        }
        let count = rows.len();
        tail.extend(rows);
        if tail.len() > lines {
            tail.drain(..tail.len() - lines);
        }
        if count < LOG_PAGE {
            break;
        }
        start += count;
    }
    tail.iter()
        .map(|r| match r.get("t") {
            None | Some(Value::Null) => String::new(),
            Some(t) => js_string(t),
        })
        .filter(|t| t != "no content")
        .collect()
}

/// Waits for a task to end. OK is a success, WARNINGS: n a success with a warning, anything
/// else task_failed with the end of the log. The node always comes from the UPID.
pub async fn wait_for_task(api: &dyn Api, upid: &str, opts: &WaitOptions) -> Result<TaskResult> {
    let parsed = parse_upid(upid)?;
    let node = parsed.node.clone();
    if upid == DRY_RUN_UPID {
        return Ok(TaskResult { upid: upid.into(), node, status: "stopped".into(), exitstatus: Some("OK".into()), log_tail: Vec::new(), warning: None });
    }
    let timeout_ms = opts.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut delay = opts.poll_ms.unwrap_or(DEFAULT_POLL_MS);
    let max_delay = opts.max_poll_ms.unwrap_or(DEFAULT_MAX_POLL_MS);
    let path_params = task_params(&node, upid);
    loop {
        let status = api.get("/nodes/{node}/tasks/{upid}/status", RequestOptions::path(path_params.clone())).await?;
        if status.get("status").and_then(Value::as_str) == Some("stopped") {
            let exit = status.get("exitstatus").and_then(Value::as_str).map(str::to_string);
            let log = task_log_tail(api, upid, opts.log_lines.unwrap_or(DEFAULT_LOG_LINES)).await;
            match exit.as_deref() {
                Some("OK") => return Ok(TaskResult { upid: upid.into(), node, status: "stopped".into(), exitstatus: exit, log_tail: log, warning: None }),
                Some(e) if WARNINGS.is_match(e) => {
                    let warning = Some(format!("The task finished with {}. See log_tail.", e.to_lowercase()));
                    return Ok(TaskResult { upid: upid.into(), node, status: "stopped".into(), exitstatus: exit, log_tail: log, warning });
                }
                _ => {
                    return Err(PveError::new(kind::TASK_FAILED, format!("Task {upid} failed on {node}: {}.", exit.as_deref().unwrap_or("no exit status")))
                        .hint("Read the log tail in details before trying again. The failed step may have left something behind.")
                        .details(json!({ "upid": upid, "node": node, "exitstatus": exit, "log_tail": log })));
                }
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PveError::new(kind::TASK_TIMEOUT, format!("Task {upid} is still running on {node} after {} s.", js_round(timeout_ms as f64 / 1000.0)))
                .hint("It was not cancelled. Check it again with pve_wait_task, or stop it with pve_stop_task.")
                .details(json!({ "upid": upid, "node": node })));
        }
        tokio::time::sleep(Duration::from_millis(delay).min(left)).await;
        delay = ((delay as f64 * 1.5).ceil() as u64).min(max_delay);
    }
}

/// An Api answered by a closure, recording each call: the fake Proxmox of the unit tests.
#[cfg(test)]
pub mod mock {
    use crate::errors::Result;
    use crate::proxmox::{Api, RequestOptions, UploadFile};
    use futures::FutureExt;
    use futures::future::BoxFuture;
    use serde_json::{Map, Value};
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct Call {
        pub method: String,
        pub path: String,
        pub path_params: Map<String, Value>,
        pub params: Map<String, Value>,
        pub read_only: Option<bool>,
    }

    type Handler = Box<dyn Fn(&Call) -> Result<Value> + Send + Sync>;

    pub struct MockApi {
        handler: Handler,
        pub calls: Mutex<Vec<Call>>,
    }

    impl MockApi {
        pub fn new(handler: impl Fn(&Call) -> Result<Value> + Send + Sync + 'static) -> Self {
            MockApi { handler: Box::new(handler), calls: Mutex::new(Vec::new()) }
        }

        pub fn calls_to(&self, path: &str) -> Vec<Call> {
            self.calls.lock().unwrap().iter().filter(|c| c.path == path).cloned().collect()
        }

        pub fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl Api for MockApi {
        fn request(&self, method: &str, path: &str, opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
            let call = Call { method: method.into(), path: path.into(), path_params: opts.path_params.unwrap_or_default(), params: opts.params.unwrap_or_default(), read_only: opts.read_only };
            self.calls.lock().unwrap().push(call.clone());
            let answer = (self.handler)(&call);
            async move { answer }.boxed()
        }

        fn upload(&self, _path: &str, _fields: Map<String, Value>, _file: UploadFile, _opts: RequestOptions) -> BoxFuture<'_, Result<Value>> {
            async { unimplemented!("upload") }.boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{Call, MockApi};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const UPID: &str = "UPID:pve1:0000A1B2:0012C3D4:5F9A1B2C:qmstart:100:root@pam:";

    fn fast() -> WaitOptions {
        WaitOptions { poll_ms: Some(1), max_poll_ms: Some(2), ..Default::default() }
    }

    fn log_rows(lines: &[String], call: &Call) -> Value {
        let start = call.params.get("start").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limit = call.params.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
        Value::Array(lines.iter().enumerate().skip(start).take(limit).map(|(i, t)| json!({ "n": i + 1, "t": t })).collect())
    }

    /// A task that runs for this many polls, then stops with this exit status and log. Node "gone" fails.
    fn task(polls: usize, exit: &'static str, log: Vec<String>) -> MockApi {
        let seen = AtomicUsize::new(0);
        MockApi::new(move |call| {
            if call.path_params.get("node").and_then(Value::as_str) == Some("gone") {
                return Err(PveError::new(kind::UPSTREAM_ERROR, "hostname lookup failed").status(500));
            }
            if call.path.ends_with("/log") {
                return Ok(log_rows(&log, call));
            }
            let n = seen.fetch_add(1, Ordering::SeqCst);
            Ok(if n < polls { json!({ "status": "running" }) } else { json!({ "status": "stopped", "exitstatus": exit }) })
        })
    }

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses() {
        let p = parse_upid(UPID).unwrap();
        assert_eq!(
            (p.upid.as_str(), p.node.as_str(), p.pid, p.pstart, p.starttime, p.kind.as_str(), p.id.as_str(), p.user.as_str()),
            (UPID, "pve1", 0xa1b2, 0x12c3d4, 0x5f9a1b2c, "qmstart", "100", "root@pam")
        );
        assert_eq!(parse_upid("UPID:n-1:00000001:00000002:00000003:vzdump::mcp@pve!tok:").unwrap().id, "");
        assert!(is_upid_str(UPID));
        assert!(is_upid_str(DRY_RUN_UPID));
        assert_eq!(parse_upid("nope").unwrap_err().kind, kind::INVALID_INPUT);
    }

    #[test]
    fn refuses_what_is_not_a_upid() {
        let extra = format!("{UPID}extra");
        for bad in ["", "ok", "UPID:", "UPID:pve1:1:2:3:x:y:z:", extra.as_str(), "UPID:pve/1:0000A1B2:0012C3D4:5F9A1B2C:qmstart:100:root@pam:"] {
            assert!(!is_upid(Some(&Value::String(bad.into()))), "{bad}");
        }
        assert!(!is_upid(Some(&json!(5))));
        assert!(!is_upid(Some(&Value::Null)));
        assert!(!is_upid(None));
    }

    #[tokio::test]
    async fn polls_the_node_of_the_upid_until_it_stops_and_returns_the_end_of_the_log() {
        let upid = "UPID:pve2:0000A1B2:0012C3D4:5F9A1B2C:qmstart:100:root@pam:";
        let api = task(3, "OK", lines(&["one", "two", "TASK OK"]));
        let result = wait_for_task(&api, upid, &fast()).await.unwrap();
        assert_eq!(result.to_json(), json!({ "upid": upid, "node": "pve2", "status": "stopped", "exitstatus": "OK", "log_tail": ["one", "two", "TASK OK"] }));
        let reads = api.calls_to("/nodes/{node}/tasks/{upid}/status");
        assert_eq!(reads.len(), 4);
        assert_eq!(reads[0].path_params["node"], "pve2");
        assert_eq!(reads[0].path_params["upid"], upid);
    }

    #[tokio::test]
    async fn counts_warnings_as_a_success_with_a_warning() {
        let api = task(0, "WARNINGS: 2", Vec::new());
        let result = wait_for_task(&api, UPID, &fast()).await.unwrap();
        assert_eq!(result.exitstatus.as_deref(), Some("WARNINGS: 2"));
        assert!(result.warning.unwrap().contains("warnings: 2"));
    }

    #[tokio::test]
    async fn turns_any_other_exit_into_task_failed_with_the_log_tail() {
        let api = task(0, "command failed", lines(&["boom", "TASK ERROR: command failed"]));
        let err = wait_for_task(&api, UPID, &fast()).await.unwrap_err();
        assert_eq!(err.kind, kind::TASK_FAILED);
        let details = err.details.unwrap();
        assert_eq!(details["exitstatus"], "command failed");
        assert_eq!(details["log_tail"], json!(["boom", "TASK ERROR: command failed"]));
    }

    #[tokio::test]
    async fn gives_up_with_task_timeout_without_cancelling_it() {
        let api = task(usize::MAX, "OK", Vec::new());
        let err = wait_for_task(&api, UPID, &WaitOptions { timeout_ms: Some(30), ..fast() }).await.unwrap_err();
        assert_eq!(err.kind, kind::TASK_TIMEOUT);
        assert!(api.calls.lock().unwrap().iter().all(|c| c.method == "GET"));
    }

    #[tokio::test]
    async fn backs_off_between_polls() {
        let delays: Arc<Mutex<Vec<u128>>> = Default::default();
        let (record, last, polls) = (delays.clone(), Mutex::new(Instant::now()), AtomicUsize::new(0));
        let api = MockApi::new(move |call| {
            if call.path.ends_with("/log") {
                return Ok(json!([]));
            }
            let mut last = last.lock().unwrap();
            record.lock().unwrap().push(last.elapsed().as_millis());
            *last = Instant::now();
            Ok(if polls.fetch_add(1, Ordering::SeqCst) < 4 { json!({ "status": "running" }) } else { json!({ "status": "stopped", "exitstatus": "OK" }) })
        });
        wait_for_task(&api, "UPID:pve1:00000001:00000002:00000003:x:y:z@pam:", &WaitOptions { poll_ms: Some(10), max_poll_ms: Some(40), ..Default::default() }).await.unwrap();
        let delays = delays.lock().unwrap();
        assert!(*delays.last().unwrap() + 5 > delays[1], "{delays:?}");
        assert!(*delays.last().unwrap() >= 30, "{delays:?}");
    }

    #[tokio::test]
    async fn stops_when_the_caller_stops_waiting() {
        // No signal in Rust: the caller drops the future, and nothing polls after that.
        let api = Arc::new(task(usize::MAX, "OK", Vec::new()));
        let opts = WaitOptions { poll_ms: Some(1000), timeout_ms: Some(60_000), ..Default::default() };
        let waiting = wait_for_task(api.as_ref(), UPID, &opts);
        assert!(tokio::time::timeout(Duration::from_millis(20), waiting).await.is_err());
        let polled = api.count();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(api.count(), polled);
    }

    #[tokio::test]
    async fn never_touches_the_api_for_the_dry_run_task() {
        let api = task(0, "OK", Vec::new());
        let result = wait_for_task(&api, DRY_RUN_UPID, &WaitOptions::default()).await.unwrap();
        assert_eq!(result.exitstatus.as_deref(), Some("OK"));
        assert_eq!(api.count(), 0);
    }

    #[tokio::test]
    async fn reports_an_api_failure_while_polling_as_it_is() {
        let api = task(0, "OK", Vec::new());
        let err = wait_for_task(&api, &UPID.replace("pve1", "gone"), &fast()).await.unwrap_err();
        assert_eq!(err.kind, kind::UPSTREAM_ERROR);
    }

    #[tokio::test]
    async fn keeps_the_last_lines_and_survives_an_unreadable_log() {
        let api = task(0, "OK", (0..30).map(|i| format!("line {i}")).collect());
        assert_eq!(task_log_tail(&api, UPID, 2).await, lines(&["line 28", "line 29"]));
        assert!(task_log_tail(&api, &UPID.replace("pve1", "gone"), DEFAULT_LOG_LINES).await.is_empty());
    }

    #[tokio::test]
    async fn pages_through_a_log_longer_than_one_read() {
        let api = task(0, "OK", (0..12_000).map(|i| format!("line {i}")).collect());
        assert_eq!(task_log_tail(&api, UPID, 1).await, lines(&["line 11999"]));
        assert_eq!(api.count(), 3);
    }
}
