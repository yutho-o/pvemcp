//! Interactive PTY sessions, kept for the life of the server.

use super::{ShellChannel, ShellEvent, ShellInput};
use crate::errors::{PveError, Result, kind};
use crate::js::{iso_from_millis, js_round, now_millis};
use crate::obj;
use crate::proxmox::redact::scrub_text;
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};

#[derive(Debug, Clone, Copy)]
pub struct SessionOptions {
    pub max_sessions: usize,
    pub idle_ms: u64,
    pub buffer_bytes: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions { max_sessions: 8, idle_ms: 15 * 60_000, buffer_bytes: 1024 * 1024 }
    }
}

const SWEEP_MS: u64 = 30_000;
/// Output comes in bursts: after the first bytes, a moment more gives whole lines instead of pieces.
const SETTLE_MS: u64 = 60;

/// How a channel ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Closed {
    pub code: Option<i64>,
    pub signal: Option<String>,
}

struct State {
    chunks: VecDeque<Vec<u8>>,
    unread: usize,
    dropped: usize,
    last_used: Instant,
    closed_with: Option<Closed>,
    /// Bytes of a character cut between two reads, as StringDecoder keeps them.
    pending: Vec<u8>,
}

/// One PTY, with what it printed since the last read.
pub struct PtySession {
    pub id: String,
    pub instance: String,
    pub node: String,
    pub vmid: Option<i64>,
    pub command: String,
    started_at: i64,
    buffer_bytes: usize,
    input: mpsc::UnboundedSender<ShellInput>,
    state: Mutex<State>,
    wake: Notify,
}

/// UTF-8 that never splits a character: an incomplete one at the end waits for the next bytes.
fn decode(pending: &mut Vec<u8>, raw: &[u8]) -> String {
    let mut bytes = std::mem::take(pending);
    bytes.extend_from_slice(raw);
    let mut out = String::new();
    let mut rest: &[u8] = &bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
                match e.error_len() {
                    Some(n) => {
                        out.push('\u{FFFD}');
                        rest = &rest[valid + n..];
                    }
                    None => {
                        *pending = rest[valid..].to_vec();
                        break;
                    }
                }
            }
        }
    }
    out
}

impl PtySession {
    pub fn new(instance: &str, node: &str, vmid: Option<i64>, command: &str, channel: ShellChannel, buffer_bytes: usize) -> Arc<PtySession> {
        let ShellChannel { input, mut events } = channel;
        let session = Arc::new(PtySession {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            instance: instance.to_string(),
            node: node.to_string(),
            vmid,
            command: command.to_string(),
            started_at: now_millis(),
            buffer_bytes,
            input,
            state: Mutex::new(State { chunks: VecDeque::new(), unread: 0, dropped: 0, last_used: Instant::now(), closed_with: None, pending: Vec::new() }),
            wake: Notify::new(),
        });
        let weak: Weak<PtySession> = Arc::downgrade(&session);
        tokio::spawn(async move {
            let mut ended = None;
            while let Some(event) = events.recv().await {
                let Some(s) = weak.upgrade() else { return };
                match event {
                    ShellEvent::Data(chunk) => s.push(chunk),
                    ShellEvent::Closed { code, signal } => {
                        ended = Some(Closed { code, signal });
                        break;
                    }
                }
            }
            if let Some(s) = weak.upgrade() {
                s.state.lock().unwrap().closed_with.get_or_insert(ended.unwrap_or(Closed { code: None, signal: None }));
                s.wake.notify_waiters();
            }
        });
        session
    }

    fn push(&self, chunk: Vec<u8>) {
        {
            let mut st = self.state.lock().unwrap();
            st.unread += chunk.len();
            st.chunks.push_back(chunk);
            // A ring in effect: what nobody read in time goes first, and the reader is told how much.
            while st.unread > self.buffer_bytes {
                let excess = st.unread - self.buffer_bytes;
                let first_len = st.chunks[0].len();
                if first_len <= excess {
                    st.chunks.pop_front();
                    st.unread -= first_len;
                    st.dropped += first_len;
                } else {
                    st.chunks[0].drain(..excess);
                    st.unread -= excess;
                    st.dropped += excess;
                }
            }
        }
        self.wake.notify_waiters();
    }

    /// Only what the agent does counts: a program printing on its own must not keep a session open forever.
    pub fn touch(&self) {
        self.state.lock().unwrap().last_used = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.state.lock().unwrap().last_used.elapsed()
    }

    pub fn closed_with(&self) -> Option<Closed> {
        self.state.lock().unwrap().closed_with.clone()
    }

    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.touch();
        if self.closed_with().is_some() {
            return Err(PveError::new(kind::INVALID_INPUT, format!("Session {} is closed.", self.id)).hint("Open a new one with pve_ssh_session_open."));
        }
        let _ = self.input.send(ShellInput::Data(data.to_vec()));
        Ok(())
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.input.send(ShellInput::Resize { cols, rows });
    }

    /// Until there is output or the session ends, for at most wait_ms.
    pub async fn wait_for_output(&self, wait_ms: u64) {
        self.touch();
        if wait_ms == 0 {
            return;
        }
        let notified = self.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let idle = {
            let st = self.state.lock().unwrap();
            st.unread == 0 && st.closed_with.is_none()
        };
        if idle {
            let _ = tokio::time::timeout(Duration::from_millis(wait_ms), notified).await;
        }
        let settle = {
            let st = self.state.lock().unwrap();
            st.unread > 0 && st.closed_with.is_none()
        };
        if settle {
            tokio::time::sleep(Duration::from_millis(SETTLE_MS.min(wait_ms))).await;
        }
    }

    /// Drains what is there. Terminal escapes are gone: the output of a guest is untrusted.
    /// Returns the output and the bytes dropped since the last read.
    pub fn read(&self) -> (String, usize) {
        let mut st = self.state.lock().unwrap();
        st.last_used = Instant::now();
        let raw: Vec<u8> = st.chunks.drain(..).flatten().collect();
        let dropped = st.dropped;
        st.unread = 0;
        st.dropped = 0;
        let text = decode(&mut st.pending, &raw);
        (scrub_text(&text), dropped)
    }

    pub fn info(&self) -> Map<String, Value> {
        let st = self.state.lock().unwrap();
        let mut out = obj! {
            "session" => &self.id,
            "instance" => &self.instance,
            "node" => &self.node,
            "vmid" => self.vmid,
            "command" => &self.command,
            "started_at" => iso_from_millis(self.started_at),
            "idle_seconds" => crate::js::num(js_round(st.last_used.elapsed().as_millis() as f64 / 1000.0)),
            "unread_bytes" => st.unread,
            "closed" => st.closed_with.is_some(),
        };
        if let Some(c) = &st.closed_with {
            out.insert("exit_code".into(), c.code.map(Value::from).unwrap_or(Value::Null));
        }
        out
    }

    pub fn close(&self) {
        let _ = self.input.send(ShellInput::Close);
    }
}

struct Inner {
    sessions: Mutex<IndexMap<String, Arc<PtySession>>>,
    sweeper: Mutex<Option<tokio::task::JoinHandle<()>>>,
    options: SessionOptions,
}

impl Inner {
    fn sweep(&self) {
        let idle = Duration::from_millis(self.options.idle_ms);
        let mut stale = Vec::new();
        let empty = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|_, s| {
                if s.idle_for() < idle {
                    return true;
                }
                stale.push(s.clone());
                false
            });
            sessions.is_empty()
        };
        for s in stale {
            if s.closed_with().is_none() {
                s.close();
            }
        }
        if empty {
            if let Some(h) = self.sweeper.lock().unwrap().take() {
                h.abort();
            }
        }
    }
}

/// Every session of the server. Lives in the runtime, because HTTP mode has no connection to keep them in.
pub struct SshSessions {
    inner: Arc<Inner>,
}

impl Default for SshSessions {
    fn default() -> Self {
        SshSessions::new(SessionOptions::default())
    }
}

impl SshSessions {
    pub fn new(options: SessionOptions) -> Self {
        SshSessions { inner: Arc::new(Inner { sessions: Mutex::new(IndexMap::new()), sweeper: Mutex::new(None), options }) }
    }

    /// Before connecting: refusing is cheap, a connection that goes unused is not.
    pub fn assert_room(&self) -> Result<()> {
        self.sweep();
        let open = self.inner.sessions.lock().unwrap().values().filter(|s| s.closed_with().is_none()).count();
        let max = self.inner.options.max_sessions;
        if open >= max {
            return Err(PveError::new(kind::INVALID_INPUT, format!("There are already {open} open sessions, the limit is {max}.")).hint("Close one with pve_ssh_session_close. pve_ssh_session_list shows them."));
        }
        Ok(())
    }

    pub fn add(&self, instance: &str, node: &str, vmid: Option<i64>, command: &str, channel: ShellChannel) -> Arc<PtySession> {
        let session = PtySession::new(instance, node, vmid, command, channel, self.inner.options.buffer_bytes);
        self.inner.sessions.lock().unwrap().insert(session.id.clone(), session.clone());
        self.start_sweeper();
        session
    }

    pub fn get(&self, id: &str, instance: &str) -> Result<Arc<PtySession>> {
        self.sweep();
        match self.inner.sessions.lock().unwrap().get(id) {
            Some(s) if s.instance == instance => Ok(s.clone()),
            _ => Err(PveError::new(kind::NOT_FOUND, format!("No session {id}.")).hint("It may have been closed after being idle for too long. pve_ssh_session_list shows the open ones.")),
        }
    }

    pub fn list(&self, instance: &str) -> Vec<Value> {
        self.sweep();
        self.inner.sessions.lock().unwrap().values().filter(|s| s.instance == instance).map(|s| Value::Object(s.info())).collect()
    }

    pub fn remove(&self, id: &str) {
        self.inner.sessions.lock().unwrap().shift_remove(id);
    }

    pub fn sweep(&self) {
        self.inner.sweep();
    }

    pub fn close_all(&self) {
        let all: Vec<Arc<PtySession>> = self.inner.sessions.lock().unwrap().drain(..).map(|(_, s)| s).collect();
        for s in all {
            if s.closed_with().is_none() {
                s.close();
            }
        }
        if let Some(h) = self.inner.sweeper.lock().unwrap().take() {
            h.abort();
        }
    }

    fn start_sweeper(&self) {
        let mut sweeper = self.inner.sweeper.lock().unwrap();
        if sweeper.is_some() {
            return;
        }
        let every = Duration::from_millis(SWEEP_MS.min(self.inner.options.idle_ms).max(1));
        let weak = Arc::downgrade(&self.inner);
        *sweeper = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                // sweep() may abort this very task once nothing is left: let it, outside the lock.
                inner.sweep();
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> (ShellChannel, mpsc::UnboundedReceiver<ShellInput>, mpsc::UnboundedSender<ShellEvent>) {
        let (input, input_rx) = mpsc::unbounded_channel();
        let (events_tx, events) = mpsc::unbounded_channel();
        (ShellChannel { input, events }, input_rx, events_tx)
    }

    #[tokio::test]
    async fn buffers_reads_and_closes() {
        let sessions = SshSessions::default();
        let (channel, mut sent, events) = fake();
        let s = sessions.add("default", "pve1", None, "(login shell)", channel);
        assert_eq!(s.id.len(), 8);
        s.send(b"ls\n").unwrap();
        assert!(matches!(sent.recv().await, Some(ShellInput::Data(d)) if d == b"ls\n"));
        // A character cut in two reaches the reader whole.
        let e = "é".as_bytes();
        events.send(ShellEvent::Data(vec![b'a', e[0]])).unwrap();
        s.wait_for_output(500).await;
        assert_eq!(s.read(), ("a".to_string(), 0));
        events.send(ShellEvent::Data(vec![e[1], b'\x1b', b'[', b'3', b'1', b'm', b'b'])).unwrap();
        s.wait_for_output(500).await;
        assert_eq!(s.read().0, "éb");
        assert_eq!(sessions.list("default").len(), 1);
        assert!(sessions.list("other").is_empty());
        assert_eq!(sessions.get(&s.id, "other").err().unwrap().kind, "not_found");
        events.send(ShellEvent::Closed { code: Some(0), signal: None }).unwrap();
        s.wait_for_output(500).await;
        assert_eq!(s.closed_with(), Some(Closed { code: Some(0), signal: None }));
        assert_eq!(s.send(b"x").unwrap_err().kind, "invalid_input");
        assert_eq!(sessions.list("default")[0]["exit_code"], 0);
    }

    #[tokio::test]
    async fn drops_the_oldest_output() {
        let sessions = SshSessions::new(SessionOptions { buffer_bytes: 10, ..Default::default() });
        let (channel, _sent, events) = fake();
        let s = sessions.add("default", "pve1", None, "x", channel);
        events.send(ShellEvent::Data(b"0123456789".to_vec())).unwrap();
        events.send(ShellEvent::Data(b"abcde".to_vec())).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(s.read(), ("56789abcde".to_string(), 5));
    }

    #[tokio::test]
    async fn limits_and_reaps() {
        let sessions = SshSessions::new(SessionOptions { max_sessions: 2, idle_ms: 60, ..Default::default() });
        let mut keep = Vec::new();
        for _ in 0..2 {
            let (channel, sent, events) = fake();
            keep.push((sessions.add("default", "pve1", None, "x", channel), sent, events));
        }
        assert_eq!(sessions.assert_room().unwrap_err().kind, "invalid_input");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(sessions.list("default").is_empty());
        // Closed when reaped.
        assert!(matches!(keep[0].1.try_recv(), Ok(ShellInput::Close)));
        sessions.assert_room().unwrap();
    }

    #[tokio::test]
    async fn waits_no_longer_than_asked() {
        let sessions = SshSessions::default();
        let (channel, _sent, _events) = fake();
        let s = sessions.add("default", "pve1", None, "x", channel);
        let started = Instant::now();
        s.wait_for_output(100).await;
        assert!(started.elapsed() >= Duration::from_millis(90));
        assert!(started.elapsed() < Duration::from_millis(1000));
        sessions.close_all();
        assert!(sessions.list("default").is_empty());
    }
}
