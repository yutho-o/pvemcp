//! PTY sessions, for what only works interactively.

use super::ssh_common::{assert_writable, locate_lxc, pct_failure};
use super::{Args, ArgsExt, ToolContext, ToolDef, node_name, vmid};
use crate::errors::{PveError, Result, kind};
use crate::js::js_slice_start;
use crate::obj;
use crate::proxmox::policy::Gate;
use crate::runtime::Runtime;
use crate::schema::z;
use crate::shape;
use crate::ssh::sessions::SshSessions;
use crate::ssh::{ExecResult, ShellOptions, SshTarget};
use futures::FutureExt;
use serde_json::{Value, json};
use std::sync::Arc;

/// One manager per server, closed with it. In HTTP mode a session outlives the request that opened it.
pub fn sessions_of(runtime: &Runtime) -> Arc<SshSessions> {
    let sessions = runtime.state("ssh-sessions", || Arc::new(SshSessions::default()));
    let hooked = sessions.clone();
    runtime.state("ssh-sessions-hook", || {
        runtime.on_shutdown(Arc::new(move || {
            let s = hooked.clone();
            async move { s.close_all() }.boxed()
        }));
        Arc::new(())
    });
    sessions
}

const KEYS: [(&str, &str); 24] = [
    ("ctrl-a", "\x01"),
    ("ctrl-b", "\x02"),
    ("ctrl-c", "\x03"),
    ("ctrl-d", "\x04"),
    ("ctrl-e", "\x05"),
    ("ctrl-k", "\x0b"),
    ("ctrl-l", "\x0c"),
    ("ctrl-r", "\x12"),
    ("ctrl-u", "\x15"),
    ("ctrl-w", "\x17"),
    ("ctrl-x", "\x18"),
    ("ctrl-z", "\x1a"),
    ("enter", "\r"),
    ("tab", "\t"),
    ("esc", "\x1b"),
    ("backspace", "\x7f"),
    ("up", "\x1b[A"),
    ("down", "\x1b[B"),
    ("right", "\x1b[C"),
    ("left", "\x1b[D"),
    ("home", "\x1b[H"),
    ("end", "\x1b[F"),
    ("page-up", "\x1b[5~"),
    ("page-down", "\x1b[6~"),
];

fn key(name: &str) -> &'static str {
    KEYS.iter().find(|(k, _)| *k == name).map(|(_, v)| *v).unwrap_or("")
}

/// How long open waits for the first output, and for pct to say the container is not running.
const OPEN_WAIT_MS: u64 = 400;

fn session_id() -> crate::schema::Schema {
    z::string().regex(r"^[a-f0-9-]{1,36}$", "Expected a session id").describe("From pve_ssh_session_open.")
}

fn log_dry_run(ctx: &ToolContext, node: &str, command: String) {
    ctx.dry_run_log.lock().unwrap().push(json!({ "ssh": { "node": node, "command": command, "access": "write" } }));
}

async fn open(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let sessions = sessions_of(&ctx.runtime);
    let vmid = args.i64("vmid");
    let node = match vmid {
        Some(vmid) => {
            assert_writable(&ctx, vmid)?;
            locate_lxc(&ctx, vmid, args.str("node")).await?.node
        }
        None => match args.string("node") {
            Some(n) => n,
            None => ctx.nodes.default_node().await?,
        },
    };
    sessions.assert_room()?;
    let command = match vmid {
        Some(v) => Some(crate::sh!("pct enter {}", v)?),
        None => None,
    };
    let options = ShellOptions { cols: args.u64("cols").map(|n| n as u32), rows: args.u64("rows").map(|n| n as u32), term: args.string("term"), command: command.clone() };
    let channel = ctx.ssh.shell(&SshTarget::node(node.clone()), options).await?;
    let session = sessions.add(&ctx.instance.name, &node, vmid, command.as_deref().unwrap_or("(login shell)"), channel);
    session.wait_for_output(OPEN_WAIT_MS).await;
    let (output, _) = session.read();
    if let Some(closed) = session.closed_with() {
        sessions.remove(&session.id);
        let res = ExecResult { stdout: String::new(), stderr: output.replace('\r', ""), exit_code: closed.code, ..Default::default() };
        if let Some(failure) = pct_failure(&res, vmid) {
            return Err(failure);
        }
        return Err(PveError::new(kind::UPSTREAM_ERROR, format!("The terminal closed right away: {}", js_slice_start(output.trim(), 500)))
            .details(json!({ "exit_code": closed.code, "untrusted": true })));
    }
    Ok(Value::Object(obj! {
        "session" => &session.id,
        "node" => &node,
        "vmid" => vmid,
        "output" => output,
        "next_step" => "pve_ssh_session_send",
        "untrusted" => true,
    }))
}

async fn send(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let session = sessions_of(&ctx.runtime).get(args.str("session").unwrap_or(""), &ctx.instance.name)?;
    let mut data = args.string("input").unwrap_or_default();
    for k in args.strings("keys").unwrap_or_default() {
        data.push_str(key(&k));
    }
    let bytes = data.len();
    if ctx.dry_run {
        log_dry_run(&ctx, &session.node, format!("(session {}: {bytes} bytes)", session.id));
        return Ok(Value::Object(obj! { "session" => &session.id, "sent_bytes" => 0 }));
    }
    if let (Some(cols), Some(rows)) = (args.u64("cols"), args.u64("rows")) {
        session.resize(cols as u32, rows as u32);
    }
    if !data.is_empty() {
        session.send(data.as_bytes())?;
        ctx.runtime.record_write(&ctx.instance.name, obj! { "status" => "sent", "ssh" => obj! { "node" => &session.node, "session" => &session.id, "bytes" => bytes } });
    }
    Ok(Value::Object(obj! { "session" => &session.id, "sent_bytes" => bytes, "next_step" => "pve_ssh_session_read" }))
}

async fn read(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let sessions = sessions_of(&ctx.runtime);
    let session = sessions.get(args.str("session").unwrap_or(""), &ctx.instance.name)?;
    session.wait_for_output(args.u64("wait_ms").unwrap_or(500)).await;
    let (output, dropped) = session.read();
    let closed = session.closed_with();
    if closed.is_some() {
        sessions.remove(&session.id);
    }
    let mut out = obj! { "session" => &session.id, "output" => output };
    if dropped > 0 {
        out.insert("dropped_bytes".into(), Value::from(dropped));
    }
    out.insert("closed".into(), Value::Bool(closed.is_some()));
    if let Some(c) = closed {
        out.insert("exit_code".into(), c.code.map(Value::from).unwrap_or(Value::Null));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn close(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let sessions = sessions_of(&ctx.runtime);
    let session = sessions.get(args.str("session").unwrap_or(""), &ctx.instance.name)?;
    if ctx.dry_run {
        log_dry_run(&ctx, &session.node, format!("(close session {})", session.id));
        return Ok(Value::Object(obj! { "session" => &session.id }));
    }
    let (output, _) = session.read();
    if session.closed_with().is_none() {
        session.close();
    }
    sessions.remove(&session.id);
    ctx.runtime.record_write(&ctx.instance.name, obj! { "status" => "sent", "ssh" => obj! { "node" => &session.node, "session" => &session.id, "closed" => true } });
    Ok(Value::Object(obj! { "session" => &session.id, "closed" => true, "output" => output, "untrusted" => true }))
}

/// PTY sessions, for what only works interactively.
pub fn ssh_session_tools() -> Vec<ToolDef> {
    let key_names: Vec<&str> = KEYS.iter().map(|(k, _)| *k).collect();
    vec![
        ToolDef::new(
            "pve_ssh_session_open",
            "Open an interactive terminal",
            "ssh",
            Gate::SshWrite,
            "Opens a terminal: a root shell on a node, or with vmid, pct enter into a container. For interactive programs only: pve_ssh_exec and pve_lxc_exec suit everything else better. This is root on the hypervisor, or in the container, and no policy of this server applies to what is typed. At most 8 at a time, closed after 15 minutes of not being used.",
        )
        .also(&["lxc"])
        .destructive()
        .open_world()
        .input(shape![
            "node" => node_name().optional().describe("Node for a shell. Default: PROXMOX_DEFAULT_NODE, or the only node. With vmid, checked if given."),
            "vmid" => vmid().optional().describe("A container to enter, instead of a shell on the node."),
            "cols" => z::int().min(10).max(1000).optional().describe("Default 120."),
            "rows" => z::int().min(5).max(1000).optional().describe("Default 40."),
            "term" => z::string().regex(r"^[a-zA-Z0-9._-]+$", "Expected a terminal type").max(64).optional().describe("Default xterm."),
        ])
        .confirmation(|args| match args.i64("vmid") {
            Some(v) => format!("Open a root terminal in container {v}?"),
            None => format!("Open a root terminal on node {}?", args.str("node").unwrap_or("(default)")),
        })
        .handler(open),
        ToolDef::new(
            "pve_ssh_session_send",
            "Type into a terminal",
            "ssh",
            Gate::SshWrite,
            "Sends text and control keys to an open terminal, as if typed. A line runs only with enter at the end of it: put \"\\n\" in input, or enter in keys. Nothing here is checked: this is a root terminal.",
        )
        .also(&["lxc"])
        // Announced as destructive, but opening the session is what a human confirms: not every key press.
        .destructive_when(|_| false)
        .open_world()
        .input(shape![
            "session" => session_id(),
            "input" => z::string().max(1_048_576).optional().describe("Text to type. Never logged."),
            "keys" => z::array(z::enumeration(&key_names)).max(256).optional().describe("Keys to press after the text, such as [\"ctrl-c\"]."),
            "cols" => z::int().min(10).max(1000).optional().describe("Resize the terminal."),
            "rows" => z::int().min(5).max(1000).optional().describe("Resize the terminal."),
        ])
        .handler(send),
        ToolDef::new(
            "pve_ssh_session_read",
            "Read from a terminal",
            "ssh",
            Gate::SshWrite,
            "What a terminal printed since the last read, without escape sequences. Up to 1 MiB is kept: dropped_bytes says if older output was lost. closed is true once the program has ended.",
        )
        .also(&["lxc"])
        .input(shape![
            "session" => session_id(),
            "wait_ms" => z::int().min(0).max(60_000).optional().describe("If there is nothing yet, wait this long for output. Default 500."),
        ])
        .handler(read),
        ToolDef::new("pve_ssh_session_close", "Close a terminal", "ssh", Gate::SshWrite, "Closes a terminal, and what runs in it gets a hangup. Any output not yet read is returned.")
            .also(&["lxc"])
            .input(shape!["session" => session_id()])
            .handler(close),
        ToolDef::new("pve_ssh_session_list", "List open terminals", "ssh", Gate::SshWrite, "The terminals opened with pve_ssh_session_open.")
            .also(&["lxc"])
            .idempotent()
            .handler(|_args, ctx: Arc<ToolContext>| async move { Ok(Value::Object(obj! { "rows" => sessions_of(&ctx.runtime).list(&ctx.instance.name) })) }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&ssh_session_tools());
    }
}
