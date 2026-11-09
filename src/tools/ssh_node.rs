//! SSH tools for the node itself.

use super::ssh_common::{
    ReadFileArgs, assert_ok, assert_ran, decode_base64, exec_options, file_mode, file_owner, js_trim, max_output_bytes, node_target, parse_ls, present, read_remote_file, remote_path,
    stat_remote_file, target_node, timeout_seconds, unit_name,
};
use super::{Args, ArgsExt, ToolContext, ToolDef, page_limit, page_offset, page_rows, paging_args};
use crate::errors::{PveError, Result, kind};
use crate::js::{js_len, num};
use crate::obj;
use crate::proxmox::localpath::resolve_local_path;
use crate::proxmox::policy::Gate;
use crate::schema::z;
use crate::shape;
use crate::ssh::quote::raw;
use crate::ssh::scripts::{EXIT_CD_FAILED, EXIT_NOT_FOUND, WriteFileOptions, delete_file_script, list_dir_script, write_file_script};
use crate::ssh::{Access, ExecOptions, ExecResult, ShellCommand, SshTarget};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::{Arc, LazyLock};

fn identity(script: &str) -> Result<String> {
    Ok(script.to_string())
}

fn timeout_ms_of(args: &Args) -> Option<u64> {
    args.u64("timeout_seconds").filter(|s| *s > 0).map(|s| s * 1000)
}

/// A partial download is never left under the final name.
pub async fn download_to(ctx: &ToolContext, target: &SshTarget, remote: &str, local: &str, timeout_ms: Option<u64>) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let part = format!("{local}.{}.part", &id[..8]);
    let sftp = ctx.ssh.sftp(target, Access::Read).await?;
    let result = async {
        sftp.fast_get(remote, &part, timeout_ms).await?;
        std::fs::rename(&part, local).map_err(|e| PveError::internal(format!("Could not move the download to {local}: {e}")))
    }
    .await;
    sftp.close();
    let _ = std::fs::remove_file(&part);
    result
}

pub fn assert_local_target(local: &str, overwrite: bool, display: &str) -> Result<()> {
    let Ok(meta) = std::fs::metadata(local) else { return Ok(()) };
    if meta.is_dir() {
        return Err(PveError::new(kind::LOCAL_PATH_REFUSED, format!("{display} is a directory.")).hint("Give the path of a file, not of the directory it goes in."));
    }
    if !overwrite {
        return Err(PveError::new(kind::LOCAL_PATH_REFUSED, format!("{display} already exists on this machine.")).hint("Pass overwrite: true to replace it."));
    }
    Ok(())
}

/// Size of a local file, as statSync(local).size.
pub fn local_size(local: &str) -> Result<u64> {
    std::fs::metadata(local).map(|m| m.len()).map_err(|e| PveError::internal(format!("Cannot stat {local}: {e}")))
}

/// A fixed command, with its own status: one failing says nothing about the others.
async fn diagnostic(ctx: &ToolContext, target: &SshTarget, command: &str, max_bytes: u64) -> Result<ExecResult> {
    ctx.ssh.run(target, &ShellCommand::read(command), ExecOptions { timeout_ms: None, max_bytes: Some(max_bytes) }).await
}

const DIAGNOSTICS: [(&str, &str); 8] = [
    ("uptime", "uptime"),
    ("disk", "df -hP"),
    ("memory", "free -m"),
    ("zfs", "zpool status -x"),
    ("lvm", "lvs --noheadings -o lv_name,vg_name,lv_size,data_percent,metadata_percent"),
    ("cluster", "pvecm status"),
    ("failed_units", "systemctl --failed --no-legend --no-pager"),
    ("journal_errors", "journalctl -p err -n 50 --no-pager -o short-iso -b"),
];

static COMMANDS_MISSING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:not found|No such file)").expect("valid pattern"));
static NO_SUCH_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)No such file").expect("valid pattern"));
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("valid pattern"));

fn fields_of(line: &str) -> Vec<&str> {
    WHITESPACE.split(js_trim(line)).collect()
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn number_of(s: &str) -> Value {
    num(crate::js::js_number_str(s).unwrap_or(f64::NAN))
}

fn parse_pct_list(output: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in output.split('\n').skip(1) {
        let fields = fields_of(line);
        if !is_digits(fields[0]) || fields.len() < 3 {
            continue;
        }
        let mut row = obj! { "vmid" => number_of(fields[0]), "status" => fields[1] };
        if fields.len() > 3 {
            row.insert("lock".into(), Value::String(fields[2].to_string()));
        }
        row.insert("name".into(), Value::String(fields[fields.len() - 1].to_string()));
        rows.push(Value::Object(row));
    }
    rows
}

fn parse_qm_list(output: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in output.split('\n').skip(1) {
        let fields = fields_of(line);
        if !is_digits(fields[0]) || fields.len() < 6 {
            continue;
        }
        let n = fields.len();
        let pid = crate::js::js_number_str(fields[n - 1]).unwrap_or(f64::NAN);
        let mut row = obj! {
            "vmid" => number_of(fields[0]),
            "name" => fields[1..n - 4].join(" "),
            "status" => fields[n - 4],
            "memory_mb" => number_of(fields[n - 3]),
            "bootdisk_gb" => number_of(fields[n - 2]),
        };
        if pid != 0.0 && !pid.is_nan() {
            row.insert("pid".into(), num(pid));
        }
        rows.push(Value::Object(row));
    }
    rows
}

const WARNING_ROOT: &str = "This runs as root on the hypervisor: not a sandbox.";

fn default_node(args: &Args) -> &str {
    args.str("node").unwrap_or("(default)")
}

async fn ssh_test(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let res = ctx.ssh.run(&target, &ShellCommand::read("hostname; id -un; pveversion 2>&1"), ExecOptions::default()).await?;
    assert_ran(&res, "The SSH test", None)?;
    let parts: Vec<&str> = res.stdout.split('\n').collect();
    let version = if parts.len() > 2 { parts[2..].join("\n") } else { String::new() };
    Ok(Value::Object(obj! {
        "node" => &target.node,
        "connected" => true,
        "hostname" => parts[0],
        "user" => parts.get(1).copied(),
        "pveversion" => if res.exit_code == Some(0) { Value::String(js_trim(&version).to_string()) } else { Value::Null },
        "host_key" => res.host_key.as_ref().map(|k| k.to_json()),
        "duration_ms" => res.duration_ms,
        "untrusted" => true,
    }))
}

async fn host_diagnostics(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let outcomes = futures::future::join_all(DIAGNOSTICS.iter().map(|(_, command)| diagnostic(&ctx, &target, command, 128 * 1024))).await;
    // Not being able to connect at all is one failure, not eight.
    if outcomes.iter().all(|o| o.is_err())
        && let Some(Err(first)) = outcomes.first()
    {
        return Err(first.clone());
    }
    let mut sections = Map::new();
    for ((name, command), outcome) in DIAGNOSTICS.iter().zip(outcomes) {
        let section = match outcome {
            Err(e) => obj! { "ok" => false, "error" => format!("{}: {}", e.kind, e.message) },
            Ok(res) => {
                let absent = res.exit_code == Some(127) && COMMANDS_MISSING.is_match(&res.stderr);
                let stderr = js_trim(&res.stderr);
                let mut s = obj! {
                    "ok" => res.exit_code == Some(0) && !res.timed_out,
                    "command" => *command,
                    "exit_code" => res.exit_code.map(Value::from).unwrap_or(Value::Null),
                    "output" => js_trim(&res.stdout),
                };
                if !stderr.is_empty() {
                    s.insert("stderr".into(), Value::String(stderr.to_string()));
                }
                if absent {
                    s.insert("not_installed".into(), Value::Bool(true));
                }
                if res.truncated {
                    s.insert("truncated".into(), Value::Bool(true));
                }
                if res.timed_out {
                    s.insert("timed_out".into(), Value::Bool(true));
                }
                s
            }
        };
        sections.insert(name.to_string(), Value::Object(section));
    }
    Ok(Value::Object(obj! { "node" => &target.node, "sections" => sections, "untrusted" => true }))
}

async fn journal(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let mut parts = vec![crate::sh!("journalctl --no-pager -o short-iso -n {}", args.i64("lines").unwrap_or(200))?];
    if let Some(unit) = args.str("unit").filter(|s| !s.is_empty()) {
        parts.push(crate::sh!("-u {}", unit)?);
    }
    if let Some(since) = args.str("since").filter(|s| !s.is_empty()) {
        parts.push(crate::sh!("{}", format!("--since={since}"))?);
    }
    if let Some(priority) = args.str("priority").filter(|s| !s.is_empty()) {
        parts.push(crate::sh!("-p {}", priority)?);
    }
    let res = ctx.ssh.run(&target, &ShellCommand::read(parts.join(" ")), ExecOptions::default()).await?;
    assert_ok(&res, "journalctl", None)?;
    Ok(present(&res, obj! { "node" => &target.node }))
}

async fn list_dir(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let path = args.str("path").unwrap_or_default();
    let res = ctx.ssh.run(&target, &ShellCommand::read(list_dir_script(path)?), ExecOptions::default()).await?;
    assert_ok(&res, &format!("Listing {path}"), None)?;
    let (limit, offset) = paging_args(&args);
    let mut out = obj! { "node" => &target.node, "path" => path };
    out.extend(page_rows(parse_ls(&res.stdout), limit, offset));
    if res.truncated {
        out.insert("truncated_output".into(), Value::Bool(true));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn read_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let read = ReadFileArgs { path: args.string("path").unwrap_or_default(), max_bytes: args.u64("max_bytes"), allow_partial: args.flag("allow_partial") };
    let file = read_remote_file(&ctx, &target, &identity, &read, None).await?;
    let mut out = obj! { "node" => &target.node };
    if let Value::Object(m) = file {
        out.extend(m);
    }
    Ok(Value::Object(out))
}

async fn pct_list(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let res = ctx.ssh.run(&target, &ShellCommand::read("pct list"), ExecOptions::default()).await?;
    assert_ran(&res, "pct list", None)?;
    assert_ok(&res, "pct list", None)?;
    Ok(Value::Object(obj! { "node" => &target.node, "rows" => parse_pct_list(&res.stdout), "untrusted" => true }))
}

async fn qm_list(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let res = ctx.ssh.run(&target, &ShellCommand::read("qm list"), ExecOptions::default()).await?;
    assert_ok(&res, "qm list", None)?;
    Ok(Value::Object(obj! { "node" => &target.node, "rows" => parse_qm_list(&res.stdout), "untrusted" => true }))
}

async fn exec(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let command = args.str("command").unwrap_or_default();
    let text = match args.str("cwd").filter(|s| !s.is_empty()) {
        Some(cwd) => crate::sh!("cd -- {} || exit {}\n{}", cwd, EXIT_CD_FAILED, raw(command))?,
        None => command.to_string(),
    };
    let mut cmd = ShellCommand::write(text);
    if let Some(stdin) = args.str("stdin") {
        cmd = cmd.stdin(stdin.as_bytes().to_vec());
    }
    let res = ctx.ssh.run(&target, &cmd, exec_options(&args, &ctx)).await?;
    assert_ran(&res, "The command", None)?;
    Ok(present(&res, obj! { "node" => &target.node }))
}

async fn write_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let path = args.str("path").unwrap_or_default();
    let content = args.str("content").unwrap_or_default();
    let stdin: Vec<u8> = if args.str("encoding") == Some("base64") { decode_base64(content) } else { content.as_bytes().to_vec() };
    let script = write_file_script(path, &WriteFileOptions { mode: args.string("mode"), owner: args.string("owner"), backup: args.flag("backup"), create_parents: args.flag("create_parents") })?;
    let cmd = ShellCommand::write(script).stdin(stdin).display(format!("write {path} (content on stdin)"));
    let res = ctx.ssh.run(&target, &cmd, ExecOptions::default()).await?;
    assert_ok(&res, &format!("Writing {path}"), None)?;
    if res.dry_run {
        return Ok(Value::Object(obj! { "node" => &target.node, "path" => path }));
    }
    let mut parts = res.stdout.split('\n');
    let bytes = parts.next().unwrap_or("");
    let backup = parts.next().filter(|b| !b.is_empty());
    Ok(Value::Object(obj! { "node" => &target.node, "path" => path, "bytes" => number_of(bytes), "backup" => backup }))
}

async fn upload(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let local_path = args.str("local_path").unwrap_or_default();
    let local = resolve_local_path(ctx.instance.local_dir.as_deref(), local_path, true)?;
    if !std::fs::metadata(&local).map(|m| m.is_file()).unwrap_or(false) {
        return Err(PveError::new(kind::LOCAL_PATH_REFUSED, format!("{local_path} is not a regular file.")));
    }
    let target = node_target(&ctx, args.str("node")).await?;
    let path = args.str("path").unwrap_or_default();
    let mode = u32::from_str_radix(args.str("mode").unwrap_or("0644"), 8).unwrap_or(0o644);
    let sftp = ctx.ssh.sftp(&target, Access::Write).await?;
    let result = sftp.fast_put(&local, path, Some(mode), timeout_ms_of(&args)).await;
    sftp.close();
    result?;
    Ok(Value::Object(obj! { "node" => &target.node, "path" => path, "bytes" => local_size(&local)? }))
}

async fn download(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let local_path = args.str("local_path").unwrap_or_default();
    let local = resolve_local_path(ctx.instance.local_dir.as_deref(), local_path, false)?;
    assert_local_target(&local, args.flag("overwrite"), local_path)?;
    let target = node_target(&ctx, args.str("node")).await?;
    let path = args.str("path").unwrap_or_default();
    let Some(stat) = stat_remote_file(&ctx, &target, &identity, path, None).await? else {
        ctx.dry_run_log.lock().unwrap().push(json!({ "ssh": { "node": &target.node, "sftp": "fastGet", "path": path, "access": "read" } }));
        return Ok(Value::Object(obj! { "node" => &target.node, "path" => path, "local_path" => &local }));
    };
    download_to(&ctx, &target, &stat.real, &local, timeout_ms_of(&args)).await?;
    Ok(Value::Object(obj! { "node" => &target.node, "path" => path, "local_path" => &local, "bytes" => local_size(&local)? }))
}

async fn delete_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let target = node_target(&ctx, args.str("node")).await?;
    let path = args.str("path").unwrap_or_default();
    let res = ctx.ssh.run(&target, &ShellCommand::write(delete_file_script(path, args.flag("missing_ok"))?), ExecOptions::default()).await?;
    let what = format!("Deleting {path}");
    assert_ran(&res, &what, None)?;
    if res.exit_code == Some(EXIT_NOT_FOUND) || NO_SUCH_FILE.is_match(&res.stderr) {
        return Err(PveError::new(kind::NOT_FOUND, format!("{path} does not exist.")));
    }
    assert_ok(&res, &what, None)?;
    Ok(Value::Object(obj! { "node" => &target.node, "path" => path, "deleted" => !res.dry_run }))
}

/// SSH tools for the node itself.
pub fn ssh_node_tools() -> Vec<ToolDef> {
    vec![
        ToolDef::new(
            "pve_ssh_test",
            "Test SSH to a node",
            "ssh",
            Gate::SshRead,
            "Connects to a node over SSH and reports the verified host key fingerprint, the user and pveversion. Shows why SSH does not work, if it does not.",
        )
        .idempotent()
        .input(shape!["node" => target_node()])
        .handler(ssh_test),
        ToolDef::new(
            "pve_ssh_host_diagnostics",
            "Node diagnostics over SSH",
            "ssh",
            Gate::SshRead,
            "Uptime, disk, memory, zpool status, lvs, pvecm status, failed units and recent journal errors on a node. Each has its own status, so that one failing does not hide the others.",
        )
        .idempotent()
        .input(shape!["node" => target_node()])
        .handler(host_diagnostics),
        ToolDef::new("pve_ssh_journal", "Read the journal of a node", "ssh", Gate::SshRead, "journalctl on a node, optionally for one unit and since a time.")
            .idempotent()
            .input(shape![
                "node" => target_node(),
                "unit" => unit_name().optional().describe("Only this unit, such as pveproxy or pvedaemon."),
                "lines" => z::int().min(1).max(10_000).optional().describe("Last lines to show. Default 200."),
                "since" => z::string()
                    .regex(r"^(?:-\d+[a-z]+|[0-9A-Za-z][0-9A-Za-z :.+-]*)$", "Expected a time such as \"2024-01-31 12:00\", yesterday or -1h")
                    .max(64)
                    .optional()
                    .describe("Such as \"2024-01-31 12:00\", yesterday or -1h."),
                "priority" => z::enumeration(&["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]).optional().describe("This level and above."),
            ])
            .handler(journal),
        ToolDef::new("pve_ssh_list_dir", "List a directory on a node", "ssh", Gate::SshRead, "ls -la on a node, as rows.")
            .idempotent()
            .input(shape!["node" => target_node(), "path" => remote_path(), "page_limit" => page_limit(), "page_offset" => page_offset()])
            .handler(list_dir),
        ToolDef::new(
            "pve_ssh_read_file",
            "Read a file on a node",
            "ssh",
            Gate::SshRead,
            "Reads a text file on a node, up to a size cap. Refuses well-known secrets such as /etc/pve/priv/*, /root/.ssh/id_* and /etc/shadow, also through a link, unless PROXMOX_ALLOW_SENSITIVE is on.",
        )
        .idempotent()
        .input(shape![
            "node" => target_node(),
            "path" => remote_path(),
            "max_bytes" => z::int().min(1).optional().describe("Largest file to return. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES."),
            "allow_partial" => z::boolean().optional().describe("Return the start of a file over the limit, instead of an error."),
        ])
        .handler(read_file),
        ToolDef::new(
            "pve_ssh_pct_list",
            "pct list on a node",
            "ssh",
            Gate::SshRead,
            "The containers of a node as pct sees them, with their lock. The API has the same list without the lock: pve_list_lxcs.",
        )
        .also(&["lxc"])
        .idempotent()
        .input(shape!["node" => target_node()])
        .handler(pct_list),
        ToolDef::new("pve_ssh_qm_list", "qm list on a node", "ssh", Gate::SshRead, "The VMs of a node as qm sees them, with their process id.")
            .also(&["vm"])
            .idempotent()
            .input(shape!["node" => target_node()])
            .handler(qm_list),
        ToolDef::new(
            "pve_ssh_exec",
            "Run a command on a node",
            "ssh",
            Gate::SshWrite,
            format!("Runs any shell command on a node. {WARNING_ROOT} The protected guest list does not apply to what a command does, and neither does any other policy of this server. A non-zero exit code is reported, not an error. Tell the user what you run."),
        )
        .destructive()
        .open_world()
        .input(shape![
            "node" => target_node(),
            "command" => z::string().min(1).describe("Shell text, as typed at a root prompt."),
            "stdin" => z::string().optional().describe("Given to the command as its input. Never logged."),
            "cwd" => remote_path().optional().describe("Run in this directory."),
            "timeout_seconds" => timeout_seconds(),
            "max_output_bytes" => max_output_bytes(),
        ])
        .confirmation(|args| format!("Run this as root on node {}?\n{}", default_node(args), args.str("command").unwrap_or_default()))
        .handler(exec),
        ToolDef::new(
            "pve_ssh_write_file",
            "Write a file on a node",
            "ssh",
            Gate::SshWrite,
            format!("Writes a file on a node, whole or not at all, keeping the mode and owner of an existing file unless told otherwise. {WARNING_ROOT}"),
        )
        .destructive()
        .input(shape![
            "node" => target_node(),
            "path" => remote_path(),
            "content" => z::string().describe("The new content. Never logged."),
            "encoding" => z::enumeration(&["utf8", "base64"]).optional().describe("How content is written. Default utf8."),
            "mode" => file_mode().optional().describe("Such as 0644."),
            "owner" => file_owner().optional().describe("user or user:group."),
            "backup" => z::boolean().optional().describe("Keep the old file as path.bak.TIMESTAMP."),
            "create_parents" => z::boolean().optional().describe("Create missing directories."),
        ])
        .confirmation(|args| format!("Write {} characters to {} on node {}, as root?", js_len(args.str("content").unwrap_or_default()), args.str("path").unwrap_or_default(), default_node(args)))
        .handler(write_file),
        ToolDef::new(
            "pve_ssh_upload",
            "Upload a local file to a node",
            "ssh",
            Gate::SshWrite,
            "Copies a file from this server, under PROXMOX_LOCAL_DIR only, to a node over SFTP. SFTP runs as the SSH user, without sudo.",
        )
        .destructive()
        .input(shape![
            "node" => target_node(),
            "local_path" => z::string().min(1).describe("Relative to PROXMOX_LOCAL_DIR, or absolute under it."),
            "path" => remote_path().describe("Where it goes on the node. An existing file is replaced."),
            "mode" => file_mode().optional().describe("Default 0644."),
            "timeout_seconds" => timeout_seconds(),
        ])
        .confirmation(|args| format!("Copy {} to {} on node {}, replacing any file there?", args.str("local_path").unwrap_or_default(), args.str("path").unwrap_or_default(), default_node(args)))
        .handler(upload),
        ToolDef::new(
            "pve_ssh_download",
            "Download a file from a node",
            "ssh",
            Gate::SshWrite,
            "Copies a file from a node to this server, under PROXMOX_LOCAL_DIR only, over SFTP. Refuses well-known secrets, as pve_ssh_read_file does. SFTP runs as the SSH user, without sudo.",
        )
        .input(shape![
            "node" => target_node(),
            "path" => remote_path().describe("The file on the node."),
            "local_path" => z::string().min(1).describe("Relative to PROXMOX_LOCAL_DIR, or absolute under it. Its directory must exist."),
            "overwrite" => z::boolean().optional().describe("Replace a local file that exists. Default false."),
            "timeout_seconds" => timeout_seconds(),
        ])
        .handler(download),
        ToolDef::new("pve_ssh_delete_file", "Delete a file on a node", "ssh", Gate::SshWrite, format!("Deletes one file on a node. Not directories. {WARNING_ROOT}"))
            .destructive()
            .input(shape![
                "node" => target_node(),
                "path" => remote_path(),
                "missing_ok" => z::boolean().optional().describe("A file already gone is not an error."),
            ])
            .confirmation(|args| format!("Delete {} on node {}?", args.str("path").unwrap_or_default(), default_node(args)))
            .handler(delete_file),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&ssh_node_tools());
    }

    #[test]
    fn ssh_node_parses_lists() {
        let pct = "VMID       Status     Lock         Name\n101        running                 web\n102        stopped    backup       db\n";
        assert_eq!(Value::Array(parse_pct_list(pct)), json!([{ "vmid": 101, "status": "running", "name": "web" }, { "vmid": 102, "status": "stopped", "lock": "backup", "name": "db" }]));
        let qm = "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n       100 my vm                running    2048              32.00 1234\n       101 off                  stopped    1024              10.50 0\n";
        assert_eq!(
            Value::Array(parse_qm_list(qm)),
            json!([{ "vmid": 100, "name": "my vm", "status": "running", "memory_mb": 2048, "bootdisk_gb": 32, "pid": 1234 }, { "vmid": 101, "name": "off", "status": "stopped", "memory_mb": 1024, "bootdisk_gb": 10.5 }])
        );
    }
}
