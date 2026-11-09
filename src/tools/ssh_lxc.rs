//! SSH tools for containers, all through pct on the node.

use super::ssh_common::{
    ReadFileArgs, assert_ok, assert_ran, assert_writable, decode_base64, exec_options, file_mode, file_owner, guest_node, header_fields, js_trim, locate_lxc, max_output_bytes,
    package_name, parse_authorized_keys, parse_header, parse_ls, parse_public_key, parse_sections, present, read_remote_file, remote_path, stat_remote_file, timeout_seconds, unit_name,
    user_name, ENV_NAME,
};
use super::ssh_node::{assert_local_target, download_to, local_size};
use super::{Args, ArgsExt, ToolContext, ToolDef, page_limit, page_offset, page_rows, paging_args, vmid};
use crate::errors::{PveError, Result, kind};
use crate::js::{js_len, js_number_str, js_slice_start, num};
use crate::obj;
use crate::proxmox::localpath::resolve_local_path;
use crate::proxmox::nodes::GuestLocation;
use crate::proxmox::policy::Gate;
use crate::schema::{Shape, z};
use crate::sh;
use crate::shape;
use crate::ssh::quote::raw;
use crate::ssh::scripts::{
    CreateUserOptions, EXIT_CD_FAILED, EXIT_NO_MANAGER, EXIT_NOT_FOUND, EXIT_REFUSED_LINK, EXIT_RELOAD_FAILED, EXIT_SSHD_NOT_EFFECTIVE, EXIT_SSHD_REJECTED, LogsOptions, SshdSettings,
    WriteFileOptions, add_key_script, create_user_script, delete_file_script, delete_user_script, disk_usage_script, install_packages_script, list_dir_script, list_keys_script,
    list_packages_script, logs_script, lxc_info_script, pct_exec, ports_script, processes_script, remove_key_script, remove_packages_script, service_script, service_status_script,
    ssh_configure_script, ssh_disable_script, ssh_enable_script, ssh_status_script, update_packages_script, write_file_script,
};
use crate::ssh::{Access, ExecOptions, ExecResult, ShellCommand, SshTarget};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::sync::{Arc, LazyLock};

fn guest() -> Shape {
    shape!["vmid" => vmid(), "node" => guest_node()]
}

/// The guest shape, then these.
fn guest_and(more: Shape) -> Shape {
    let mut s = guest();
    s.extend(more);
    s
}

const ROOT_IN_CT: &str = "Runs as root inside the container, from the node, through pct: not a sandbox.";

#[derive(Default)]
struct RunExtra {
    stdin: Option<Vec<u8>>,
    display: Option<String>,
    sensitive_stdin: bool,
    timeout_ms: Option<u64>,
    max_bytes: Option<u64>,
}

impl RunExtra {
    fn timeout(ms: u64) -> Self {
        RunExtra { timeout_ms: Some(ms), ..Default::default() }
    }
    fn exec(opts: ExecOptions) -> Self {
        RunExtra { timeout_ms: opts.timeout_ms, max_bytes: opts.max_bytes, ..Default::default() }
    }
}

/// Runs a script inside a container.
async fn run_in(ctx: &ToolContext, loc: &GuestLocation, access: Access, script: &str, extra: RunExtra) -> Result<ExecResult> {
    let text = pct_exec(loc.vmid, script)?;
    let mut cmd = match access {
        Access::Read => ShellCommand::read(text),
        Access::Write => ShellCommand::write(text),
    };
    if let Some(stdin) = extra.stdin {
        cmd = cmd.stdin(stdin);
    }
    if let Some(display) = extra.display {
        cmd = cmd.display(display);
    }
    if extra.sensitive_stdin {
        cmd = cmd.sensitive_stdin();
    }
    ctx.ssh.run(&SshTarget::node(&loc.node), &cmd, ExecOptions { timeout_ms: extra.timeout_ms, max_bytes: extra.max_bytes }).await
}

async fn for_write(ctx: &ToolContext, id: i64, node: Option<&str>) -> Result<GuestLocation> {
    assert_writable(ctx, id)?;
    locate_lxc(ctx, id, node).await
}

static OS_RELEASE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Z_]+)=(.*)$").expect("valid pattern"));
static IP_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+:\s+(\S+)\s+(inet6?)\s+(\S+)").expect("valid pattern"));
static APK_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)-([^-]+-r[0-9]+)$").expect("valid pattern"));
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("valid pattern"));
static EFFECTIVE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-z0-9]+) (.*)$").expect("valid pattern"));
static ENABLE_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(installed|init|manager)=(.*)$").expect("valid pattern"));
static NO_SUCH_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)No such file").expect("valid pattern"));

fn split_ws(text: &str) -> Vec<&str> {
    WHITESPACE.split(text).collect()
}

fn parse_os_release(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.split('\n') {
        if let Some(m) = OS_RELEASE_LINE.captures(js_trim(line)) {
            let value = &m[2];
            let value = value.strip_prefix(['"', '\'']).unwrap_or(value);
            let value = value.strip_suffix(['"', '\'']).unwrap_or(value);
            out.insert(m[1].to_lowercase(), Value::String(value.to_string()));
        }
    }
    out
}

fn parse_ips(text: &str) -> Vec<Value> {
    text.split('\n')
        .filter_map(|line| IP_LINE.captures(line))
        .map(|m| Value::Object(obj! { "interface" => &m[1], "family" => &m[2], "address" => &m[3] }))
        .collect()
}

fn parse_mounts(text: &str) -> Vec<Value> {
    text.split('\n')
        .map(|line| line.split(' ').collect::<Vec<_>>())
        .filter(|f| f.len() >= 4)
        .map(|f| Value::Object(obj! { "device" => f[0], "mountpoint" => f[1], "type" => f[2], "options" => f[3] }))
        .collect()
}

fn package_row(name: &str, version: Option<&str>, arch: Option<&str>) -> Map<String, Value> {
    obj! { "name" => name, "version" => version.filter(|v| !v.is_empty()), "arch" => arch.filter(|a| !a.is_empty()) }
}

fn parse_packages(manager: Option<&str>, text: &str) -> Vec<Map<String, Value>> {
    let mut rows = Vec::new();
    for line in text.split('\n') {
        if js_trim(line).is_empty() {
            continue;
        }
        match manager {
            Some("dpkg") => {
                let mut f = line.split('\t');
                let (name, version, status) = (f.next().unwrap_or(""), f.next(), f.next());
                if !name.is_empty() && status.is_none_or(|s| s.is_empty() || s.ends_with(" installed")) {
                    rows.push(package_row(name, version, None));
                }
            }
            Some("apk") => {
                let t = js_trim(line);
                rows.push(match APK_LINE.captures(t) {
                    Some(m) => obj! { "name" => &m[1], "version" => &m[2] },
                    None => obj! { "name" => t },
                });
            }
            Some("rpm") => {
                let mut f = line.split('\t');
                let (name, version, arch) = (f.next().unwrap_or(""), f.next(), f.next());
                if !name.is_empty() {
                    rows.push(package_row(name, version, arch));
                }
            }
            _ => {
                let f = split_ws(js_trim(line));
                let name = f[0];
                if !name.is_empty() {
                    rows.push(package_row(name, f.get(1).copied(), None));
                }
            }
        }
    }
    rows
}

fn no_manager(res: &ExecResult) -> Result<()> {
    if res.exit_code == Some(EXIT_NO_MANAGER) {
        let reason = js_trim(&res.stderr);
        return Err(PveError::new(kind::NOT_SUPPORTED, if reason.is_empty() { "No supported tool in this container." } else { reason })
            .hint("pve_lxc_exec can do it by hand, knowing what this container has."));
    }
    Ok(())
}

/// Parses ssh status output. The effective settings are lines of "name value".
fn parse_ssh_status(text: &str) -> Map<String, Value> {
    let sections = parse_sections(&format!("@@head\n{text}"));
    let (header, _) = parse_header(sections.get("head").map(String::as_str).unwrap_or(""));
    let mut effective = Map::new();
    let mut error: Option<String> = None;
    for line in sections.get("effective").map(String::as_str).unwrap_or("").split('\n') {
        let Some(m) = EFFECTIVE_LINE.captures(line) else {
            let t = js_trim(line);
            if !t.is_empty() {
                error = Some(match error {
                    Some(e) => format!("{e}\n{t}"),
                    None => t.to_string(),
                });
            }
            continue;
        };
        let value = Value::String(m[2].to_string());
        let key = m[1].to_string();
        // In place, as a JavaScript object keeps the position of a key it already has.
        match effective.get_mut(&key) {
            None => {
                effective.insert(key, value);
            }
            Some(Value::Array(list)) => list.push(value),
            Some(existing) => *existing = Value::Array(vec![existing.take(), value]),
        }
    }
    let ports: Vec<Value> = match effective.get("port") {
        None => Vec::new(),
        Some(Value::Array(list)) => list.iter().map(|v| num(js_number_str(v.as_str().unwrap_or("")).unwrap_or(f64::NAN))).collect(),
        Some(v) => vec![num(js_number_str(v.as_str().unwrap_or("")).unwrap_or(f64::NAN))],
    };
    let binary = header.get("binary").filter(|b| !b.is_empty());
    let running = header.get("running").map(String::as_str);
    let mut out = obj! { "installed" => binary.is_some(), "binary" => binary.cloned() };
    out.insert("running".into(), Value::Bool(matches!(running, Some("yes" | "socket"))));
    if running == Some("socket") {
        out.insert("socket_activated".into(), Value::Bool(true));
    }
    if let Some(init) = header.get("init") {
        out.insert("init".into(), Value::String(init.clone()));
    }
    if header.get("dropbear").is_some_and(|d| !d.is_empty()) {
        out.insert("dropbear_installed".into(), Value::Bool(true));
    }
    out.insert("ports".into(), Value::Array(ports));
    if !effective.is_empty() {
        out.insert("effective".into(), Value::Object(effective));
    }
    if let Some(e) = error {
        out.insert("sshd_error".into(), Value::String(e));
    }
    out
}

/// Builds what pve_lxc_exec runs inside. Values are quoted; the command itself is shell text, once.
fn exec_script(args: &Args) -> Result<(String, String)> {
    let command = args.str("command").unwrap_or_default();
    let cwd = args.str("cwd").filter(|s| !s.is_empty());
    let as_user = args.str("as_user").filter(|s| !s.is_empty());
    let env = args.object("env");
    let mut parts: Vec<String> = Vec::new();
    if let Some(cwd) = cwd {
        parts.push(sh!("cd -- {} || exit {}", cwd, EXIT_CD_FAILED)?);
    }
    for (name, value) in env.into_iter().flatten() {
        parts.push(sh!("{}={}; export {}", raw(name.as_str()), crate::js::js_string(value), raw(name.as_str()))?);
    }
    parts.push(sh!("exec sh -c {}", command)?);
    let inner = parts.join("\n");
    let script = match as_user {
        Some(user) => sh!("exec su -s /bin/sh {} -c {}", user, &inner)?,
        None => inner,
    };
    let context: Vec<String> = [
        cwd.map(|c| format!("cwd={c}")),
        as_user.map(|u| format!("as_user={u}")),
        env.map(|e| format!("env={}", e.keys().cloned().collect::<Vec<_>>().join(","))),
    ]
    .into_iter()
    .flatten()
    .collect();
    let context = context.join(" ");
    let display = if context.is_empty() { command.to_string() } else { format!("({context}) {command}") };
    Ok((script, display))
}

fn interpreter(name: &str) -> Vec<String> {
    let words: &[&str] = match name {
        "bash" => &["bash", "-s", "--"],
        "ash" => &["ash", "-s", "--"],
        "dash" => &["dash", "-s", "--"],
        "python3" => &["python3", "-"],
        "perl" => &["perl", "-"],
        _ => &["sh", "-s", "--"],
    };
    words.iter().map(|w| w.to_string()).collect()
}

fn ssh_configure_failure(res: &ExecResult) -> Result<()> {
    let reason = js_trim(&res.stderr);
    match res.exit_code {
        Some(EXIT_NOT_FOUND) => Err(PveError::new(kind::NOT_FOUND, if reason.is_empty() { "sshd is not installed in this container." } else { reason }).hint("pve_lxc_ssh_enable installs it.")),
        Some(EXIT_SSHD_REJECTED) => Err(PveError::new(kind::INVALID_INPUT, reason).hint("The old configuration is back in place. If sshd has no host keys yet, pve_lxc_ssh_enable creates them.")),
        Some(EXIT_SSHD_NOT_EFFECTIVE) => Err(PveError::new(kind::UPSTREAM_ERROR, reason).hint("The old configuration is back in place. Look at /etc/ssh/sshd_config and sshd_config.d in the container.")),
        Some(EXIT_RELOAD_FAILED) => Err(PveError::new(kind::UPSTREAM_ERROR, reason).hint("The old configuration is back in place.")),
        _ => Ok(()),
    }
}

fn lookup_failure(res: &ExecResult, vmid: i64) -> Result<()> {
    let reason = js_trim(&res.stderr);
    match res.exit_code {
        Some(EXIT_NOT_FOUND) => Err(PveError::new(kind::NOT_FOUND, if reason.is_empty() { format!("No such user in container {vmid}.") } else { reason.to_string() })),
        Some(EXIT_REFUSED_LINK) => Err(PveError::new(kind::INVALID_INPUT, reason).hint("A link there could point anywhere, and root follows it. Check this home directory by hand.")),
        _ => Ok(()),
    }
}

/// vmid and node of the arguments.
fn where_of(args: &Args) -> (i64, Option<&str>) {
    (args.i64("vmid").unwrap_or_default(), args.str("node"))
}

/// The first fields of most answers.
fn base(vmid: i64, loc: &GuestLocation) -> Map<String, Value> {
    obj! { "vmid" => vmid, "node" => &loc.node }
}

fn with_paging(mut out: Map<String, Value>, rows: Vec<Value>, args: &Args) -> Map<String, Value> {
    let (limit, offset) = paging_args(args);
    out.extend(page_rows(rows, limit, offset));
    out
}

fn timeout_or(args: &Args, default_seconds: u64) -> u64 {
    args.u64("timeout_seconds").unwrap_or(default_seconds) * 1000
}

/// Removes the temporary file on the node, whatever happened: the field to add when that failed.
async fn remove_temp(ctx: &ToolContext, target: &SshTarget, temp: &str) -> Map<String, Value> {
    let removed = match delete_file_script(temp, true) {
        Ok(script) => ctx.ssh.run(target, &ShellCommand::write(script), ExecOptions::default()).await,
        Err(e) => Err(e),
    };
    match removed {
        Ok(res) if res.exit_code == Some(0) => Map::new(),
        _ => obj! { "temp_file_left_on_node" => temp },
    }
}

async fn info(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &lxc_info_script(), RunExtra::default()).await?;
    assert_ok(&res, "Reading container information", Some(vmid))?;
    let s = parse_sections(&res.stdout);
    let get = |k: &str| s.get(k).map(String::as_str);
    let uptime = get("uptime").unwrap_or("");
    let seconds = js_number_str(split_ws(uptime)[0]).unwrap_or(f64::NAN);
    let ips = parse_ips(get("ips").unwrap_or(""));
    let mut out = base(vmid, &loc);
    out.insert("os".into(), Value::Object(parse_os_release(get("os").unwrap_or(""))));
    crate::js::put(&mut out, "kernel", get("kernel"));
    crate::js::put(&mut out, "hostname", get("hostname"));
    if seconds.is_finite() && !uptime.is_empty() {
        out.insert("uptime_seconds".into(), num(seconds));
    }
    let no_ips = ips.is_empty();
    out.insert("ips".into(), Value::Array(ips));
    if let Some(raw_ips) = get("ips").filter(|t| no_ips && !t.is_empty()) {
        out.insert("ips_raw".into(), Value::String(raw_ips.to_string()));
    }
    out.insert("mounts".into(), Value::Array(parse_mounts(get("mounts").unwrap_or(""))));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn processes(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &processes_script(), RunExtra::default()).await?;
    assert_ok(&res, "ps", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("output".into(), Value::String(res.stdout.clone()));
    if res.truncated {
        out.insert("truncated".into(), Value::Bool(true));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn ports(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &ports_script(), RunExtra::default()).await?;
    assert_ok(&res, "Listing ports", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("output".into(), Value::String(res.stdout.clone()));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn disk_usage(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &disk_usage_script(args.str("path"))?, RunExtra::exec(exec_options(&args, &ctx))).await?;
    assert_ok(&res, "df", Some(vmid))?;
    let mut parts = res.stdout.split("@@du\n");
    let (df, du) = (parts.next().unwrap_or(""), parts.next());
    let filesystems: Vec<Value> = df
        .split('\n')
        .skip(1)
        .map(|line| split_ws(js_trim(line)))
        .filter(|f| f.len() >= 6)
        .map(|f| Value::Object(obj! { "filesystem" => f[0], "size" => f[1], "used" => f[2], "available" => f[3], "use_percent" => f[4], "mountpoint" => f[5..].join(" ") }))
        .collect();
    let mut out = base(vmid, &loc);
    out.insert("filesystems".into(), Value::Array(filesystems));
    if let Some(du) = du.filter(|d| !d.is_empty()) {
        out.insert("directory".into(), Value::String(js_trim(du).to_string()));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn logs(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let opts = LogsOptions { lines: args.i64("lines").unwrap_or(200), unit: args.string("unit"), since: args.string("since") };
    let res = run_in(&ctx, &loc, Access::Read, &logs_script(&opts)?, RunExtra::default()).await?;
    assert_ran(&res, "Reading logs", Some(vmid))?;
    if res.exit_code == Some(EXIT_NOT_FOUND) {
        let reason = js_trim(&res.stderr);
        return Err(PveError::new(kind::NOT_FOUND, if reason.is_empty() { "No logs found in this container." } else { reason })
            .hint("Some services only log to their own files: pve_lxc_list_dir on /var/log shows what is there."));
    }
    assert_ok(&res, "Reading logs", Some(vmid))?;
    let (header, rest) = parse_header(&res.stdout);
    let mut out = base(vmid, &loc);
    crate::js::put(&mut out, "source", header.get("source").cloned());
    out.insert("output".into(), Value::String(rest));
    if res.truncated {
        out.insert("truncated".into(), Value::Bool(true));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn list_dir(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let path = args.str("path").unwrap_or_default();
    let res = run_in(&ctx, &loc, Access::Read, &list_dir_script(path)?, RunExtra::default()).await?;
    assert_ok(&res, &format!("Listing {path}"), Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("path".into(), Value::String(path.to_string()));
    let mut out = with_paging(out, parse_ls(&res.stdout), &args);
    if res.truncated {
        out.insert("truncated_output".into(), Value::Bool(true));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn read_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let read = ReadFileArgs { path: args.string("path").unwrap_or_default(), max_bytes: args.u64("max_bytes"), allow_partial: args.flag("allow_partial") };
    let wrap = move |s: &str| pct_exec(vmid, s);
    let file = read_remote_file(&ctx, &SshTarget::node(&loc.node), &wrap, &read, Some(vmid)).await?;
    let mut out = base(vmid, &loc);
    if let Value::Object(m) = file {
        out.extend(m);
    }
    Ok(Value::Object(out))
}

async fn service_status(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &service_status_script(args.str("unit"))?, RunExtra::default()).await?;
    assert_ok(&res, "Reading service status", Some(vmid))?;
    let (header, rest) = parse_header(&res.stdout);
    let mut out = base(vmid, &loc);
    out.extend(header_fields(&header));
    out.insert("output".into(), Value::String(js_trim(&rest).to_string()));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn list_packages(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &list_packages_script(), RunExtra::default()).await?;
    assert_ran(&res, "Listing packages", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Listing packages", Some(vmid))?;
    let (header, rest) = parse_header(&res.stdout);
    let manager = header.get("manager").map(String::as_str);
    let mut rows = parse_packages(manager, &rest);
    if let Some(filter) = args.str("filter").filter(|f| !f.is_empty()) {
        rows.retain(|r| r.get("name").and_then(Value::as_str).is_some_and(|n| n.contains(filter)));
    }
    let mut out = base(vmid, &loc);
    crate::js::put(&mut out, "manager", manager);
    let mut out = with_paging(out, rows.into_iter().map(Value::Object).collect(), &args);
    if res.truncated {
        out.insert("truncated_output".into(), Value::Bool(true));
    }
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn list_users(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, "cat /etc/passwd", RunExtra::default()).await?;
    assert_ok(&res, "Reading /etc/passwd", Some(vmid))?;
    let number = |s: &str| js_number_str(s).unwrap_or(f64::NAN);
    let mut rows: Vec<(f64, Value)> = res
        .stdout
        .split('\n')
        .map(|line| line.split(':').collect::<Vec<_>>())
        .filter(|f| f.len() >= 7)
        .map(|f| {
            let uid = number(f[2]);
            (uid, Value::Object(obj! { "name" => f[0], "uid" => num(uid), "gid" => num(number(f[3])), "comment" => f[4], "home" => f[5], "shell" => f[6] }))
        })
        .collect();
    if args.bool("include_system") == Some(false) {
        rows.retain(|(uid, _)| *uid == 0.0 || (*uid >= 1000.0 && *uid < 65_534.0));
    }
    Ok(Value::Object(with_paging(base(vmid, &loc), rows.into_iter().map(|(_, r)| r).collect(), &args)))
}

async fn exec(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let (script, display) = exec_script(&args)?;
    let mut extra = RunExtra::exec(exec_options(&args, &ctx));
    extra.display = Some(format!("pct exec {vmid} -- {display}"));
    extra.stdin = args.str("stdin").map(|s| s.as_bytes().to_vec());
    let res = run_in(&ctx, &loc, Access::Write, &script, extra).await?;
    assert_ran(&res, "The command", Some(vmid))?;
    Ok(present(&res, base(vmid, &loc)))
}

async fn run_script(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let words = interpreter(args.str("interpreter").unwrap_or("sh"));
    let script_args = args.strings("args").unwrap_or_default();
    let cmd = ShellCommand::write(sh!("pct exec {} -- {} {}", vmid, words, script_args)?).stdin(args.str("script").unwrap_or_default().as_bytes().to_vec());
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &cmd, exec_options(&args, &ctx)).await?;
    assert_ran(&res, "The script", Some(vmid))?;
    Ok(present(&res, base(vmid, &loc)))
}

async fn write_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let path = args.str("path").unwrap_or_default();
    let content = args.str("content").unwrap_or_default();
    let stdin: Vec<u8> = if args.str("encoding") == Some("base64") { decode_base64(content) } else { content.as_bytes().to_vec() };
    let script = write_file_script(path, &WriteFileOptions { mode: args.string("mode"), owner: args.string("owner"), backup: args.flag("backup"), create_parents: args.flag("create_parents") })?;
    let extra = RunExtra { stdin: Some(stdin), display: Some(format!("pct exec {vmid} -- write {path} (content on stdin)")), ..Default::default() };
    let res = run_in(&ctx, &loc, Access::Write, &script, extra).await?;
    let what = format!("Writing {path}");
    assert_ran(&res, &what, Some(vmid))?;
    if res.exit_code == Some(EXIT_NOT_FOUND) {
        return Err(PveError::new(kind::NOT_FOUND, js_trim(&res.stderr)).hint("create_parents creates the directories."));
    }
    assert_ok(&res, &what, Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("path".into(), Value::String(path.to_string()));
    if res.dry_run {
        return Ok(Value::Object(out));
    }
    let mut parts = res.stdout.split('\n');
    let bytes = parts.next().unwrap_or("");
    out.insert("bytes".into(), num(js_number_str(bytes).unwrap_or(f64::NAN)));
    crate::js::put(&mut out, "backup", parts.next().filter(|b| !b.is_empty()));
    Ok(Value::Object(out))
}

fn temp_name() -> String {
    format!("/tmp/pvemcp-{}", uuid::Uuid::new_v4())
}

async fn push_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let local_path = args.str("local_path").unwrap_or_default();
    let local = resolve_local_path(ctx.instance.local_dir.as_deref(), local_path, true)?;
    if !std::fs::metadata(&local).map(|m| m.is_file()).unwrap_or(false) {
        return Err(PveError::new(kind::LOCAL_PATH_REFUSED, format!("{local_path} is not a regular file.")));
    }
    let path = args.str("path").unwrap_or_default();
    let temp = temp_name();
    let target = SshTarget::node(&loc.node);
    let timeout_ms = args.u64("timeout_seconds").filter(|s| *s > 0).map(|s| s * 1000);
    let sftp = ctx.ssh.sftp(&target, Access::Write).await?;
    let result: Result<()> = async {
        let put = sftp.fast_put(&local, &temp, Some(0o600), timeout_ms).await;
        sftp.close();
        put?;
        let mut options: Vec<String> = Vec::new();
        if let Some(mode) = args.str("mode").filter(|s| !s.is_empty()) {
            options.push(format!("--perms {}", sh!("{}", mode)?));
        }
        if let Some(user) = args.str("user").filter(|s| !s.is_empty()) {
            options.push(format!("--user {}", sh!("{}", user)?));
        }
        if let Some(group) = args.str("group").filter(|s| !s.is_empty()) {
            options.push(format!("--group {}", sh!("{}", group)?));
        }
        let text = sh!("pct push {} {} {} {}", vmid, &temp, path, raw(options.join(" ")))?;
        let res = ctx.ssh.run(&target, &ShellCommand::write(text.trim_end()), ExecOptions { timeout_ms, max_bytes: None }).await?;
        assert_ok(&res, "pct push", Some(vmid))
    }
    .await;
    let cleanup = remove_temp(&ctx, &target, &temp).await;
    result?;
    let mut out = base(vmid, &loc);
    out.insert("path".into(), Value::String(path.to_string()));
    out.insert("bytes".into(), Value::from(local_size(&local)?));
    out.extend(cleanup);
    Ok(Value::Object(out))
}

async fn pull_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let local_path = args.str("local_path").unwrap_or_default();
    let local = resolve_local_path(ctx.instance.local_dir.as_deref(), local_path, false)?;
    assert_local_target(&local, args.flag("overwrite"), local_path)?;
    let target = SshTarget::node(&loc.node);
    let timeout_ms = args.u64("timeout_seconds").filter(|s| *s > 0).map(|s| s * 1000);
    let path = args.str("path").unwrap_or_default();
    let wrap = move |s: &str| pct_exec(vmid, s);
    let stat = stat_remote_file(&ctx, &target, &wrap, path, Some(vmid)).await?;
    let temp = temp_name();
    let ssh = &ctx.instance.ssh;
    // With sudo, pct writes as root, and SFTP has to be able to read it afterwards.
    let owner = if ssh.sudo && ssh.user != "root" { sh!(" --user {}", &ssh.user)? } else { String::new() };
    let result: Result<()> = async {
        let source = stat.as_ref().map(|s| s.real.as_str()).unwrap_or(path);
        let text = format!("{}{owner}", sh!("pct pull {} {} {} --perms 0600", vmid, source, &temp)?);
        let res = ctx.ssh.run(&target, &ShellCommand::write(text), ExecOptions { timeout_ms, max_bytes: None }).await?;
        assert_ok(&res, "pct pull", Some(vmid))?;
        if !res.dry_run {
            download_to(&ctx, &target, &temp, &local, timeout_ms).await?;
        } else {
            ctx.dry_run_log.lock().unwrap().push(json!({ "ssh": { "node": &loc.node, "sftp": "fastGet", "path": &temp, "access": "read" } }));
        }
        Ok(())
    }
    .await;
    let cleanup = remove_temp(&ctx, &target, &temp).await;
    result?;
    let mut out = base(vmid, &loc);
    out.insert("path".into(), Value::String(path.to_string()));
    out.insert("local_path".into(), Value::String(local.clone()));
    if !ctx.dry_run {
        out.insert("bytes".into(), Value::from(local_size(&local)?));
    }
    out.extend(cleanup);
    Ok(Value::Object(out))
}

async fn delete_file(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let path = args.str("path").unwrap_or_default();
    let res = run_in(&ctx, &loc, Access::Write, &delete_file_script(path, args.flag("missing_ok"))?, RunExtra::default()).await?;
    let what = format!("Deleting {path}");
    assert_ran(&res, &what, Some(vmid))?;
    if NO_SUCH_FILE.is_match(&res.stderr) && res.exit_code != Some(0) {
        return Err(PveError::new(kind::NOT_FOUND, format!("{path} does not exist in container {vmid}.")));
    }
    assert_ok(&res, &what, Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("path".into(), Value::String(path.to_string()));
    out.insert("deleted".into(), Value::Bool(!res.dry_run));
    Ok(Value::Object(out))
}

async fn service(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let (action, unit) = (args.str("action").unwrap_or_default(), args.str("unit").unwrap_or_default());
    let res = run_in(&ctx, &loc, Access::Write, &service_script(action, unit)?, RunExtra::default()).await?;
    let what = format!("{action} {unit}");
    assert_ran(&res, &what, Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, &what, Some(vmid))?;
    let mut extra = base(vmid, &loc);
    extra.extend(header_fields(&parse_header(&res.stdout).0));
    Ok(present(&res, extra))
}

/// The answer of the package tools: vmid, node, manager, and the packages when given.
fn package_answer(res: &ExecResult, vmid: i64, loc: &GuestLocation, packages: Option<Vec<String>>) -> Value {
    let mut extra = base(vmid, loc);
    crate::js::put(&mut extra, "manager", parse_header(&res.stdout).0.get("manager").cloned());
    crate::js::put(&mut extra, "packages", packages);
    present(res, extra)
}

async fn install_packages(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let packages = args.strings("packages").unwrap_or_default();
    let script = install_packages_script(&packages, args.bool("refresh").unwrap_or(true))?;
    let res = run_in(&ctx, &loc, Access::Write, &script, RunExtra::timeout(timeout_or(&args, 600))).await?;
    assert_ran(&res, "Installing packages", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Installing packages", Some(vmid))?;
    Ok(package_answer(&res, vmid, &loc, Some(packages)))
}

async fn remove_packages(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let packages = args.strings("packages").unwrap_or_default();
    let script = remove_packages_script(&packages, args.flag("purge"))?;
    let res = run_in(&ctx, &loc, Access::Write, &script, RunExtra::timeout(timeout_or(&args, 600))).await?;
    assert_ran(&res, "Removing packages", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Removing packages", Some(vmid))?;
    Ok(package_answer(&res, vmid, &loc, Some(packages)))
}

async fn update_packages(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Write, &update_packages_script(args.flag("full")), RunExtra::timeout(timeout_or(&args, 1800))).await?;
    assert_ran(&res, "Updating packages", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Updating packages", Some(vmid))?;
    Ok(package_answer(&res, vmid, &loc, None))
}

async fn create_user(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let name = args.str("name").unwrap_or_default();
    let opts = CreateUserOptions {
        uid: args.i64("uid"),
        shell: args.string("shell"),
        home: args.string("home"),
        comment: args.string("comment"),
        groups: args.strings("groups").unwrap_or_default(),
        system: args.flag("system"),
    };
    let res = run_in(&ctx, &loc, Access::Write, &create_user_script(name, &opts)?, RunExtra::default()).await?;
    let what = format!("Creating user {name}");
    assert_ran(&res, &what, Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, &what, Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("user".into(), Value::String(name.to_string()));
    out.insert("created".into(), Value::Bool(!res.dry_run));
    Ok(Value::Object(out))
}

async fn delete_user(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let name = args.str("name").unwrap_or_default();
    if name == "root" {
        return Err(PveError::new(kind::INVALID_INPUT, "This tool does not delete root."));
    }
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Write, &delete_user_script(name, args.flag("remove_home"))?, RunExtra::default()).await?;
    let what = format!("Deleting user {name}");
    assert_ran(&res, &what, Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, &what, Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("user".into(), Value::String(name.to_string()));
    out.insert("deleted".into(), Value::Bool(!res.dry_run));
    Ok(Value::Object(out))
}

async fn set_password(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let user = args.str("user").unwrap_or_default();
    let password = args.str("password").unwrap_or_default();
    // On stdin and marked sensitive: no digest of it in any log.
    let cmd = ShellCommand::write(sh!("pct exec {} -- chpasswd", vmid)?)
        .stdin(format!("{user}:{password}\n").into_bytes())
        .sensitive_stdin()
        .display(format!("pct exec {vmid} -- chpasswd (password of {user} on stdin)"));
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &cmd, ExecOptions::default()).await?;
    assert_ok(&res, &format!("Setting the password of {user}"), Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("user".into(), Value::String(user.to_string()));
    out.insert("changed".into(), Value::Bool(!res.dry_run));
    Ok(Value::Object(out))
}

async fn fsck(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let mut parts = vec![sh!("pct fsck {}", vmid)?];
    if let Some(device) = args.str("device").filter(|s| !s.is_empty()) {
        parts.push(sh!("--device {}", device)?);
    }
    if args.flag("force") {
        parts.push("--force 1".into());
    }
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &ShellCommand::write(parts.join(" ")), ExecOptions { timeout_ms: Some(timeout_or(&args, 1800)), max_bytes: None }).await?;
    assert_ok(&res, "pct fsck", Some(vmid))?;
    Ok(present(&res, base(vmid, &loc)))
}

async fn fstrim(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let text = format!("{}{}", sh!("pct fstrim {}", vmid)?, if args.flag("ignore_mountpoints") { " --ignore-mountpoints 1" } else { "" });
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &ShellCommand::write(text), ExecOptions { timeout_ms: Some(timeout_or(&args, 1800)), max_bytes: None }).await?;
    assert_ok(&res, "pct fstrim", Some(vmid))?;
    Ok(present(&res, base(vmid, &loc)))
}

async fn mount(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &ShellCommand::write(sh!("pct mount {}", vmid)?), ExecOptions::default()).await?;
    assert_ok(&res, "pct mount", Some(vmid))?;
    let mut extra = base(vmid, &loc);
    extra.insert("mounted_at".into(), Value::String(format!("/var/lib/lxc/{vmid}/rootfs")));
    extra.insert("next_step".into(), Value::String("pve_lxc_unmount".into()));
    Ok(present(&res, extra))
}

async fn unmount(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &ShellCommand::write(sh!("pct unmount {}", vmid)?), ExecOptions::default()).await?;
    assert_ok(&res, "pct unmount", Some(vmid))?;
    Ok(present(&res, base(vmid, &loc)))
}

async fn ssh_status(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Read, &ssh_status_script(), RunExtra::default()).await?;
    assert_ok(&res, "Reading the SSH status", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.extend(parse_ssh_status(&res.stdout));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn ssh_list_keys(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = locate_lxc(&ctx, vmid, node).await?;
    let user = args.str("user").unwrap_or("root");
    let res = run_in(&ctx, &loc, Access::Read, &list_keys_script(user)?, RunExtra::default()).await?;
    assert_ran(&res, "Reading authorized keys", Some(vmid))?;
    lookup_failure(&res, vmid)?;
    assert_ok(&res, "Reading authorized keys", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("user".into(), Value::String(user.to_string()));
    out.extend(parse_authorized_keys(&res.stdout).into_fields());
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn ssh_enable(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Write, &ssh_enable_script(), RunExtra::timeout(timeout_or(&args, 600))).await?;
    assert_ran(&res, "Enabling SSH", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Enabling SSH", Some(vmid))?;
    let mut header: Map<String, Value> = Map::new();
    for line in res.stdout.split('\n') {
        if let Some(m) = ENABLE_HEADER.captures(line) {
            header.insert(m[1].to_string(), Value::String(m[2].to_string()));
        }
    }
    let field = |k: &str| header.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    let mut out = base(vmid, &loc);
    out.insert("enabled".into(), Value::Bool(!res.dry_run));
    if let Some(installed) = field("installed") {
        out.insert("installed_now".into(), Value::Bool(installed == "yes"));
    }
    crate::js::put(&mut out, "init", field("init"));
    crate::js::put(&mut out, "manager", field("manager"));
    out.insert("next_step".into(), Value::String("pve_lxc_ssh_status".into()));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

async fn ssh_disable(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Write, &ssh_disable_script(), RunExtra::default()).await?;
    assert_ran(&res, "Disabling SSH", Some(vmid))?;
    no_manager(&res)?;
    assert_ok(&res, "Disabling SSH", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("disabled".into(), Value::Bool(!res.dry_run));
    out.extend(header_fields(&parse_header(&res.stdout).0));
    Ok(Value::Object(out))
}

async fn ssh_add_key(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let key = parse_public_key(args.str("public_key").unwrap_or_default())?;
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let user = args.str("user").unwrap_or("root");
    let res = run_in(&ctx, &loc, Access::Write, &add_key_script(user, &key.line, &key.blob)?, RunExtra::default()).await?;
    assert_ran(&res, "Adding the key", Some(vmid))?;
    lookup_failure(&res, vmid)?;
    assert_ok(&res, "Adding the key", Some(vmid))?;
    let mut out = base(vmid, &loc);
    out.insert("user".into(), Value::String(user.to_string()));
    out.insert("fingerprint".into(), Value::String(key.fingerprint.clone()));
    if !res.dry_run {
        out.insert("added".into(), Value::Bool(js_trim(&res.stdout).ends_with("added")));
    }
    Ok(Value::Object(out))
}

async fn ssh_remove_key(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    if args.get("public_key").is_none() == args.get("fingerprint").is_none() {
        return Err(PveError::new(kind::INVALID_INPUT, "Pass exactly one of public_key and fingerprint."));
    }
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let user = args.str("user").unwrap_or("root");
    let answer = |more: Map<String, Value>| {
        let mut out = base(vmid, &loc);
        out.insert("user".into(), Value::String(user.to_string()));
        out.extend(more);
        Ok(Value::Object(out))
    };
    let blob = match args.str("public_key").filter(|k| !k.is_empty()) {
        Some(public_key) => parse_public_key(public_key)?.blob,
        None => {
            let listed = run_in(&ctx, &loc, Access::Read, &list_keys_script(user)?, RunExtra::default()).await?;
            assert_ran(&listed, "Reading authorized keys", Some(vmid))?;
            lookup_failure(&listed, vmid)?;
            assert_ok(&listed, "Reading authorized keys", Some(vmid))?;
            if listed.dry_run {
                return answer(obj! { "note" => "The key would be looked up by its fingerprint first, so the removal itself cannot be shown." });
            }
            let wanted = args.str("fingerprint").unwrap_or_default().trim_end_matches('=');
            let keys = parse_authorized_keys(&listed.stdout).keys;
            match keys.iter().find(|k| k.get("fingerprint").and_then(Value::as_str) == Some(wanted)) {
                None => return answer(obj! { "removed" => 0 }),
                Some(found) => found.get("blob").and_then(Value::as_str).unwrap_or_default().to_string(),
            }
        }
    };
    let res = run_in(&ctx, &loc, Access::Write, &remove_key_script(user, &blob)?, RunExtra::default()).await?;
    assert_ran(&res, "Removing the key", Some(vmid))?;
    lookup_failure(&res, vmid)?;
    assert_ok(&res, "Removing the key", Some(vmid))?;
    if res.dry_run {
        return answer(Map::new());
    }
    let (header, _) = parse_header(&res.stdout);
    let removed = js_number_str(header.get("removed").map(String::as_str).unwrap_or("0")).unwrap_or(f64::NAN);
    answer(obj! { "removed" => num(removed) })
}

async fn ssh_configure(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let settings = SshdSettings {
        permit_root_login: args.string("permit_root_login"),
        password_authentication: args.bool("password_authentication"),
        pubkey_authentication: args.bool("pubkey_authentication"),
        port: args.i64("port"),
    };
    if settings.is_empty() {
        return Err(PveError::new(kind::INVALID_INPUT, "Pass at least one setting to change."));
    }
    let (vmid, node) = where_of(&args);
    let loc = for_write(&ctx, vmid, node).await?;
    let res = run_in(&ctx, &loc, Access::Write, &ssh_configure_script(&settings)?, RunExtra::default()).await?;
    assert_ran(&res, "Configuring SSH", Some(vmid))?;
    ssh_configure_failure(&res)?;
    assert_ok(&res, "Configuring SSH", Some(vmid))?;
    let mut out = base(vmid, &loc);
    if res.dry_run {
        return Ok(Value::Object(out));
    }
    let (header, rest) = parse_header(&res.stdout);
    crate::js::put(&mut out, "layout", header.get("layout").cloned());
    out.insert("reloaded".into(), Value::Bool(header.get("reloaded").map(String::as_str) == Some("yes")));
    out.insert("effective".into(), Value::Array(js_trim(&rest).split('\n').map(|l| Value::String(l.to_string())).collect()));
    out.insert("untrusted".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

fn vmid_of(args: &Args) -> i64 {
    args.i64("vmid").unwrap_or_default()
}

fn s<'a>(args: &'a Args, key: &str) -> &'a str {
    args.str(key).unwrap_or_default()
}

/// SSH tools for containers, all through pct on the node.
pub fn ssh_lxc_tools() -> Vec<ToolDef> {
    let paging = || shape!["page_limit" => page_limit(), "page_offset" => page_offset()];
    let since = || z::string().regex(r"^(?:-\d+[a-z]+|[0-9A-Za-z][0-9A-Za-z :.+-]*)$", "Expected a time such as \"2024-01-31 12:00\", yesterday or -1h").max(64);
    let tool = |name: &str, title: &str, gate: Gate, description: String| ToolDef::new(name, title, "ssh", gate, description).also(&["lxc"]);
    let read = |name: &str, title: &str, description: &str| tool(name, title, Gate::SshRead, description.to_string()).idempotent();
    let write = |name: &str, title: &str, description: &str| tool(name, title, Gate::SshWrite, description.to_string());
    vec![
        read("pve_lxc_info", "Container system information", "From inside a container: os-release, kernel, uptime, IP addresses and mounts.").input(guest()).handler(info),
        read("pve_lxc_processes", "Container processes", "The processes running inside a container, from ps.").input(guest()).handler(processes),
        read("pve_lxc_ports", "Container listening ports", "What listens inside a container, from ss or netstat.").input(guest()).handler(ports),
        read("pve_lxc_disk_usage", "Container disk usage", "df inside a container, and optionally the total size of one directory.")
            .input(guest_and(shape!["path" => remote_path().optional().describe("Also give the total size of this directory."), "timeout_seconds" => timeout_seconds()]))
            .handler(disk_usage),
        read("pve_lxc_logs", "Container logs", "Recent logs of a container: from the journal where there is one, otherwise from /var/log.")
            .input(guest_and(shape![
                "unit" => unit_name().optional().describe("Only this service."),
                "lines" => z::int().min(1).max(10_000).optional().describe("Last lines to show. Default 200."),
                "since" => since().optional().describe("Only honoured with a journal."),
            ]))
            .handler(logs),
        read("pve_lxc_list_dir", "List a directory in a container", "ls -la inside a container, as rows.")
            .input(guest_and([shape!["path" => remote_path()], paging()].concat()))
            .handler(list_dir),
        read(
            "pve_lxc_read_file",
            "Read a file in a container",
            "Reads a text file inside a container, up to a size cap. Refuses well-known secrets such as /etc/shadow and /root/.ssh/id_*, also through a link, unless PROXMOX_ALLOW_SENSITIVE is on.",
        )
        .input(guest_and(shape![
            "path" => remote_path(),
            "max_bytes" => z::int().min(1).optional().describe("Largest file to return. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES."),
            "allow_partial" => z::boolean().optional().describe("Return the start of a file over the limit, instead of an error."),
        ]))
        .handler(read_file),
        read("pve_lxc_service_status", "Service status in a container", "One service, or all of them, under systemd, OpenRC or SysV init, whichever the container has.")
            .input(guest_and(shape!["unit" => unit_name().optional().describe("A service. Without it, all of them are listed.")]))
            .handler(service_status),
        read("pve_lxc_list_packages", "Packages in a container", "Installed packages, through dpkg, apk, rpm or pacman, whichever the container has.")
            .input(guest_and([shape!["filter" => z::string().max(128).optional().describe("Only packages whose name holds this.")], paging()].concat()))
            .handler(list_packages),
        read("pve_lxc_list_users", "Users in a container", "The accounts in /etc/passwd of a container. No password data: that lives in /etc/shadow, which is not read.")
            .input(guest_and([shape!["include_system" => z::boolean().optional().describe("Also list uid 1-999. Default true.")], paging()].concat()))
            .handler(list_users),
        tool(
            "pve_lxc_exec",
            "Run a command in a container",
            Gate::SshWrite,
            format!("Runs any shell command inside a container, through pct exec. {ROOT_IN_CT} A non-zero exit code is reported, not an error. A stopped container gives guest_not_running. Tell the user what you run."),
        )
        .destructive()
        .open_world()
        .input(guest_and(shape![
            "command" => z::string().min(1).describe("Shell text, run by sh in the container: Alpine and others have no bash."),
            "stdin" => z::string().optional().describe("Given to the command as its input. Never logged."),
            "cwd" => remote_path().optional().describe("Run in this directory."),
            "env" => z::map_of(z::string(), Some((ENV_NAME, "Expected an environment variable name")))
                .optional()
                .describe("Environment variables to set. The values are not logged, but they do appear on the command line of the node while it runs."),
            "as_user" => user_name().optional().describe("Run as this user in the container, through su."),
            "timeout_seconds" => timeout_seconds(),
            "max_output_bytes" => max_output_bytes(),
        ]))
        .confirmation(|args| {
            let who = args.str("as_user").filter(|u| !u.is_empty()).map(|u| format!(" as {u}")).unwrap_or_else(|| " as root".into());
            format!("Run this in container {}{who}?\n{}", vmid_of(args), s(args, "command"))
        })
        .handler(exec),
        tool(
            "pve_lxc_run_script",
            "Run a script in a container",
            Gate::SshWrite,
            format!("Runs a whole script inside a container, given to the interpreter on stdin, so that it needs no quoting and leaves no file. Its own stdin is therefore used up. {ROOT_IN_CT} A non-zero exit code is reported, not an error."),
        )
        .destructive()
        .open_world()
        .input(guest_and(shape![
            "script" => z::string().min(1).describe("The script. Never logged."),
            "interpreter" => z::enumeration(&["sh", "bash", "ash", "dash", "python3", "perl"]).optional().describe("Must exist in the container. Default sh."),
            "args" => z::array(z::string()).optional().describe("Arguments for the script."),
            "timeout_seconds" => timeout_seconds(),
            "max_output_bytes" => max_output_bytes(),
        ]))
        .confirmation(|args| {
            let script = s(args, "script");
            format!("Run a {}-character {} script as root in container {}?\n{}", js_len(script), args.str("interpreter").unwrap_or("sh"), vmid_of(args), js_slice_start(script, 2000))
        })
        .handler(run_script),
        write("pve_lxc_write_file", "Write a file in a container", "Writes a file inside a container, whole or not at all, keeping the mode and owner of an existing file unless told otherwise.")
            .destructive()
            .input(guest_and(shape![
                "path" => remote_path(),
                "content" => z::string().describe("The new content. Never logged."),
                "encoding" => z::enumeration(&["utf8", "base64"]).optional().describe("How content is written. Default utf8."),
                "mode" => file_mode().optional().describe("Such as 0644."),
                "owner" => file_owner().optional().describe("user or user:group."),
                "backup" => z::boolean().optional().describe("Keep the old file as path.bak.TIMESTAMP."),
                "create_parents" => z::boolean().optional().describe("Create missing directories."),
            ]))
            .confirmation(|args| format!("Write {} characters to {} in container {}?", js_len(s(args, "content")), s(args, "path"), vmid_of(args)))
            .handler(write_file),
        write(
            "pve_lxc_push_file",
            "Copy a local file into a container",
            "Copies a file from this server, under PROXMOX_LOCAL_DIR only, into a running container: SFTP to a temporary file on the node (mode 0600), pct push, and the temporary file is always removed.",
        )
        .destructive()
        .input(guest_and(shape![
            "local_path" => z::string().min(1).describe("Relative to PROXMOX_LOCAL_DIR, or absolute under it."),
            "path" => remote_path().describe("Where it goes in the container. An existing file is replaced."),
            "mode" => file_mode().optional().describe("Such as 0644."),
            "user" => user_name().optional().describe("Owner in the container."),
            "group" => user_name().optional().describe("Group in the container."),
            "timeout_seconds" => timeout_seconds(),
        ]))
        .confirmation(|args| format!("Copy {} to {} in container {}, replacing any file there?", s(args, "local_path"), s(args, "path"), vmid_of(args)))
        .handler(push_file),
        write(
            "pve_lxc_pull_file",
            "Copy a file out of a container",
            "Copies a file from a running container to this server, under PROXMOX_LOCAL_DIR only: pct pull to a temporary file on the node (mode 0600), SFTP, and the temporary file is always removed. Refuses well-known secrets, as pve_lxc_read_file does.",
        )
        .input(guest_and(shape![
            "path" => remote_path().describe("The file in the container."),
            "local_path" => z::string().min(1).describe("Relative to PROXMOX_LOCAL_DIR, or absolute under it. Its directory must exist."),
            "overwrite" => z::boolean().optional().describe("Replace a local file that exists. Default false."),
            "timeout_seconds" => timeout_seconds(),
        ]))
        .handler(pull_file),
        write("pve_lxc_delete_file", "Delete a file in a container", "Deletes one file inside a container. Not directories.")
            .destructive()
            .input(guest_and(shape!["path" => remote_path(), "missing_ok" => z::boolean().optional().describe("A file already gone is not an error.")]))
            .confirmation(|args| format!("Delete {} in container {}?", s(args, "path"), vmid_of(args)))
            .handler(delete_file),
        write("pve_lxc_service", "Control a service in a container", "Start, stop, restart, reload, enable or disable a service, under systemd, OpenRC or SysV init, whichever the container has.")
            .destructive_when(|args| !matches!(args.str("action"), Some("start" | "enable")))
            .input(guest_and(shape![
                "unit" => unit_name().describe("The service."),
                "action" => z::enumeration(&["start", "stop", "restart", "reload", "enable", "disable"]).describe("What to do with it."),
            ]))
            .confirmation(|args| format!("{} the service {} in container {}?", s(args, "action"), s(args, "unit"), vmid_of(args)))
            .handler(service),
        write(
            "pve_lxc_install_packages",
            "Install packages in a container",
            "Installs packages with apt, apk, dnf, yum or pacman, whichever the container has. Non-interactive. On Arch, refresh is a full upgrade, since partial upgrades are not supported there.",
        )
        .idempotent()
        .open_world()
        .input(guest_and(shape![
            "packages" => z::array(package_name()).min(1).max(200).describe("Package names. A version where the manager allows it: curl=8.5.0-1."),
            "refresh" => z::boolean().optional().describe("Refresh the package lists first. Default true."),
            "timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 600."),
        ]))
        .handler(install_packages),
        write("pve_lxc_remove_packages", "Remove packages from a container", "Removes packages with apt, apk, dnf, yum or pacman, whichever the container has.")
            .destructive()
            .input(guest_and(shape![
                "packages" => z::array(package_name()).min(1).max(200).describe("Package names."),
                "purge" => z::boolean().optional().describe("Also remove configuration, where the manager can: apt purge, pacman -Rns."),
                "timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 600."),
            ]))
            .confirmation(|args| format!("Remove these packages from container {}: {}?", vmid_of(args), args.strings("packages").unwrap_or_default().join(", ")))
            .handler(remove_packages),
        write(
            "pve_lxc_update_packages",
            "Update packages in a container",
            "Refreshes the package lists and upgrades everything, with apt, apk, dnf, yum or pacman, whichever the container has. Non-interactive: existing configuration files are kept.",
        )
        .open_world()
        .input(guest_and(shape![
            "full" => z::boolean().optional().describe("On apt: dist-upgrade, which may add and remove packages. Default false."),
            "timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 1800."),
        ]))
        .handler(update_packages),
        write(
            "pve_lxc_create_user",
            "Create a user in a container",
            "Creates a user with useradd or, on Alpine, the adduser of BusyBox. pve_lxc_set_password and pve_lxc_ssh_add_key give it a way in.",
        )
        .input(guest_and(shape![
            "name" => user_name().describe("The user to create."),
            "uid" => z::int().min(0).max(4_294_967_294u32).optional().describe("User id. Default: decided by the container."),
            "shell" => remote_path().optional().describe("Such as /bin/sh."),
            "home" => remote_path().optional().describe("Home directory. Default: decided by the container."),
            "comment" => z::string().regex(r"^[^:\r\n\0]*$", "No colons or line breaks").max(128).optional().describe("Full name or note: the GECOS field."),
            "groups" => z::array(user_name()).max(32).optional().describe("Extra groups, which must exist."),
            "system" => z::boolean().optional().describe("A system account."),
        ]))
        .handler(create_user),
        write("pve_lxc_delete_user", "Delete a user in a container", "Deletes a user with userdel or, on Alpine, the deluser of BusyBox. Refuses root.")
            .destructive()
            .input(guest_and(shape!["name" => user_name().describe("The user to delete."), "remove_home" => z::boolean().optional().describe("Also delete the home directory.")]))
            .confirmation(|args| format!("Delete user {}{} in container {}?", s(args, "name"), if args.flag("remove_home") { " and its home directory" } else { "" }, vmid_of(args)))
            .handler(delete_user),
        write(
            "pve_lxc_set_password",
            "Set a password in a container",
            "Sets the password of a user in a container, through chpasswd on stdin: never on a command line, and no digest of it in the logs.",
        )
        .destructive()
        .input(guest_and(shape![
            "user" => user_name().describe("The user whose password changes."),
            "password" => z::string().min(1).max(4096).regex(r"^[^\r\n\0]*$", "No line breaks").describe("The new password. Never logged."),
        ]))
        .confirmation(|args| format!("Change the password of {} in container {}?", s(args, "user"), vmid_of(args)))
        .handler(set_password),
        write("pve_lxc_fsck", "Check a container filesystem", "pct fsck on a stopped container: checks, and with force repairs, the root disk or a mount point. It refuses a running container.")
            .destructive()
            .input(guest_and(shape![
                "device" => z::string().regex(r"^(?:rootfs|mp\d+)$", "Expected rootfs or mp0, mp1...").optional().describe("rootfs, mp0... Default rootfs."),
                "force" => z::boolean().optional().describe("Check even if the filesystem looks clean."),
                "timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 1800."),
            ]))
            .confirmation(|args| format!("Run fsck on {} of container {}?", args.str("device").unwrap_or("rootfs"), vmid_of(args)))
            .handler(fsck),
        write("pve_lxc_fstrim", "Trim a container filesystem", "pct fstrim on a running container: gives unused blocks back to thin storage.")
            .input(guest_and(shape![
                "ignore_mountpoints" => z::boolean().optional().describe("Only the root disk."),
                "timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 1800."),
            ]))
            .handler(fstrim),
        write(
            "pve_lxc_mount",
            "Mount a container on its node",
            "pct mount: mounts the filesystem of a stopped container under /var/lib/lxc/VMID/rootfs on the node, for offline repairs, and locks the container. pve_lxc_unmount undoes it, and the container cannot start until then.",
        )
        .input(guest())
        .handler(mount),
        write("pve_lxc_unmount", "Unmount a container from its node", "pct unmount: undoes pve_lxc_mount and removes its lock.").input(guest()).handler(unmount),
        read("pve_lxc_ssh_status", "SSH server state in a container", "Whether sshd is installed and running in a container, on which ports, and its effective settings from sshd -T.")
            .input(guest())
            .handler(ssh_status),
        read("pve_lxc_ssh_list_keys", "Authorized SSH keys in a container", "The public keys in authorized_keys of a user in a container, with their fingerprints.")
            .input(guest_and(shape!["user" => user_name().optional().describe("Default root.")]))
            .handler(ssh_list_keys),
        write(
            "pve_lxc_ssh_enable",
            "Enable the SSH server in a container",
            "Installs openssh-server if it is missing, for the distribution of the container, then enables and starts it. Safe to repeat. By itself this opens no way in: add a key with pve_lxc_ssh_add_key.",
        )
        .idempotent()
        .open_world()
        .input(guest_and(shape!["timeout_seconds" => timeout_seconds().describe("Stop after this long. Default 600.")]))
        .handler(ssh_enable),
        write("pve_lxc_ssh_disable", "Disable the SSH server in a container", "Stops sshd in a container and keeps it from starting at boot. Does not uninstall it. pct access is not affected.")
            .destructive()
            .input(guest())
            .confirmation(|args| format!("Stop and disable the SSH server in container {}? Anyone logged in over SSH loses the way in.", vmid_of(args)))
            .handler(ssh_disable),
        write(
            "pve_lxc_ssh_add_key",
            "Authorize an SSH key in a container",
            "Adds a public key to authorized_keys of a user in a container, with the right modes (700 and 600) and owner. Adding a key already there changes nothing. Refuses a link at ~/.ssh or authorized_keys.",
        )
        .idempotent()
        .input(guest_and(shape![
            "public_key" => z::string().min(1).max(16_384).describe("One line: ssh-ed25519 AAAA... comment. Never a private key."),
            "user" => user_name().optional().describe("Default root."),
        ]))
        .handler(ssh_add_key),
        write("pve_lxc_ssh_remove_key", "Remove an SSH key in a container", "Removes a key from authorized_keys of a user in a container, given as the public key or its fingerprint.")
            .destructive()
            .input(guest_and(shape![
                "public_key" => z::string().min(1).max(16_384).optional().describe("The key to remove."),
                "fingerprint" => z::string().regex(r"^SHA256:[A-Za-z0-9+/]+=*$", "Expected SHA256:...").optional().describe("Or its fingerprint, as pve_lxc_ssh_list_keys shows it."),
                "user" => user_name().optional().describe("Default root."),
            ]))
            .confirmation(|args| {
                format!("Remove the key {} of {} in container {}?", args.str("fingerprint").unwrap_or("(given as a public key)"), args.str("user").unwrap_or("root"), vmid_of(args))
            })
            .handler(ssh_remove_key),
        write(
            "pve_lxc_ssh_configure",
            "Configure the SSH server in a container",
            "Sets PermitRootLogin, PasswordAuthentication, PubkeyAuthentication and Port, in a drop-in or at the top of sshd_config. Applied only if sshd -t accepts it and sshd -T shows the values in force, then sshd is reloaded. On any failure the old configuration is put back.",
        )
        .destructive()
        .input(guest_and(shape![
            "permit_root_login" => z::enumeration(&["yes", "no", "prohibit-password", "forced-commands-only"]).optional().describe("PermitRootLogin."),
            "password_authentication" => z::boolean().optional().describe("PasswordAuthentication."),
            "pubkey_authentication" => z::boolean().optional().describe("PubkeyAuthentication."),
            "port" => z::int().min(1).max(65_535).optional().describe("Port."),
        ]))
        .confirmation(|args| format!("Change the SSH server settings of container {}? This can lock out whoever logs in over SSH.", vmid_of(args)))
        .handler(ssh_configure),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&ssh_lxc_tools());
    }

    fn args(v: Value) -> Args {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn ssh_lxc_exec_script() {
        let (script, display) = exec_script(&args(json!({ "command": "echo \"$X\"", "cwd": "/srv", "env": { "X": "it's", "Y": "2" }, "as_user": "alice" }))).unwrap();
        let inner = "cd -- '/srv' || exit '125'\nX='it'\\''s'; export X\nY='2'; export Y\nexec sh -c 'echo \"$X\"'";
        assert_eq!(script, format!("exec su -s /bin/sh 'alice' -c {}", crate::ssh::sh_quote(inner).unwrap()));
        assert_eq!(display, "(cwd=/srv as_user=alice env=X,Y) echo \"$X\"");
        let (plain, shown) = exec_script(&args(json!({ "command": "id" }))).unwrap();
        assert_eq!((plain.as_str(), shown.as_str()), ("exec sh -c 'id'", "id"));
    }

    #[test]
    fn ssh_lxc_run_script_command() {
        let none: Vec<String> = Vec::new();
        assert_eq!(sh!("pct exec {} -- {} {}", 101, interpreter("sh"), none).unwrap(), "pct exec '101' -- 'sh' '-s' '--' ");
    }

    #[test]
    fn ssh_lxc_parsers() {
        let os = parse_os_release("NAME=\"Debian GNU/Linux\"\nVERSION_ID='12'\nbad line\n");
        assert_eq!(Value::Object(os), json!({ "name": "Debian GNU/Linux", "version_id": "12" }));
        assert_eq!(Value::Array(parse_ips("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet6 fe80::1/64 scope link")).as_array().unwrap().len(), 2);
        let dpkg = parse_packages(Some("dpkg"), "curl\t8.5\tinstall ok installed\ngone\t1\tdeinstall ok config-files\n");
        assert_eq!(dpkg.len(), 1);
        let apk = parse_packages(Some("apk"), "musl-1.2.4-r2\nodd\n");
        assert_eq!(Value::Object(apk[0].clone()), json!({ "name": "musl", "version": "1.2.4-r2" }));
        assert_eq!(Value::Object(apk[1].clone()), json!({ "name": "odd" }));
        let status = parse_ssh_status("binary=/usr/sbin/sshd\ninit=systemd\nrunning=socket\n@@effective\nport 22\nport 2222\npermitrootlogin no\nWarning: something\n");
        assert_eq!(
            Value::Object(status),
            json!({ "installed": true, "binary": "/usr/sbin/sshd", "running": true, "socket_activated": true, "init": "systemd", "ports": [22, 2222], "effective": { "port": ["22", "2222"], "permitrootlogin": "no" }, "sshd_error": "Warning: something" })
        );
        let empty = parse_ssh_status("binary=\ninit=none\nrunning=no\n");
        assert_eq!(Value::Object(empty), json!({ "installed": false, "running": false, "init": "none", "ports": [] }));
    }
}
