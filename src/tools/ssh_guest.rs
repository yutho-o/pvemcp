//! Direct SSH to guests.

use super::ssh_common::{assert_ran, assert_writable, exec_options, max_output_bytes, present, remote_path, timeout_seconds, user_name};
use super::{Args, ArgsExt, ToolContext, ToolDef, vmid};
use crate::errors::{PveError, Result, kind};
use crate::js::js_string;
use crate::obj;
use crate::proxmox::nodes::GuestLocation;
use crate::proxmox::policy::Gate;
use crate::proxmox::{Api, RequestOptions};
use crate::schema::{Shape, z};
use crate::shape;
use crate::ssh::known_hosts::parse_public_key_lines;
use crate::ssh::quote::raw;
use crate::ssh::scripts::{EXIT_CD_FAILED, pct_exec};
use crate::ssh::{ExecOptions, GuestEndpoint, ShellCommand, SshTarget};
use serde_json::Value;
use std::sync::Arc;

fn usable_address(address: &str) -> bool {
    let lower = address.to_lowercase();
    !lower.is_empty() && !lower.starts_with("fe80") && lower != "::1"
}

struct Candidate {
    name: String,
    address: String,
}

fn pick_address(candidates: &[Candidate]) -> Option<String> {
    let usable: Vec<&Candidate> = candidates.iter().filter(|c| c.name != "lo" && usable_address(&c.address)).collect();
    usable.iter().find(|c| !c.address.contains(':')).or(usable.first()).map(|c| c.address.clone())
}

/// String(row.name ?? '').
fn name_of(row: &Value) -> String {
    match row.get("name") {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

/// Addresses of a guest, as the node and the guest agent report them.
async fn find_address(ctx: &ToolContext, loc: &GuestLocation) -> Result<String> {
    let mut candidates = Vec::new();
    let hint = "Pass host, or use via_node with a guest the node can reach.";
    if loc.kind == "lxc" {
        let rows = ctx.api.get(&format!("/nodes/{}/lxc/{}/interfaces", loc.node, loc.vmid), RequestOptions::default()).await?;
        for row in rows.as_array().map(Vec::as_slice).unwrap_or_default() {
            for key in ["inet", "inet6"] {
                if let Some(value) = row.get(key).and_then(Value::as_str) {
                    candidates.push(Candidate { name: name_of(row), address: value.split('/').next().unwrap_or_default().to_string() });
                }
            }
        }
    } else {
        let answer = ctx
            .api
            .get(&format!("/nodes/{}/qemu/{}/agent/network-get-interfaces", loc.node, loc.vmid), RequestOptions::default())
            .await
            .map_err(|err| PveError::new(kind::INVALID_INPUT, format!("The address of VM {} is unknown: its guest agent did not answer ({}).", loc.vmid, err.message)).hint(hint))?;
        let rows = answer.get("result").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        for row in rows {
            for ip in row.get("ip-addresses").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
                if let Some(address) = ip.get("ip-address").and_then(Value::as_str) {
                    candidates.push(Candidate { name: name_of(row), address: address.to_string() });
                }
            }
        }
    }
    pick_address(&candidates).ok_or_else(|| PveError::new(kind::INVALID_INPUT, format!("No usable address reported for guest {}.", loc.vmid)).hint(hint))
}

/// For a container the keys are read through pct, which is already authenticated, so host key
/// checking stays on with nothing to configure. A VM offers no such path: known_hosts or a
/// fingerprint on the call, else it is refused by the transport.
async fn container_host_keys(ctx: &ToolContext, loc: &GuestLocation) -> Result<Option<Vec<String>>> {
    let res = ctx.ssh.run(&SshTarget::node(&loc.node), &ShellCommand::read(pct_exec(loc.vmid, "cat /etc/ssh/ssh_host_*_key.pub")?), ExecOptions::default()).await?;
    if res.dry_run {
        return Ok(None);
    }
    assert_ran(&res, "Reading the host keys", Some(loc.vmid))?;
    let keys: Vec<String> = res.stdout.split('\n').filter(|line| !parse_public_key_lines(line).is_empty()).map(str::to_string).collect();
    if keys.is_empty() {
        return Err(PveError::new(kind::HOST_KEY_UNKNOWN, format!("Container {} has no SSH host keys to check against.", loc.vmid))
            .hint("pve_lxc_ssh_enable installs and starts the SSH server. pve_lxc_exec needs none of this."));
    }
    Ok(Some(keys))
}

async fn guest_target(ctx: &ToolContext, args: &Args) -> Result<(SshTarget, GuestLocation, GuestEndpoint)> {
    let vmid = args.i64("vmid").unwrap_or_default();
    let loc = ctx.nodes.resolve_guest(vmid).await?;
    let host = match args.string("host") {
        Some(h) => h,
        None => find_address(ctx, &loc).await?,
    };
    let host_keys = if loc.kind == "lxc" { container_host_keys(ctx, &loc).await? } else { None };
    let guest = GuestEndpoint {
        vmid,
        host,
        port: args.u64("port").map(|p| p as u16).unwrap_or(22),
        user: args.string("user").or_else(|| ctx.instance.ssh.guest_user.clone()).unwrap_or_else(|| "root".into()),
        via_node: if args.flag("via_node") { Some(loc.node.clone()) } else { None },
        host_keys,
        fingerprint: args.string("fingerprint").filter(|f| !f.is_empty()),
    };
    Ok((SshTarget { node: loc.node.clone(), guest: Some(guest.clone()) }, loc, guest))
}

fn connection() -> Shape {
    shape![
        "vmid" => vmid(),
        "user" => user_name().optional().describe("Log in as this user. Default: PROXMOX_GUEST_SSH_USER, or root."),
        "host" => z::string().regex(r"^[a-zA-Z0-9][a-zA-Z0-9.:_-]*$", "Expected an address").max(255).optional().describe("Address to connect to. Default: what the node or the guest agent reports."),
        "port" => z::int().min(1).max(65_535).optional().describe("Default 22."),
        "via_node" => z::boolean().optional().describe("Go through the node of the guest, for a guest this server cannot reach directly."),
        "fingerprint" => z::string()
            .regex(r"^SHA256:[A-Za-z0-9+/]+=*$", "Expected SHA256:...")
            .optional()
            .describe("The host key to expect, for a VM that is not in known_hosts. Get it from the console of the VM, not from the connection itself."),
    ]
}

async fn guest_test(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let (target, _, guest) = guest_target(&ctx, &args).await?;
    let res = ctx.ssh.run(&target, &ShellCommand::read("id -un; uname -srm"), ExecOptions::default()).await?;
    assert_ran(&res, "The SSH test", None)?;
    let mut parts = res.stdout.split('\n');
    let (user, system) = (parts.next(), parts.next());
    Ok(Value::Object(obj! {
        "vmid" => args.i64("vmid"),
        "host" => &guest.host,
        "port" => guest.port as u64,
        "connected" => true,
        "user" => user,
        "system" => system,
        "host_key" => res.host_key.as_ref().map(|k| k.to_json()),
        "duration_ms" => res.duration_ms,
        "untrusted" => true,
    }))
}

async fn guest_exec(args: Args, ctx: Arc<ToolContext>) -> Result<Value> {
    let vmid = args.i64("vmid").unwrap_or_default();
    assert_writable(&ctx, vmid)?;
    let (target, _, guest) = guest_target(&ctx, &args).await?;
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
    Ok(present(&res, obj! { "vmid" => vmid, "host" => &guest.host }))
}

/// Direct SSH to guests.
pub fn ssh_guest_tools() -> Vec<ToolDef> {
    let mut exec_input = connection();
    exec_input.extend(shape![
        "command" => z::string().min(1).describe("Shell text."),
        "stdin" => z::string().optional().describe("Given to the command as its input. Never logged."),
        "cwd" => remote_path().optional().describe("Run in this directory."),
        "timeout_seconds" => timeout_seconds(),
        "max_output_bytes" => max_output_bytes(),
    ]);
    vec![
        ToolDef::new(
            "pve_guest_ssh_test",
            "Test SSH to a guest",
            "ssh",
            Gate::SshRead,
            "Connects to a container or VM over SSH with the credentials for guests, and reports the verified host key. A container has its host key checked against the one read through pct; a VM needs known_hosts or fingerprint.",
        )
        .also(&["lxc", "vm"])
        .idempotent()
        .input(connection())
        .handler(guest_test),
        ToolDef::new(
            "pve_guest_ssh_exec",
            "Run a command in a guest over SSH",
            "ssh",
            Gate::SshWrite,
            "Runs any shell command in a container or VM over SSH, with the credentials for guests and as whichever user they log in as. A non-zero exit code is reported, not an error. For a container, pve_lxc_exec needs no credential and no SSH server inside. Tell the user what you run.",
        )
        .also(&["lxc", "vm"])
        .destructive()
        .open_world()
        .input(exec_input)
        .confirmation(|args| {
            let user = args.str("user").filter(|u| !u.is_empty()).map(|u| format!(" as {u}")).unwrap_or_default();
            format!("Run this in guest {} over SSH{user}?\n{}", args.i64("vmid").unwrap_or_default(), args.str("command").unwrap_or_default())
        })
        .handler(guest_exec),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        crate::tools::reference::assert_matches(&ssh_guest_tools());
    }

    #[test]
    fn ssh_guest_picks_an_address() {
        let c = |name: &str, address: &str| Candidate { name: name.into(), address: address.into() };
        assert_eq!(pick_address(&[c("lo", "127.0.0.1"), c("eth0", "fe80::1"), c("eth0", "2001:db8::5"), c("eth0", "10.0.0.5")]).as_deref(), Some("10.0.0.5"));
        assert_eq!(pick_address(&[c("eth0", "2001:db8::5")]).as_deref(), Some("2001:db8::5"));
        assert_eq!(pick_address(&[c("eth0", "::1"), c("eth0", "")]), None);
    }
}
