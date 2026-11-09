import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import type { GuestLocation } from '../proxmox/nodes.js';
import { pctExec, EXIT_CD_FAILED } from '../ssh/scripts.js';
import { parsePublicKeyLines } from '../ssh/known-hosts.js';
import { sh, shRaw, type GuestEndpoint, type ShellCommand, type SshTarget } from '../ssh/index.js';
import { isObject, tool, vmid, type ToolContext, type ToolDef } from './helpers.js';
import { assertRan, assertWritable, execOptions, maxOutputBytes, present, remotePath, timeoutSeconds, userName } from './ssh-common.js';

function usableAddress(address: string): boolean {
  const lower = address.toLowerCase();
  return lower !== '' && !lower.startsWith('fe80') && lower !== '::1';
}

function pickAddress(candidates: Array<{ name: string; address: string }>): string | undefined {
  const usable = candidates.filter((c) => c.name !== 'lo' && usableAddress(c.address));
  return (usable.find((c) => !c.address.includes(':')) ?? usable[0])?.address;
}

/** Addresses of a guest, as the node and the guest agent report them. */
async function findAddress(ctx: ToolContext, loc: GuestLocation): Promise<string> {
  const candidates: Array<{ name: string; address: string }> = [];
  const hint = 'Pass host, or use via_node with a guest the node can reach.';
  if (loc.type === 'lxc') {
    const rows = await ctx.api.get(`/nodes/${loc.node}/lxc/${loc.vmid}/interfaces`);
    for (const row of (Array.isArray(rows) ? rows : []) as Array<Record<string, unknown>>) {
      for (const key of ['inet', 'inet6']) {
        const value = row[key];
        if (typeof value === 'string') candidates.push({ name: String(row.name ?? ''), address: value.split('/')[0]! });
      }
    }
  } else {
    let answer: unknown;
    try {
      answer = await ctx.api.get(`/nodes/${loc.node}/qemu/${loc.vmid}/agent/network-get-interfaces`);
    } catch (err) {
      if (err instanceof ProxmoxError) throw new ProxmoxError('invalid_input', `The address of VM ${loc.vmid} is unknown: its guest agent did not answer (${err.message}).`, { hint });
      throw err;
    }
    const rows = isObject(answer) && Array.isArray(answer.result) ? answer.result : [];
    for (const row of rows as Array<Record<string, unknown>>) {
      for (const ip of (Array.isArray(row['ip-addresses']) ? row['ip-addresses'] : []) as Array<Record<string, unknown>>) {
        if (typeof ip['ip-address'] === 'string') candidates.push({ name: String(row.name ?? ''), address: ip['ip-address'] });
      }
    }
  }
  const address = pickAddress(candidates);
  if (!address) throw new ProxmoxError('invalid_input', `No usable address reported for guest ${loc.vmid}.`, { hint });
  return address;
}

/**
 * For a container the keys are read through pct, which is already authenticated, so host key
 * checking stays on with nothing to configure. A VM offers no such path: known_hosts or a
 * fingerprint on the call, else it is refused by the transport.
 */
async function containerHostKeys(ctx: ToolContext, loc: GuestLocation): Promise<string[] | undefined> {
  const res = await ctx.ssh.run({ node: loc.node }, { text: pctExec(loc.vmid, 'cat /etc/ssh/ssh_host_*_key.pub'), access: 'read' });
  if (res.dry_run) return undefined;
  assertRan(res, 'Reading the host keys', loc.vmid);
  const keys = res.stdout.split('\n').filter((line) => parsePublicKeyLines(line).length > 0);
  if (keys.length === 0) {
    throw new ProxmoxError('host_key_unknown', `Container ${loc.vmid} has no SSH host keys to check against.`, { hint: 'pve_lxc_ssh_enable installs and starts the SSH server. pve_lxc_exec needs none of this.' });
  }
  return keys;
}

interface GuestArgs {
  vmid: number;
  user?: string | undefined;
  host?: string | undefined;
  port?: number | undefined;
  via_node?: boolean | undefined;
  fingerprint?: string | undefined;
}

async function guestTarget(ctx: ToolContext, args: GuestArgs): Promise<{ target: SshTarget; loc: GuestLocation; guest: GuestEndpoint }> {
  const loc = await ctx.nodes.resolveGuest(args.vmid);
  const host = args.host ?? (await findAddress(ctx, loc));
  const hostKeys = loc.type === 'lxc' ? await containerHostKeys(ctx, loc) : undefined;
  const guest: GuestEndpoint = {
    vmid: args.vmid,
    host,
    port: args.port ?? 22,
    user: args.user ?? ctx.instance.ssh.guestUser ?? 'root',
    ...(args.via_node ? { viaNode: loc.node } : {}),
    ...(hostKeys ? { hostKeys } : {}),
    ...(args.fingerprint ? { fingerprint: args.fingerprint } : {}),
  };
  return { target: { node: loc.node, guest }, loc, guest };
}

const connection = {
  vmid,
  user: userName.optional().describe('Log in as this user. Default: PROXMOX_GUEST_SSH_USER, or root.'),
  host: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9.:_-]*$/, 'Expected an address').max(255).optional().describe('Address to connect to. Default: what the node or the guest agent reports.'),
  port: z.number().int().min(1).max(65_535).optional().describe('Default 22.'),
  via_node: z.boolean().optional().describe('Go through the node of the guest, for a guest this server cannot reach directly.'),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+=*$/, 'Expected SHA256:...').optional().describe('The host key to expect, for a VM that is not in known_hosts. Get it from the console of the VM, not from the connection itself.'),
};

/** Direct SSH to guests. */
export function sshGuestTools(): ToolDef[] {
  return [
    tool({
      name: 'pve_guest_ssh_test',
      title: 'Test SSH to a guest',
      description: 'Connects to a container or VM over SSH with the credentials for guests, and reports the verified host key. A container has its host key checked against the one read through pct; a VM needs known_hosts or fingerprint.',
      domain: 'ssh',
      also: ['lxc', 'vm'],
      gate: 'ssh_read',
      idempotent: true,
      input: connection,
      handler: async (args, ctx) => {
        const { target, guest } = await guestTarget(ctx, args);
        const res = await ctx.ssh.run(target, { text: 'id -un; uname -srm', access: 'read' });
        assertRan(res, 'The SSH test');
        const [user, system] = res.stdout.split('\n');
        return { vmid: args.vmid, host: guest.host, port: guest.port, connected: true, user, system, host_key: res.host_key, duration_ms: res.duration_ms, untrusted: true };
      },
    }),
    tool({
      name: 'pve_guest_ssh_exec',
      title: 'Run a command in a guest over SSH',
      description: 'Runs any shell command in a container or VM over SSH, with the credentials for guests and as whichever user they log in as. A non-zero exit code is reported, not an error. For a container, pve_lxc_exec needs no credential and no SSH server inside. Tell the user what you run.',
      domain: 'ssh',
      also: ['lxc', 'vm'],
      gate: 'ssh_write',
      destructive: true,
      openWorld: true,
      input: {
        ...connection,
        command: z.string().min(1).describe('Shell text.'),
        stdin: z.string().optional().describe('Given to the command as its input. Never logged.'),
        cwd: remotePath.optional().describe('Run in this directory.'),
        timeout_seconds: timeoutSeconds,
        max_output_bytes: maxOutputBytes,
      },
      confirmation: (args) => `Run this in guest ${args.vmid} over SSH${args.user ? ` as ${args.user}` : ''}?\n${args.command}`,
      handler: async (args, ctx) => {
        assertWritable(ctx, args.vmid);
        const { target, guest } = await guestTarget(ctx, args);
        const cmd: ShellCommand = { text: args.cwd ? sh`cd -- ${args.cwd} || exit ${EXIT_CD_FAILED}\n${shRaw(args.command)}` : args.command, access: 'write', ...(args.stdin !== undefined ? { stdin: args.stdin } : {}) };
        const res = await ctx.ssh.run(target, cmd, execOptions(args, ctx));
        assertRan(res, 'The command');
        return present(res, { vmid: args.vmid, host: guest.host });
      },
    }),
  ];
}
