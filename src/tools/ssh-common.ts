import { posix } from 'node:path';
import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import type { GuestLocation } from '../proxmox/nodes.js';
import { fingerprintOf, keyTypeOf } from '../ssh/known-hosts.js';
import { EXIT_NOT_A_FILE, EXIT_NOT_FOUND, EXIT_NOT_READABLE, fileStatScript, readFileScript } from '../ssh/scripts.js';
import type { ExecResult, SshTarget } from '../ssh/index.js';
import { nodeName, type ToolContext } from './helpers.js';

/*
 * What the SSH tools share: validated argument types, the refusals, and the turning of a
 * finished command into a tool result or a typed error.
 */

/** Absolute, so that it cannot be taken for an option by any command it reaches. */
export const remotePath = z.string().min(1).max(4096).regex(/^\/[^\0]*$/, 'Expected an absolute path, with no NUL character').describe('An absolute path.');

/** The first character blocks option injection: none of these can start with a dash. */
export const unitName = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9@._:+-]*$/, 'Expected a service name').max(256);
export const packageName = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9+._:@=~-]*$/, 'Expected a package name').max(256);
export const userName = z.string().regex(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/, 'Expected a user name').max(32);
export const fileMode = z.string().regex(/^[0-7]{3,4}$/, 'Expected an octal mode such as 0644');
export const fileOwner = z.string().regex(/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]*)?$/, 'Expected user or user:group').max(65);
export const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const timeoutSeconds = z.number().int().min(1).max(86_400).optional().describe('Stop after this long. Default: PROXMOX_SSH_TIMEOUT_SECONDS. The command may go on running on the far side after the channel is closed.');
export const maxOutputBytes = z.number().int().min(1024).optional().describe('Keep at most this much of stdout, and of stderr. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES.');
export const targetNode = nodeName.optional().describe('Node to connect to. Default: PROXMOX_DEFAULT_NODE, or the only node.');
export const guestNode = nodeName.optional().describe('Node of the guest, checked if given. Found from the vmid otherwise.');

export function execOptions(args: { timeout_seconds?: number | undefined; max_output_bytes?: number | undefined }, ctx: ToolContext): { timeoutMs?: number; maxBytes?: number } {
  return {
    ...(args.timeout_seconds !== undefined ? { timeoutMs: args.timeout_seconds * 1000 } : {}),
    ...(args.max_output_bytes !== undefined ? { maxBytes: Math.min(args.max_output_bytes, ctx.instance.ssh.maxOutputBytes) } : {}),
  };
}

export async function nodeTarget(ctx: ToolContext, node: string | undefined): Promise<SshTarget> {
  return { node: node ?? (await ctx.nodes.defaultNode()) };
}

export function assertWritable(ctx: ToolContext, vmid: number): void {
  if (ctx.instance.protectedVmids.has(vmid)) {
    throw new ProxmoxError('protected_guest', `Guest ${vmid} is protected on this server: nothing was run.`, {
      hint: 'Do not retry and do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS.',
    });
  }
}

/** Where a container is. Only containers: pct has nothing to say about a VM. */
export async function locateLxc(ctx: ToolContext, vmid: number, node: string | undefined): Promise<GuestLocation> {
  const guest = await ctx.nodes.resolveGuest(vmid);
  if (guest.type !== 'lxc') {
    throw new ProxmoxError('invalid_input', `Guest ${vmid} is a VM, not a container: pct cannot reach it.`, { hint: 'pve_guest_ssh_exec reaches a VM over SSH, and the guest agent tools go through the API.' });
  }
  if (node !== undefined && node !== guest.node) {
    throw new ProxmoxError('invalid_input', `Container ${vmid} is on node ${guest.node}, not ${node}.`, { hint: 'Leave node out: it is found from the vmid.' });
  }
  return guest;
}

/** The last of an output, for an error message. */
function tail(text: string, chars = 2000): string {
  return text.length > chars ? `...${text.slice(-chars)}` : text;
}

function failureDetails(res: ExecResult): Record<string, unknown> {
  return { exit_code: res.exit_code, stdout: tail(res.stdout), stderr: tail(res.stderr), untrusted: true };
}

/** Whole lines only: what a container prints on its own stderr should not read as a message from pct. */
const NOT_RUNNING = /^(?:CT \d+ not running|container '?\d+'? (?:is )?not running!?|can only (?:push|pull) files (?:to|from) a running CT|.*\bFailed to get init pid\b.*)\.?$/im;
const NO_CONFIG = /^Configuration file '[^']*' does not exist$/im;
const LOCKED = /^CT is locked(?: \([^)]*\))?\.?$/im;
const MUST_BE_STOPPED = /^Cannot run command on active container\.?$/im;

/** Turns what pct and sudo answer into the errors an agent can act on. Undefined when it is none of these. */
export function pctFailure(res: ExecResult, vmid?: number): ProxmoxError | undefined {
  if (res.exit_code === 0) return undefined;
  const text = res.stderr;
  if (/^sudo: .*(?:password is required|a terminal is required|not allowed|not in the sudoers)/im.test(text)) {
    return new ProxmoxError('ssh_auth_failed', 'sudo -n was refused on the node.', { hint: 'The SSH user needs passwordless sudo for this, or the operator can connect as root.', details: failureDetails(res) });
  }
  if (vmid === undefined) return undefined;
  if (NOT_RUNNING.test(text)) {
    return new ProxmoxError('guest_not_running', `Container ${vmid} is not running: nothing was run in it.`, { hint: 'pve_guest_power or pve_start_lxc starts it. Offline work has pve_lxc_mount and pve_lxc_fsck.', details: failureDetails(res) });
  }
  if (NO_CONFIG.test(text)) return new ProxmoxError('not_found', `Container ${vmid} is not on this node.`, { hint: 'It may have moved. Leave node out, so that it is found from the vmid.', details: failureDetails(res) });
  if (LOCKED.test(text)) return new ProxmoxError('guest_locked', `Container ${vmid} is locked: ${tail(text, 200).trim()}`, { hint: 'A backup or migration may be running. Check before trying again.', details: failureDetails(res) });
  if (MUST_BE_STOPPED.test(text)) return new ProxmoxError('invalid_input', `Container ${vmid} is running, and this needs it stopped.`, { hint: 'Stop it first, if that is acceptable, with pve_guest_power.', details: failureDetails(res) });
  return undefined;
}

/** A command that could not run its course: timed out, or stopped before starting properly. */
export function assertRan(res: ExecResult, what: string, vmid?: number): void {
  if (res.timed_out) {
    throw new ProxmoxError('ssh_timeout', `${what} did not finish in time, and its channel was closed.`, { hint: 'It may still be running on the far side, and it may have done part of its work. Check before running it again, and give a larger timeout_seconds if needed.', details: failureDetails(res) });
  }
  const failure = pctFailure(res, vmid);
  if (failure) throw failure;
  if (res.exit_code === 127 && /\bpct\b.*(?:not found|No such file)/i.test(res.stderr)) {
    throw new ProxmoxError('not_supported', 'pct is not available on this host: it does not look like a Proxmox node.', { details: failureDetails(res) });
  }
}

/** For commands of this server: a failure is an error. For arbitrary commands, the exit code is the answer. */
export function assertOk(res: ExecResult, what: string, vmid?: number): void {
  assertRan(res, what, vmid);
  if (res.dry_run || res.exit_code === 0) return;
  const reason = res.stderr.trim() || res.stdout.trim();
  throw new ProxmoxError('upstream_error', `${what} failed with exit code ${res.exit_code}${reason ? `: ${tail(reason, 500)}` : ''}`, { details: failureDetails(res) });
}

/** The result of a command run for the agent. */
export function present(res: ExecResult, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const { host_key: _hostKey, ...rest } = res;
  return {
    ...rest,
    ...(res.truncated ? { warning: 'Output over the cap was dropped: stdout and stderr hold only the start. Redirect to a file and read parts of it, or narrow the command.' } : {}),
    untrusted: true,
    ...extra,
  };
}

/** Paths known to hold keys and password hashes, on a node as in a container. */
const SECRET_PATHS: RegExp[] = [
  /^\/etc\/pve\/priv(?:\/|$)/,
  /^\/etc\/pve\/(?:local|nodes\/[^/]+)\/[^/]*\.key$/,
  /^\/var\/lib\/pve-cluster\/config\.db/,
  /^\/etc\/corosync\/authkey$/,
  /^\/etc\/(?:shadow|gshadow)-?$/,
  /^\/etc\/security\/opasswd$/,
  /^\/etc\/ssh\/ssh_host_[^/]*_key$/,
  /^\/(?:root|home\/[^/]+)\/\.ssh\/id_[^/]*$/,
  /^\/proc\/[^/]+\/environ$/,
];

export function isSecretPath(path: string): boolean {
  const normal = posix.normalize(path);
  if (normal.endsWith('.pub')) return false;
  return SECRET_PATHS.some((pattern) => pattern.test(normal));
}

/** Both as asked and after links: a link in /tmp to /etc/shadow is /etc/shadow. */
export function assertNotSecret(ctx: ToolContext, ...paths: string[]): void {
  if (ctx.instance.allowSensitive) return;
  for (const path of paths) {
    if (isSecretPath(path)) {
      throw new ProxmoxError('sensitive_disabled', `${path} holds key material or password hashes, and this server does not read those.`, {
        hint: 'Do not retry and do not look for another route to the same file. The operator can allow it with PROXMOX_ALLOW_SENSITIVE=true.',
      });
    }
  }
}

export interface FileStat {
  size: number;
  real: string;
}

/**
 * Looks at a remote file through the given wrapper: as it is on a node, or carried by pct exec.
 * Undefined in a dry run, when nothing is known about it.
 */
export async function statRemoteFile(ctx: ToolContext, target: SshTarget, wrap: (script: string) => string, path: string, vmid?: number): Promise<FileStat | undefined> {
  assertNotSecret(ctx, path);
  const res = await ctx.ssh.run(target, { text: wrap(fileStatScript(path)), access: 'read' });
  if (res.dry_run) return undefined;
  assertRan(res, `Reading ${path}`, vmid);
  if (res.exit_code === EXIT_NOT_FOUND) throw new ProxmoxError('not_found', `${path} does not exist.`);
  if (res.exit_code === EXIT_NOT_A_FILE) throw new ProxmoxError('invalid_input', `${path} is not a regular file.`, { hint: 'The list_dir tools show directories.' });
  if (res.exit_code === EXIT_NOT_READABLE) throw new ProxmoxError('forbidden', `${path} cannot be read by this user.`);
  assertOk(res, `Reading ${path}`, vmid);
  const [size, ...rest] = res.stdout.split('\n');
  // Only the one newline readlink adds: a file name can end with spaces, or with a newline of its own.
  const real = rest.join('\n').replace(/\n$/, '') || path;
  assertNotSecret(ctx, real);
  return { size: Number(size), real };
}

export interface ReadFileArgs {
  path: string;
  max_bytes?: number | undefined;
  allow_partial?: boolean | undefined;
}

/** A file as text, refusing what is over the cap rather than returning less than was asked for. */
export async function readRemoteFile(ctx: ToolContext, target: SshTarget, wrap: (script: string) => string, args: ReadFileArgs, vmid?: number): Promise<Record<string, unknown>> {
  const stat = await statRemoteFile(ctx, target, wrap, args.path, vmid);
  const cap = Math.min(args.max_bytes ?? ctx.instance.ssh.maxOutputBytes, ctx.instance.ssh.maxOutputBytes);
  if (!stat) return { path: args.path };
  const partial = stat.size > cap;
  if (partial && !args.allow_partial) {
    throw new ProxmoxError('ssh_output_too_large', `${args.path} is ${stat.size} bytes, over the limit of ${cap}.`, { hint: 'allow_partial returns the start of it. The pull_file and download tools copy a file of any size.', details: { size: stat.size, limit: cap } });
  }
  const res = await ctx.ssh.run(target, { text: wrap(readFileScript(stat.real, partial ? cap : undefined)), access: 'read' }, { maxBytes: cap });
  assertOk(res, `Reading ${args.path}`, vmid);
  // Replacement characters mean this was not text: what came through is not the file.
  const binary = res.stdout.includes('�');
  return {
    path: args.path,
    ...(stat.real !== args.path ? { resolved_path: stat.real } : {}),
    size: stat.size,
    content: res.stdout,
    truncated: partial || res.truncated,
    ...(binary ? { binary: true, hint: 'This does not look like text, so content is not faithful. The pull_file and download tools copy it as it is.' } : {}),
    untrusted: true,
  };
}

export interface ListedFile {
  mode: string;
  links: number;
  owner: string;
  group: string;
  size: number;
  modified: string;
  name: string;
  link_target?: string;
}

/** ls -la as GNU and BusyBox print it. Lines that are something else are left out. */
export function parseLs(output: string): ListedFile[] {
  const rows: ListedFile[] = [];
  for (const line of output.split('\n')) {
    const match = /^([bcdlps-][rwxsStT-]{9}[.+@]?)\s+(\d+)\s+(\S+)\s+(\S+)\s+(?:\d+,\s+)?(\d+)\s+(\S+\s+\S+\s+\S+)\s(.*)$/.exec(line);
    if (!match) continue;
    const [name, target] = match[1]!.startsWith('l') ? match[7]!.split(' -> ') : [match[7]!];
    if (name === '.' || name === '..') continue;
    rows.push({ mode: match[1]!, links: Number(match[2]), owner: match[3]!, group: match[4]!, size: Number(match[5]), modified: match[6]!.replace(/\s+/g, ' '), name: name!, ...(target ? { link_target: target } : {}) });
  }
  return rows;
}

const PUBLIC_KEY_TYPES = new Set(['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com']);

export interface ParsedPublicKey {
  type: string;
  blob: string;
  comment?: string;
  fingerprint: string;
  /** The line to write: normalized, one line, no options. */
  line: string;
}

/** One public key, with the blob checked against its declared type. An options prefix is not accepted here. */
export function parsePublicKey(text: string): ParsedPublicKey {
  const refused = (why: string) => new ProxmoxError('invalid_input', `This is not an acceptable SSH public key: ${why}.`, { hint: 'Expected one line, such as: ssh-ed25519 AAAAC3Nza... user@host. Never pass a private key.' });
  const value = text.trim();
  if (value.includes('PRIVATE KEY')) throw refused('it looks like a private key, which must not be sent anywhere');
  if (/[\r\n\0]/.test(value)) throw refused('it spans several lines');
  const match = /^(\S+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$/.exec(value);
  if (!match) throw refused('it is not "type base64 comment"');
  const [, type, blob, comment] = match;
  if (!PUBLIC_KEY_TYPES.has(type!)) throw refused(`unknown key type "${type!.slice(0, 40)}"`);
  const key = Buffer.from(blob!, 'base64');
  if (keyTypeOf(key) !== type) throw refused('the key data does not match its declared type');
  // eslint-disable-next-line no-control-regex
  if (comment && /[\u0000-\u001f\u007f]/.test(comment)) throw refused('the comment holds control characters');
  return { type: type!, blob: blob!, ...(comment ? { comment } : {}), fingerprint: fingerprintOf(key), line: `${type} ${blob}${comment ? ` ${comment}` : ''}` };
}

/** authorized_keys lines, which may have options in front. Anything else is reported as unparsed. */
export function parseAuthorizedKeys(output: string): { keys: Array<Record<string, unknown>>; unparsed: number } {
  const keys: Array<Record<string, unknown>> = [];
  let unparsed = 0;
  for (const raw of output.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^(?:(.*?)\s+)?((?:ssh|ecdsa|sk)-[a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s+(.*))?$/.exec(line);
    if (!match || !PUBLIC_KEY_TYPES.has(match[2]!)) {
      unparsed++;
      continue;
    }
    const key = Buffer.from(match[3]!, 'base64');
    keys.push({ type: match[2], fingerprint: fingerprintOf(key), blob: match[3], ...(match[4] ? { comment: match[4] } : {}), ...(match[1] ? { options: match[1] } : {}) });
  }
  return { keys, unparsed };
}

/** Sections of a script that prints @@name lines. */
export function parseSections(output: string): Record<string, string> {
  const sections: Record<string, string> = {};
  let current = '';
  let body: string[] = [];
  for (const line of output.split('\n')) {
    const match = /^@@([a-z-]+)$/.exec(line);
    if (match) {
      if (current) sections[current] = body.join('\n').trim();
      current = match[1]!;
      body = [];
    } else {
      body.push(line);
    }
  }
  if (current) sections[current] = body.join('\n').trim();
  return sections;
}

/** Splits leading key=value lines from what follows them. */
export function parseHeader(output: string): { header: Record<string, string>; rest: string } {
  const header: Record<string, string> = {};
  const lines = output.split('\n');
  let i = 0;
  for (; i < lines.length; i++) {
    const match = /^([a-z_]+)=(.*)$/.exec(lines[i]!);
    if (!match) break;
    header[match[1]!] = match[2]!;
  }
  return { header, rest: lines.slice(i).join('\n') };
}
