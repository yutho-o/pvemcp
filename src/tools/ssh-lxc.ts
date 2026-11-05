import { randomUUID } from 'node:crypto';
import { statSync } from 'node:fs';
import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import { resolveLocalPath } from '../proxmox/localpath.js';
import type { GuestLocation } from '../proxmox/nodes.js';
import { sh, shRaw, type ExecResult } from '../ssh/index.js';
import {
  addKeyScript,
  createUserScript,
  deleteFileScript,
  deleteUserScript,
  diskUsageScript,
  EXIT_CD_FAILED,
  EXIT_NO_MANAGER,
  EXIT_NOT_FOUND,
  EXIT_REFUSED_LINK,
  EXIT_RELOAD_FAILED,
  EXIT_SSHD_NOT_EFFECTIVE,
  EXIT_SSHD_REJECTED,
  installPackagesScript,
  listDirScript,
  listKeysScript,
  listPackagesScript,
  logsScript,
  lxcInfoScript,
  pctExec,
  portsScript,
  processesScript,
  removeKeyScript,
  removePackagesScript,
  serviceScript,
  serviceStatusScript,
  sshConfigureScript,
  sshDisableScript,
  sshEnableScript,
  sshStatusScript,
  updatePackagesScript,
  writeFileScript,
} from '../ssh/scripts.js';
import { mapOf, pageRows, paging, tool, vmid, type ToolContext, type ToolDef } from './helpers.js';
import {
  assertOk,
  assertRan,
  assertWritable,
  envName,
  execOptions,
  fileMode,
  fileOwner,
  guestNode,
  locateLxc,
  maxOutputBytes,
  packageName,
  parseAuthorizedKeys,
  parseHeader,
  parseLs,
  parsePublicKey,
  parseSections,
  present,
  readRemoteFile,
  remotePath,
  statRemoteFile,
  timeoutSeconds,
  unitName,
  userName,
} from './ssh-common.js';
import { assertLocalTarget, downloadTo } from './ssh-node.js';

const guest = { vmid, node: guestNode };
const ROOT_IN_CT = 'Runs as root inside the container, from the node, through pct: not a sandbox.';

/** Runs a script inside a container. */
function runIn(ctx: ToolContext, loc: GuestLocation, access: 'read' | 'write', script: string, extra: { stdin?: string | Buffer; display?: string; sensitiveStdin?: boolean; timeoutMs?: number; maxBytes?: number } = {}): Promise<ExecResult> {
  const { timeoutMs, maxBytes, ...cmd } = extra;
  return ctx.ssh.run(
    { node: loc.node },
    { text: pctExec(loc.vmid, script), access, ...cmd },
    { ...(timeoutMs !== undefined ? { timeoutMs } : {}), ...(maxBytes !== undefined ? { maxBytes } : {}) },
  );
}

async function forWrite(ctx: ToolContext, id: number, node: string | undefined): Promise<GuestLocation> {
  assertWritable(ctx, id);
  return locateLxc(ctx, id, node);
}

function parseOsRelease(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const match = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (match) out[match[1]!.toLowerCase()] = match[2]!.replace(/^["']|["']$/g, '');
  }
  return out;
}

function parseIps(text: string): Array<Record<string, string>> {
  const rows: Array<Record<string, string>> = [];
  for (const line of text.split('\n')) {
    const match = /^\d+:\s+(\S+)\s+(inet6?)\s+(\S+)/.exec(line);
    if (match) rows.push({ interface: match[1]!, family: match[2]!, address: match[3]! });
  }
  return rows;
}

function parseMounts(text: string): Array<Record<string, string>> {
  return text
    .split('\n')
    .map((line) => line.split(' '))
    .filter((f) => f.length >= 4)
    .map((f) => ({ device: f[0]!, mountpoint: f[1]!, type: f[2]!, options: f[3]! }));
}

interface PackageRow {
  name: string;
  version?: string;
  arch?: string;
}

function parsePackages(manager: string | undefined, text: string): PackageRow[] {
  const rows: PackageRow[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (manager === 'dpkg') {
      const [name, version, status] = line.split('\t');
      if (name && (!status || status.endsWith(' installed'))) rows.push({ name, ...(version ? { version } : {}) });
    } else if (manager === 'apk') {
      const match = /^(.+)-([^-]+-r\d+)$/.exec(line.trim());
      rows.push(match ? { name: match[1]!, version: match[2]! } : { name: line.trim() });
    } else if (manager === 'rpm') {
      const [name, version, arch] = line.split('\t');
      if (name) rows.push({ name, ...(version ? { version } : {}), ...(arch ? { arch } : {}) });
    } else {
      const [name, version] = line.trim().split(/\s+/);
      if (name) rows.push({ name, ...(version ? { version } : {}) });
    }
  }
  return rows;
}

function noManager(res: ExecResult): void {
  if (res.exit_code === EXIT_NO_MANAGER) throw new ProxmoxError('not_supported', res.stderr.trim() || 'No supported tool in this container.', { hint: 'pve_lxc_exec can do it by hand, knowing what this container has.' });
}

/** Parses ssh status output. The effective settings are lines of "name value". */
function parseSshStatus(text: string): Record<string, unknown> {
  const sections = parseSections(`@@head\n${text}`);
  const { header } = parseHeader(sections.head ?? '');
  const effective: Record<string, string | string[]> = {};
  let error: string | undefined;
  for (const line of (sections.effective ?? '').split('\n')) {
    const match = /^([a-z0-9]+) (.*)$/.exec(line);
    if (!match) {
      if (line.trim()) error = `${error ? `${error}\n` : ''}${line.trim()}`;
      continue;
    }
    const [, key, value] = match as unknown as [string, string, string];
    const existing = effective[key];
    effective[key] = existing === undefined ? value : Array.isArray(existing) ? [...existing, value] : [existing, value];
  }
  const ports = effective.port === undefined ? [] : (Array.isArray(effective.port) ? effective.port : [effective.port]).map(Number);
  return {
    installed: Boolean(header.binary),
    ...(header.binary ? { binary: header.binary } : {}),
    running: header.running === 'yes' || header.running === 'socket',
    ...(header.running === 'socket' ? { socket_activated: true } : {}),
    init: header.init,
    ...(header.dropbear ? { dropbear_installed: true } : {}),
    ports,
    ...(Object.keys(effective).length > 0 ? { effective } : {}),
    ...(error ? { sshd_error: error } : {}),
  };
}

/** Builds what pve_lxc_exec runs inside. Values are quoted; the command itself is shell text, once. */
function execScript(args: { command: string; cwd?: string | undefined; env?: Record<string, string> | undefined; as_user?: string | undefined }): { script: string; display: string } {
  const parts: string[] = [];
  if (args.cwd) parts.push(sh`cd -- ${args.cwd} || exit ${EXIT_CD_FAILED}`);
  for (const [name, value] of Object.entries(args.env ?? {})) parts.push(sh`${shRaw(name)}=${value}; export ${shRaw(name)}`);
  parts.push(sh`exec sh -c ${args.command}`);
  const inner = parts.join('\n');
  const script = args.as_user ? sh`exec su -s /bin/sh ${args.as_user} -c ${inner}` : inner;
  const context = [args.cwd ? `cwd=${args.cwd}` : '', args.as_user ? `as_user=${args.as_user}` : '', args.env ? `env=${Object.keys(args.env).join(',')}` : ''].filter(Boolean).join(' ');
  return { script, display: `${context ? `(${context}) ` : ''}${args.command}` };
}

const INTERPRETERS: Record<string, readonly string[]> = {
  sh: ['sh', '-s', '--'],
  bash: ['bash', '-s', '--'],
  ash: ['ash', '-s', '--'],
  dash: ['dash', '-s', '--'],
  python3: ['python3', '-'],
  perl: ['perl', '-'],
};

function sshConfigureFailure(res: ExecResult): void {
  const reason = res.stderr.trim();
  if (res.exit_code === EXIT_NOT_FOUND) throw new ProxmoxError('not_found', reason || 'sshd is not installed in this container.', { hint: 'pve_lxc_ssh_enable installs it.' });
  if (res.exit_code === EXIT_SSHD_REJECTED) throw new ProxmoxError('invalid_input', reason, { hint: 'The old configuration is back in place. If sshd has no host keys yet, pve_lxc_ssh_enable creates them.' });
  if (res.exit_code === EXIT_SSHD_NOT_EFFECTIVE) throw new ProxmoxError('upstream_error', reason, { hint: 'The old configuration is back in place. Look at /etc/ssh/sshd_config and sshd_config.d in the container.' });
  if (res.exit_code === EXIT_RELOAD_FAILED) throw new ProxmoxError('upstream_error', reason, { hint: 'The old configuration is back in place.' });
}

function lookupFailure(res: ExecResult, vmid: number): void {
  if (res.exit_code === EXIT_NOT_FOUND) throw new ProxmoxError('not_found', res.stderr.trim() || `No such user in container ${vmid}.`);
  if (res.exit_code === EXIT_REFUSED_LINK) throw new ProxmoxError('invalid_input', res.stderr.trim(), { hint: 'A link there could point anywhere, and root follows it. Check this home directory by hand.' });
}

/** SSH tools for containers, all through pct on the node. */
export function sshLxcTools(): ToolDef[] {
  return [
    tool({
      name: 'pve_lxc_info',
      title: 'Container system information',
      description: 'From inside a container: os-release, kernel, uptime, IP addresses and mounts.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: guest,
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', lxcInfoScript());
        assertOk(res, 'Reading container information', args.vmid);
        const s = parseSections(res.stdout);
        const seconds = Number((s.uptime ?? '').split(/\s+/)[0]);
        const ips = parseIps(s.ips ?? '');
        return {
          vmid: args.vmid,
          node: loc.node,
          os: parseOsRelease(s.os ?? ''),
          kernel: s.kernel,
          hostname: s.hostname,
          ...(Number.isFinite(seconds) && s.uptime ? { uptime_seconds: seconds } : {}),
          ips,
          ...(ips.length === 0 && s.ips ? { ips_raw: s.ips } : {}),
          mounts: parseMounts(s.mounts ?? ''),
          untrusted: true,
        };
      },
    }),
    tool({
      name: 'pve_lxc_processes',
      title: 'Container processes',
      description: 'The processes running inside a container, from ps.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: guest,
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', processesScript());
        assertOk(res, 'ps', args.vmid);
        return { vmid: args.vmid, node: loc.node, output: res.stdout, ...(res.truncated ? { truncated: true } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_ports',
      title: 'Container listening ports',
      description: 'What listens inside a container, from ss or netstat.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: guest,
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', portsScript());
        assertOk(res, 'Listing ports', args.vmid);
        return { vmid: args.vmid, node: loc.node, output: res.stdout, untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_disk_usage',
      title: 'Container disk usage',
      description: 'df inside a container, and optionally the total size of one directory.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, path: remotePath.optional().describe('Also give the total size of this directory.'), timeout_seconds: timeoutSeconds },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', diskUsageScript(args.path), execOptions(args, ctx));
        assertOk(res, 'df', args.vmid);
        const [df, du] = res.stdout.split('@@du\n');
        const filesystems = (df ?? '')
          .split('\n')
          .slice(1)
          .map((line) => line.trim().split(/\s+/))
          .filter((f) => f.length >= 6)
          .map((f) => ({ filesystem: f[0], size: f[1], used: f[2], available: f[3], use_percent: f[4], mountpoint: f.slice(5).join(' ') }));
        return { vmid: args.vmid, node: loc.node, filesystems, ...(du ? { directory: du.trim() } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_logs',
      title: 'Container logs',
      description: 'Recent logs of a container: from the journal where there is one, otherwise from /var/log.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: {
        ...guest,
        unit: unitName.optional().describe('Only this service.'),
        lines: z.number().int().min(1).max(10_000).optional().describe('Last lines to show. Default 200.'),
        since: z.string().regex(/^(?:-\d+[a-z]+|[0-9A-Za-z][0-9A-Za-z :.+-]*)$/, 'Expected a time such as "2024-01-31 12:00", yesterday or -1h').max(64).optional().describe('Only honoured with a journal.'),
      },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', logsScript({ lines: args.lines ?? 200, ...(args.unit ? { unit: args.unit } : {}), ...(args.since ? { since: args.since } : {}) }));
        assertRan(res, 'Reading logs', args.vmid);
        if (res.exit_code === EXIT_NOT_FOUND) throw new ProxmoxError('not_found', res.stderr.trim() || 'No logs found in this container.', { hint: 'Some services only log to their own files: pve_lxc_list_dir on /var/log shows what is there.' });
        assertOk(res, 'Reading logs', args.vmid);
        const { header, rest } = parseHeader(res.stdout);
        return { vmid: args.vmid, node: loc.node, source: header.source, output: rest, ...(res.truncated ? { truncated: true } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_list_dir',
      title: 'List a directory in a container',
      description: 'ls -la inside a container, as rows.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, path: remotePath, ...paging },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', listDirScript(args.path));
        assertOk(res, `Listing ${args.path}`, args.vmid);
        return { vmid: args.vmid, node: loc.node, path: args.path, ...pageRows(parseLs(res.stdout), args.page_limit, args.page_offset), ...(res.truncated ? { truncated_output: true } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_read_file',
      title: 'Read a file in a container',
      description: 'Reads a text file inside a container, up to a size cap. Refuses well-known secrets such as /etc/shadow and /root/.ssh/id_*, also through a link, unless PROXMOX_ALLOW_SENSITIVE is on.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: {
        ...guest,
        path: remotePath,
        max_bytes: z.number().int().min(1).optional().describe('Largest file to return. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES.'),
        allow_partial: z.boolean().optional().describe('Return the start of a file over the limit, instead of an error.'),
      },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        return { vmid: args.vmid, node: loc.node, ...(await readRemoteFile(ctx, { node: loc.node }, (s) => pctExec(args.vmid, s), args, args.vmid)) };
      },
    }),
    tool({
      name: 'pve_lxc_service_status',
      title: 'Service status in a container',
      description: 'One service, or all of them, under systemd, OpenRC or SysV init, whichever the container has.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, unit: unitName.optional().describe('A service. Without it, all of them are listed.') },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', serviceStatusScript(args.unit));
        assertOk(res, 'Reading service status', args.vmid);
        const { header, rest } = parseHeader(res.stdout);
        return { vmid: args.vmid, node: loc.node, ...header, output: rest.trim(), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_list_packages',
      title: 'Packages in a container',
      description: 'Installed packages, through dpkg, apk, rpm or pacman, whichever the container has.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, filter: z.string().max(128).optional().describe('Only packages whose name holds this.'), ...paging },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', listPackagesScript());
        assertRan(res, 'Listing packages', args.vmid);
        noManager(res);
        assertOk(res, 'Listing packages', args.vmid);
        const { header, rest } = parseHeader(res.stdout);
        let rows = parsePackages(header.manager, rest);
        if (args.filter) rows = rows.filter((r) => r.name.includes(args.filter!));
        return { vmid: args.vmid, node: loc.node, manager: header.manager, ...pageRows(rows, args.page_limit, args.page_offset), ...(res.truncated ? { truncated_output: true } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_list_users',
      title: 'Users in a container',
      description: 'The accounts in /etc/passwd of a container. No password data: that lives in /etc/shadow, which is not read.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, include_system: z.boolean().optional().describe('Also list uid 1-999. Default true.'), ...paging },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', 'cat /etc/passwd');
        assertOk(res, 'Reading /etc/passwd', args.vmid);
        let rows = res.stdout
          .split('\n')
          .map((line) => line.split(':'))
          .filter((f) => f.length >= 7)
          .map((f) => ({ name: f[0]!, uid: Number(f[2]), gid: Number(f[3]), comment: f[4]!, home: f[5]!, shell: f[6]! }));
        if (args.include_system === false) rows = rows.filter((r) => r.uid === 0 || (r.uid >= 1000 && r.uid < 65_534));
        return { vmid: args.vmid, node: loc.node, ...pageRows(rows, args.page_limit, args.page_offset), untrusted: true };
      },
    }),

    tool({
      name: 'pve_lxc_exec',
      title: 'Run a command in a container',
      description: `Runs any shell command inside a container, through pct exec. ${ROOT_IN_CT} A non-zero exit code is reported, not an error. A stopped container gives guest_not_running. Tell the user what you run.`,
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      openWorld: true,
      input: {
        ...guest,
        command: z.string().min(1).describe('Shell text, run by sh in the container: Alpine and others have no bash.'),
        stdin: z.string().optional().describe('Given to the command as its input. Never logged.'),
        cwd: remotePath.optional().describe('Run in this directory.'),
        env: mapOf(z.string(), { pattern: envName, message: 'Expected an environment variable name' }).optional().describe('Environment variables to set. The values are not logged, but they do appear on the command line of the node while it runs.'),
        as_user: userName.optional().describe('Run as this user in the container, through su.'),
        timeout_seconds: timeoutSeconds,
        max_output_bytes: maxOutputBytes,
      },
      confirmation: (args) => `Run this in container ${args.vmid}${args.as_user ? ` as ${args.as_user}` : ' as root'}?\n${args.command}`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const { script, display } = execScript(args);
        const res = await runIn(ctx, loc, 'write', script, { display: `pct exec ${args.vmid} -- ${display}`, ...(args.stdin !== undefined ? { stdin: args.stdin } : {}), ...execOptions(args, ctx) });
        assertRan(res, 'The command', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node });
      },
    }),
    tool({
      name: 'pve_lxc_run_script',
      title: 'Run a script in a container',
      description: `Runs a whole script inside a container, given to the interpreter on stdin, so that it needs no quoting and leaves no file. Its own stdin is therefore used up. ${ROOT_IN_CT} A non-zero exit code is reported, not an error.`,
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      openWorld: true,
      input: {
        ...guest,
        script: z.string().min(1).describe('The script. Never logged.'),
        interpreter: z.enum(['sh', 'bash', 'ash', 'dash', 'python3', 'perl']).optional().describe('Must exist in the container. Default sh.'),
        args: z.array(z.string()).optional().describe('Arguments for the script.'),
        timeout_seconds: timeoutSeconds,
        max_output_bytes: maxOutputBytes,
      },
      confirmation: (args) => `Run a ${args.script.length}-character ${args.interpreter ?? 'sh'} script as root in container ${args.vmid}?\n${args.script.slice(0, 2000)}`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const interpreter = INTERPRETERS[args.interpreter ?? 'sh']!;
        const res = await ctx.ssh.run({ node: loc.node }, { text: sh`pct exec ${args.vmid} -- ${interpreter} ${args.args ?? []}`, access: 'write', stdin: args.script }, execOptions(args, ctx));
        assertRan(res, 'The script', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node });
      },
    }),
    tool({
      name: 'pve_lxc_write_file',
      title: 'Write a file in a container',
      description: 'Writes a file inside a container, whole or not at all, keeping the mode and owner of an existing file unless told otherwise.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        path: remotePath,
        content: z.string().describe('The new content. Never logged.'),
        encoding: z.enum(['utf8', 'base64']).optional().describe('How content is written. Default utf8.'),
        mode: fileMode.optional().describe('Such as 0644.'),
        owner: fileOwner.optional().describe('user or user:group.'),
        backup: z.boolean().optional().describe('Keep the old file as path.bak.TIMESTAMP.'),
        create_parents: z.boolean().optional().describe('Create missing directories.'),
      },
      confirmation: (args) => `Write ${args.content.length} characters to ${args.path} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const stdin = args.encoding === 'base64' ? Buffer.from(args.content, 'base64') : args.content;
        const script = writeFileScript(args.path, { ...(args.mode ? { mode: args.mode } : {}), ...(args.owner ? { owner: args.owner } : {}), ...(args.backup ? { backup: true } : {}), ...(args.create_parents ? { createParents: true } : {}) });
        const res = await runIn(ctx, loc, 'write', script, { stdin, display: `pct exec ${args.vmid} -- write ${args.path} (content on stdin)` });
        assertRan(res, `Writing ${args.path}`, args.vmid);
        if (res.exit_code === EXIT_NOT_FOUND) throw new ProxmoxError('not_found', res.stderr.trim(), { hint: 'create_parents creates the directories.' });
        assertOk(res, `Writing ${args.path}`, args.vmid);
        if (res.dry_run) return { vmid: args.vmid, node: loc.node, path: args.path };
        const [bytes, backup] = res.stdout.split('\n');
        return { vmid: args.vmid, node: loc.node, path: args.path, bytes: Number(bytes), ...(backup ? { backup } : {}) };
      },
    }),
    tool({
      name: 'pve_lxc_push_file',
      title: 'Copy a local file into a container',
      description: 'Copies a file from this server, under PROXMOX_LOCAL_DIR only, into a running container: SFTP to a temporary file on the node (mode 0600), pct push, and the temporary file is always removed.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        local_path: z.string().min(1).describe('Relative to PROXMOX_LOCAL_DIR, or absolute under it.'),
        path: remotePath.describe('Where it goes in the container. An existing file is replaced.'),
        mode: fileMode.optional().describe('Such as 0644.'),
        user: userName.optional().describe('Owner in the container.'),
        group: userName.optional().describe('Group in the container.'),
        timeout_seconds: timeoutSeconds,
      },
      confirmation: (args) => `Copy ${args.local_path} to ${args.path} in container ${args.vmid}, replacing any file there?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const local = resolveLocalPath(ctx.instance.localDir, args.local_path, { mustExist: true });
        if (!statSync(local).isFile()) throw new ProxmoxError('local_path_refused', `${args.local_path} is not a regular file.`);
        const temp = `/tmp/pvemcp-${randomUUID()}`;
        const target = { node: loc.node };
        const timeoutMs = args.timeout_seconds ? args.timeout_seconds * 1000 : undefined;
        const sftp = await ctx.ssh.sftp(target, 'write');
        let cleanup: Record<string, unknown> = {};
        try {
          try {
            await sftp.fastPut(local, temp, { mode: 0o600, ...(timeoutMs ? { timeoutMs } : {}) });
          } finally {
            sftp.close();
          }
          const options = [...(args.mode ? [`--perms ${sh`${args.mode}`}`] : []), ...(args.user ? [`--user ${sh`${args.user}`}`] : []), ...(args.group ? [`--group ${sh`${args.group}`}`] : [])].join(' ');
          const res = await ctx.ssh.run(target, { text: sh`pct push ${args.vmid} ${temp} ${args.path} ${shRaw(options)}`.trimEnd(), access: 'write' }, timeoutMs ? { timeoutMs } : {});
          assertOk(res, 'pct push', args.vmid);
        } finally {
          const removed = await ctx.ssh.run(target, { text: deleteFileScript(temp, true), access: 'write' }).catch((err: Error) => err);
          if (removed instanceof Error || removed.exit_code !== 0) cleanup = { temp_file_left_on_node: temp };
        }
        return { vmid: args.vmid, node: loc.node, path: args.path, bytes: statSync(local).size, ...cleanup };
      },
    }),
    tool({
      name: 'pve_lxc_pull_file',
      title: 'Copy a file out of a container',
      description: 'Copies a file from a running container to this server, under PROXMOX_LOCAL_DIR only: pct pull to a temporary file on the node (mode 0600), SFTP, and the temporary file is always removed. Refuses well-known secrets, as pve_lxc_read_file does.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: {
        ...guest,
        path: remotePath.describe('The file in the container.'),
        local_path: z.string().min(1).describe('Relative to PROXMOX_LOCAL_DIR, or absolute under it. Its directory must exist.'),
        overwrite: z.boolean().optional().describe('Replace a local file that exists. Default false.'),
        timeout_seconds: timeoutSeconds,
      },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const local = resolveLocalPath(ctx.instance.localDir, args.local_path, { mustExist: false });
        assertLocalTarget(local, args.overwrite, args.local_path);
        const target = { node: loc.node };
        const timeoutMs = args.timeout_seconds ? args.timeout_seconds * 1000 : undefined;
        const stat = await statRemoteFile(ctx, target, (s) => pctExec(args.vmid, s), args.path, args.vmid);
        const temp = `/tmp/pvemcp-${randomUUID()}`;
        const { sudo, user } = ctx.instance.ssh;
        // With sudo, pct writes as root, and SFTP has to be able to read it afterwards.
        const owner = sudo && user !== 'root' ? sh` --user ${user}` : '';
        let cleanup: Record<string, unknown> = {};
        try {
          const res = await ctx.ssh.run(target, { text: `${sh`pct pull ${args.vmid} ${stat?.real ?? args.path} ${temp} --perms 0600`}${owner}`, access: 'write' }, timeoutMs ? { timeoutMs } : {});
          assertOk(res, 'pct pull', args.vmid);
          if (!res.dry_run) await downloadTo(ctx, target, temp, local, timeoutMs);
          else ctx.dryRunLog.push({ ssh: { node: loc.node, sftp: 'fastGet', path: temp, access: 'read' } });
        } finally {
          const removed = await ctx.ssh.run(target, { text: deleteFileScript(temp, true), access: 'write' }).catch((err: Error) => err);
          if (removed instanceof Error || removed.exit_code !== 0) cleanup = { temp_file_left_on_node: temp };
        }
        return { vmid: args.vmid, node: loc.node, path: args.path, local_path: local, ...(ctx.dryRun ? {} : { bytes: statSync(local).size }), ...cleanup };
      },
    }),
    tool({
      name: 'pve_lxc_delete_file',
      title: 'Delete a file in a container',
      description: 'Deletes one file inside a container. Not directories.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: { ...guest, path: remotePath, missing_ok: z.boolean().optional().describe('A file already gone is not an error.') },
      confirmation: (args) => `Delete ${args.path} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', deleteFileScript(args.path, args.missing_ok === true));
        assertRan(res, `Deleting ${args.path}`, args.vmid);
        if (/No such file/i.test(res.stderr) && res.exit_code !== 0) throw new ProxmoxError('not_found', `${args.path} does not exist in container ${args.vmid}.`);
        assertOk(res, `Deleting ${args.path}`, args.vmid);
        return { vmid: args.vmid, node: loc.node, path: args.path, deleted: !res.dry_run };
      },
    }),
    tool({
      name: 'pve_lxc_service',
      title: 'Control a service in a container',
      description: 'Start, stop, restart, reload, enable or disable a service, under systemd, OpenRC or SysV init, whichever the container has.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructiveWhen: (args) => args.action !== 'start' && args.action !== 'enable',
      input: { ...guest, unit: unitName.describe('The service.'), action: z.enum(['start', 'stop', 'restart', 'reload', 'enable', 'disable']).describe('What to do with it.') },
      confirmation: (args) => `${args.action} the service ${args.unit} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', serviceScript(args.action, args.unit));
        assertRan(res, `${args.action} ${args.unit}`, args.vmid);
        noManager(res);
        assertOk(res, `${args.action} ${args.unit}`, args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node, ...parseHeader(res.stdout).header });
      },
    }),
    tool({
      name: 'pve_lxc_install_packages',
      title: 'Install packages in a container',
      description: 'Installs packages with apt, apk, dnf, yum or pacman, whichever the container has. Non-interactive. On Arch, refresh is a full upgrade, since partial upgrades are not supported there.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      idempotent: true,
      openWorld: true,
      input: {
        ...guest,
        packages: z.array(packageName).min(1).max(200).describe('Package names. A version where the manager allows it: curl=8.5.0-1.'),
        refresh: z.boolean().optional().describe('Refresh the package lists first. Default true.'),
        timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 600.'),
      },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', installPackagesScript(args.packages, args.refresh ?? true), { timeoutMs: (args.timeout_seconds ?? 600) * 1000 });
        assertRan(res, 'Installing packages', args.vmid);
        noManager(res);
        assertOk(res, 'Installing packages', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node, manager: parseHeader(res.stdout).header.manager, packages: args.packages });
      },
    }),
    tool({
      name: 'pve_lxc_remove_packages',
      title: 'Remove packages from a container',
      description: 'Removes packages with apt, apk, dnf, yum or pacman, whichever the container has.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        packages: z.array(packageName).min(1).max(200).describe('Package names.'),
        purge: z.boolean().optional().describe('Also remove configuration, where the manager can: apt purge, pacman -Rns.'),
        timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 600.'),
      },
      confirmation: (args) => `Remove these packages from container ${args.vmid}: ${args.packages.join(', ')}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', removePackagesScript(args.packages, args.purge === true), { timeoutMs: (args.timeout_seconds ?? 600) * 1000 });
        assertRan(res, 'Removing packages', args.vmid);
        noManager(res);
        assertOk(res, 'Removing packages', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node, manager: parseHeader(res.stdout).header.manager, packages: args.packages });
      },
    }),
    tool({
      name: 'pve_lxc_update_packages',
      title: 'Update packages in a container',
      description: 'Refreshes the package lists and upgrades everything, with apt, apk, dnf, yum or pacman, whichever the container has. Non-interactive: existing configuration files are kept.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      openWorld: true,
      input: {
        ...guest,
        full: z.boolean().optional().describe('On apt: dist-upgrade, which may add and remove packages. Default false.'),
        timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 1800.'),
      },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', updatePackagesScript(args.full === true), { timeoutMs: (args.timeout_seconds ?? 1800) * 1000 });
        assertRan(res, 'Updating packages', args.vmid);
        noManager(res);
        assertOk(res, 'Updating packages', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node, manager: parseHeader(res.stdout).header.manager });
      },
    }),
    tool({
      name: 'pve_lxc_create_user',
      title: 'Create a user in a container',
      description: 'Creates a user with useradd or, on Alpine, the adduser of BusyBox. pve_lxc_set_password and pve_lxc_ssh_add_key give it a way in.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: {
        ...guest,
        name: userName.describe('The user to create.'),
        uid: z.number().int().min(0).max(4_294_967_294).optional().describe('User id. Default: decided by the container.'),
        shell: remotePath.optional().describe('Such as /bin/sh.'),
        home: remotePath.optional().describe('Home directory. Default: decided by the container.'),
        comment: z.string().regex(/^[^:\r\n\0]*$/, 'No colons or line breaks').max(128).optional().describe('Full name or note: the GECOS field.'),
        groups: z.array(userName).max(32).optional().describe('Extra groups, which must exist.'),
        system: z.boolean().optional().describe('A system account.'),
      },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', createUserScript(args.name, { ...(args.uid !== undefined ? { uid: args.uid } : {}), ...(args.shell ? { shell: args.shell } : {}), ...(args.home ? { home: args.home } : {}), ...(args.comment ? { comment: args.comment } : {}), ...(args.groups ? { groups: args.groups } : {}), ...(args.system ? { system: true } : {}) }));
        assertRan(res, `Creating user ${args.name}`, args.vmid);
        noManager(res);
        assertOk(res, `Creating user ${args.name}`, args.vmid);
        return { vmid: args.vmid, node: loc.node, user: args.name, created: !res.dry_run };
      },
    }),
    tool({
      name: 'pve_lxc_delete_user',
      title: 'Delete a user in a container',
      description: 'Deletes a user with userdel or, on Alpine, the deluser of BusyBox. Refuses root.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: { ...guest, name: userName.describe('The user to delete.'), remove_home: z.boolean().optional().describe('Also delete the home directory.') },
      confirmation: (args) => `Delete user ${args.name}${args.remove_home ? ' and its home directory' : ''} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        if (args.name === 'root') throw new ProxmoxError('invalid_input', 'This tool does not delete root.');
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', deleteUserScript(args.name, args.remove_home === true));
        assertRan(res, `Deleting user ${args.name}`, args.vmid);
        noManager(res);
        assertOk(res, `Deleting user ${args.name}`, args.vmid);
        return { vmid: args.vmid, node: loc.node, user: args.name, deleted: !res.dry_run };
      },
    }),
    tool({
      name: 'pve_lxc_set_password',
      title: 'Set a password in a container',
      description: 'Sets the password of a user in a container, through chpasswd on stdin: never on a command line, and no digest of it in the logs.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        user: userName.describe('The user whose password changes.'),
        password: z.string().min(1).max(4096).regex(/^[^\r\n\0]*$/, 'No line breaks').describe('The new password. Never logged.'),
      },
      confirmation: (args) => `Change the password of ${args.user} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await ctx.ssh.run({ node: loc.node }, { text: sh`pct exec ${args.vmid} -- chpasswd`, access: 'write', stdin: `${args.user}:${args.password}\n`, sensitiveStdin: true, display: `pct exec ${args.vmid} -- chpasswd (password of ${args.user} on stdin)` });
        assertOk(res, `Setting the password of ${args.user}`, args.vmid);
        return { vmid: args.vmid, node: loc.node, user: args.user, changed: !res.dry_run };
      },
    }),
    tool({
      name: 'pve_lxc_fsck',
      title: 'Check a container filesystem',
      description: 'pct fsck on a stopped container: checks, and with force repairs, the root disk or a mount point. It refuses a running container.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        device: z.string().regex(/^(?:rootfs|mp\d+)$/, 'Expected rootfs or mp0, mp1...').optional().describe('rootfs, mp0... Default rootfs.'),
        force: z.boolean().optional().describe('Check even if the filesystem looks clean.'),
        timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 1800.'),
      },
      confirmation: (args) => `Run fsck on ${args.device ?? 'rootfs'} of container ${args.vmid}?`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const options = [...(args.device ? [sh`--device ${args.device}`] : []), ...(args.force ? ['--force 1'] : [])];
        const res = await ctx.ssh.run({ node: loc.node }, { text: [sh`pct fsck ${args.vmid}`, ...options].join(' '), access: 'write' }, { timeoutMs: (args.timeout_seconds ?? 1800) * 1000 });
        assertOk(res, 'pct fsck', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node });
      },
    }),
    tool({
      name: 'pve_lxc_fstrim',
      title: 'Trim a container filesystem',
      description: 'pct fstrim on a running container: gives unused blocks back to thin storage.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: {
        ...guest,
        ignore_mountpoints: z.boolean().optional().describe('Only the root disk.'),
        timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 1800.'),
      },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await ctx.ssh.run({ node: loc.node }, { text: `${sh`pct fstrim ${args.vmid}`}${args.ignore_mountpoints ? ' --ignore-mountpoints 1' : ''}`, access: 'write' }, { timeoutMs: (args.timeout_seconds ?? 1800) * 1000 });
        assertOk(res, 'pct fstrim', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node });
      },
    }),
    tool({
      name: 'pve_lxc_mount',
      title: 'Mount a container on its node',
      description: 'pct mount: mounts the filesystem of a stopped container under /var/lib/lxc/VMID/rootfs on the node, for offline repairs, and locks the container. pve_lxc_unmount undoes it, and the container cannot start until then.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: guest,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await ctx.ssh.run({ node: loc.node }, { text: sh`pct mount ${args.vmid}`, access: 'write' });
        assertOk(res, 'pct mount', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node, mounted_at: `/var/lib/lxc/${args.vmid}/rootfs`, next_step: 'pve_lxc_unmount' });
      },
    }),
    tool({
      name: 'pve_lxc_unmount',
      title: 'Unmount a container from its node',
      description: 'pct unmount: undoes pve_lxc_mount and removes its lock.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: guest,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await ctx.ssh.run({ node: loc.node }, { text: sh`pct unmount ${args.vmid}`, access: 'write' });
        assertOk(res, 'pct unmount', args.vmid);
        return present(res, { vmid: args.vmid, node: loc.node });
      },
    }),

    tool({
      name: 'pve_lxc_ssh_status',
      title: 'SSH server state in a container',
      description: 'Whether sshd is installed and running in a container, on which ports, and its effective settings from sshd -T.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: guest,
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', sshStatusScript());
        assertOk(res, 'Reading the SSH status', args.vmid);
        return { vmid: args.vmid, node: loc.node, ...parseSshStatus(res.stdout), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_list_keys',
      title: 'Authorized SSH keys in a container',
      description: 'The public keys in authorized_keys of a user in a container, with their fingerprints.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { ...guest, user: userName.optional().describe('Default root.') },
      handler: async (args, ctx) => {
        const loc = await locateLxc(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'read', listKeysScript(args.user ?? 'root'));
        assertRan(res, 'Reading authorized keys', args.vmid);
        lookupFailure(res, args.vmid);
        assertOk(res, 'Reading authorized keys', args.vmid);
        return { vmid: args.vmid, node: loc.node, user: args.user ?? 'root', ...parseAuthorizedKeys(res.stdout), untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_enable',
      title: 'Enable the SSH server in a container',
      description: 'Installs openssh-server if it is missing, for the distribution of the container, then enables and starts it. Safe to repeat. By itself this opens no way in: add a key with pve_lxc_ssh_add_key.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      idempotent: true,
      openWorld: true,
      input: { ...guest, timeout_seconds: timeoutSeconds.describe('Stop after this long. Default 600.') },
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', sshEnableScript(), { timeoutMs: (args.timeout_seconds ?? 600) * 1000 });
        assertRan(res, 'Enabling SSH', args.vmid);
        noManager(res);
        assertOk(res, 'Enabling SSH', args.vmid);
        const header = Object.fromEntries(res.stdout.split('\n').flatMap((line) => {
          const match = /^(installed|init|manager)=(.*)$/.exec(line);
          return match ? [[match[1]!, match[2]!]] : [];
        }));
        return { vmid: args.vmid, node: loc.node, enabled: !res.dry_run, ...(header.installed ? { installed_now: header.installed === 'yes' } : {}), ...(header.init ? { init: header.init } : {}), ...(header.manager ? { manager: header.manager } : {}), next_step: 'pve_lxc_ssh_status', untrusted: true };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_disable',
      title: 'Disable the SSH server in a container',
      description: 'Stops sshd in a container and keeps it from starting at boot. Does not uninstall it. pct access is not affected.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: guest,
      confirmation: (args) => `Stop and disable the SSH server in container ${args.vmid}? Anyone logged in over SSH loses the way in.`,
      handler: async (args, ctx) => {
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', sshDisableScript());
        assertRan(res, 'Disabling SSH', args.vmid);
        noManager(res);
        assertOk(res, 'Disabling SSH', args.vmid);
        return { vmid: args.vmid, node: loc.node, disabled: !res.dry_run, ...parseHeader(res.stdout).header };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_add_key',
      title: 'Authorize an SSH key in a container',
      description: 'Adds a public key to authorized_keys of a user in a container, with the right modes (700 and 600) and owner. Adding a key already there changes nothing. Refuses a link at ~/.ssh or authorized_keys.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      idempotent: true,
      input: { ...guest, public_key: z.string().min(1).max(16_384).describe('One line: ssh-ed25519 AAAA... comment. Never a private key.'), user: userName.optional().describe('Default root.') },
      handler: async (args, ctx) => {
        const key = parsePublicKey(args.public_key);
        const loc = await forWrite(ctx, args.vmid, args.node);
        const user = args.user ?? 'root';
        const res = await runIn(ctx, loc, 'write', addKeyScript(user, key.line, key.blob));
        assertRan(res, 'Adding the key', args.vmid);
        lookupFailure(res, args.vmid);
        assertOk(res, 'Adding the key', args.vmid);
        return { vmid: args.vmid, node: loc.node, user, fingerprint: key.fingerprint, ...(res.dry_run ? {} : { added: res.stdout.trim().endsWith('added') }) };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_remove_key',
      title: 'Remove an SSH key in a container',
      description: 'Removes a key from authorized_keys of a user in a container, given as the public key or its fingerprint.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        public_key: z.string().min(1).max(16_384).optional().describe('The key to remove.'),
        fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+=*$/, 'Expected SHA256:...').optional().describe('Or its fingerprint, as pve_lxc_ssh_list_keys shows it.'),
        user: userName.optional().describe('Default root.'),
      },
      confirmation: (args) => `Remove the key ${args.fingerprint ?? '(given as a public key)'} of ${args.user ?? 'root'} in container ${args.vmid}?`,
      handler: async (args, ctx) => {
        if ((args.public_key === undefined) === (args.fingerprint === undefined)) throw new ProxmoxError('invalid_input', 'Pass exactly one of public_key and fingerprint.');
        const loc = await forWrite(ctx, args.vmid, args.node);
        const user = args.user ?? 'root';
        let blob: string | undefined;
        if (args.public_key) {
          blob = parsePublicKey(args.public_key).blob;
        } else {
          const listed = await runIn(ctx, loc, 'read', listKeysScript(user));
          assertRan(listed, 'Reading authorized keys', args.vmid);
          lookupFailure(listed, args.vmid);
          assertOk(listed, 'Reading authorized keys', args.vmid);
          if (listed.dry_run) return { vmid: args.vmid, node: loc.node, user, note: 'The key would be looked up by its fingerprint first, so the removal itself cannot be shown.' };
          const found = parseAuthorizedKeys(listed.stdout).keys.find((k) => k.fingerprint === args.fingerprint!.replace(/=+$/, ''));
          if (!found) return { vmid: args.vmid, node: loc.node, user, removed: 0 };
          blob = found.blob as string;
        }
        const res = await runIn(ctx, loc, 'write', removeKeyScript(user, blob));
        assertRan(res, 'Removing the key', args.vmid);
        lookupFailure(res, args.vmid);
        assertOk(res, 'Removing the key', args.vmid);
        if (res.dry_run) return { vmid: args.vmid, node: loc.node, user };
        return { vmid: args.vmid, node: loc.node, user, removed: Number(parseHeader(res.stdout).header.removed ?? 0) };
      },
    }),
    tool({
      name: 'pve_lxc_ssh_configure',
      title: 'Configure the SSH server in a container',
      description: 'Sets PermitRootLogin, PasswordAuthentication, PubkeyAuthentication and Port, in a drop-in or at the top of sshd_config. Applied only if sshd -t accepts it and sshd -T shows the values in force, then sshd is reloaded. On any failure the old configuration is put back.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      input: {
        ...guest,
        permit_root_login: z.enum(['yes', 'no', 'prohibit-password', 'forced-commands-only']).optional().describe('PermitRootLogin.'),
        password_authentication: z.boolean().optional().describe('PasswordAuthentication.'),
        pubkey_authentication: z.boolean().optional().describe('PubkeyAuthentication.'),
        port: z.number().int().min(1).max(65_535).optional().describe('Port.'),
      },
      confirmation: (args) => `Change the SSH server settings of container ${args.vmid}? This can lock out whoever logs in over SSH.`,
      handler: async (args, ctx) => {
        const settings = {
          ...(args.permit_root_login !== undefined ? { permitRootLogin: args.permit_root_login } : {}),
          ...(args.password_authentication !== undefined ? { passwordAuthentication: args.password_authentication } : {}),
          ...(args.pubkey_authentication !== undefined ? { pubkeyAuthentication: args.pubkey_authentication } : {}),
          ...(args.port !== undefined ? { port: args.port } : {}),
        };
        if (Object.keys(settings).length === 0) throw new ProxmoxError('invalid_input', 'Pass at least one setting to change.');
        const loc = await forWrite(ctx, args.vmid, args.node);
        const res = await runIn(ctx, loc, 'write', sshConfigureScript(settings));
        assertRan(res, 'Configuring SSH', args.vmid);
        sshConfigureFailure(res);
        assertOk(res, 'Configuring SSH', args.vmid);
        if (res.dry_run) return { vmid: args.vmid, node: loc.node };
        const { header, rest } = parseHeader(res.stdout);
        return { vmid: args.vmid, node: loc.node, layout: header.layout, reloaded: header.reloaded === 'yes', effective: rest.trim().split('\n'), untrusted: true };
      },
    }),
  ];
}
