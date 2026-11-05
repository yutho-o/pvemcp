import { randomUUID } from 'node:crypto';
import { existsSync, renameSync, rmSync, statSync } from 'node:fs';
import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import { resolveLocalPath } from '../proxmox/localpath.js';
import { deleteFileScript, EXIT_CD_FAILED, EXIT_NOT_FOUND, listDirScript, writeFileScript } from '../ssh/scripts.js';
import { sh, shRaw, type ExecResult, type ShellCommand, type SshTarget } from '../ssh/index.js';
import { pageRows, paging, tool, type ToolContext, type ToolDef } from './helpers.js';
import { assertOk, assertRan, execOptions, fileMode, fileOwner, maxOutputBytes, nodeTarget, parseLs, present, readRemoteFile, remotePath, statRemoteFile, targetNode, timeoutSeconds, unitName } from './ssh-common.js';

const identity = (script: string) => script;

/** A partial download is never left under the final name. */
export async function downloadTo(ctx: ToolContext, target: SshTarget, remote: string, local: string, timeoutMs?: number): Promise<void> {
  const part = `${local}.${randomUUID().slice(0, 8)}.part`;
  const sftp = await ctx.ssh.sftp(target, 'read');
  try {
    await sftp.fastGet(remote, part, timeoutMs !== undefined ? { timeoutMs } : {});
    renameSync(part, local);
  } finally {
    sftp.close();
    rmSync(part, { force: true });
  }
}

export function assertLocalTarget(local: string, overwrite: boolean | undefined, display: string): void {
  if (!existsSync(local)) return;
  if (statSync(local).isDirectory()) throw new ProxmoxError('local_path_refused', `${display} is a directory.`, { hint: 'Give the path of a file, not of the directory it goes in.' });
  if (!overwrite) throw new ProxmoxError('local_path_refused', `${display} already exists on this machine.`, { hint: 'Pass overwrite: true to replace it.' });
}

/** A fixed command, with its own status: one failing says nothing about the others. */
async function diagnostic(ctx: ToolContext, target: SshTarget, command: string, maxBytes: number): Promise<ExecResult> {
  return ctx.ssh.run(target, { text: command, access: 'read' }, { maxBytes });
}

const DIAGNOSTICS: Record<string, string> = {
  uptime: 'uptime',
  disk: 'df -hP',
  memory: 'free -m',
  zfs: 'zpool status -x',
  lvm: 'lvs --noheadings -o lv_name,vg_name,lv_size,data_percent,metadata_percent',
  cluster: 'pvecm status',
  failed_units: 'systemctl --failed --no-legend --no-pager',
  journal_errors: 'journalctl -p err -n 50 --no-pager -o short-iso -b',
};

const COMMANDS_MISSING = /(?:not found|No such file)/i;

function parsePctList(output: string): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  for (const line of output.split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (!/^\d+$/.test(fields[0] ?? '') || fields.length < 3) continue;
    rows.push({ vmid: Number(fields[0]), status: fields[1], ...(fields.length > 3 ? { lock: fields[2] } : {}), name: fields.at(-1) });
  }
  return rows;
}

function parseQmList(output: string): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  for (const line of output.split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (!/^\d+$/.test(fields[0] ?? '') || fields.length < 6) continue;
    const pid = Number(fields.at(-1));
    rows.push({ vmid: Number(fields[0]), name: fields.slice(1, -4).join(' '), status: fields.at(-4), memory_mb: Number(fields.at(-3)), bootdisk_gb: Number(fields.at(-2)), ...(pid ? { pid } : {}) });
  }
  return rows;
}

const WARNING_ROOT = 'This runs as root on the hypervisor: not a sandbox.';

/** SSH tools for the node itself. */
export function sshNodeTools(): ToolDef[] {
  return [
    tool({
      name: 'pve_ssh_test',
      title: 'Test SSH to a node',
      description: 'Connects to a node over SSH and reports the verified host key fingerprint, the user and pveversion. Shows why SSH does not work, if it does not.',
      domain: 'ssh',
      gate: 'ssh_read',
      idempotent: true,
      input: { node: targetNode },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const res = await ctx.ssh.run(target, { text: `hostname; id -un; pveversion 2>&1`, access: 'read' });
        assertRan(res, 'The SSH test');
        const [hostname, user, ...version] = res.stdout.split('\n');
        return { node: target.node, connected: true, hostname, user, pveversion: res.exit_code === 0 ? version.join('\n').trim() : null, host_key: res.host_key, duration_ms: res.duration_ms, untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_host_diagnostics',
      title: 'Node diagnostics over SSH',
      description: 'Uptime, disk, memory, zpool status, lvs, pvecm status, failed units and recent journal errors on a node. Each has its own status, so that one failing does not hide the others.',
      domain: 'ssh',
      gate: 'ssh_read',
      idempotent: true,
      input: { node: targetNode },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const names = Object.keys(DIAGNOSTICS);
        const outcomes = await Promise.allSettled(names.map((name) => diagnostic(ctx, target, DIAGNOSTICS[name]!, 128 * 1024)));
        // Not being able to connect at all is one failure, not eight.
        const refused = outcomes.find((o): o is PromiseRejectedResult => o.status === 'rejected' && o.reason instanceof ProxmoxError);
        if (refused && outcomes.every((o) => o.status === 'rejected')) throw refused.reason;
        const sections: Record<string, unknown> = {};
        outcomes.forEach((outcome, i) => {
          const name = names[i]!;
          if (outcome.status === 'rejected') {
            sections[name] = { ok: false, error: outcome.reason instanceof ProxmoxError ? `${outcome.reason.type}: ${outcome.reason.message}` : String(outcome.reason) };
            return;
          }
          const res = outcome.value;
          const absent = res.exit_code === 127 && COMMANDS_MISSING.test(res.stderr);
          sections[name] = { ok: res.exit_code === 0 && !res.timed_out, command: DIAGNOSTICS[name], exit_code: res.exit_code, output: res.stdout.trim(), ...(res.stderr.trim() ? { stderr: res.stderr.trim() } : {}), ...(absent ? { not_installed: true } : {}), ...(res.truncated ? { truncated: true } : {}), ...(res.timed_out ? { timed_out: true } : {}) };
        });
        return { node: target.node, sections, untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_journal',
      title: 'Read the journal of a node',
      description: 'journalctl on a node, optionally for one unit and since a time.',
      domain: 'ssh',
      gate: 'ssh_read',
      idempotent: true,
      input: {
        node: targetNode,
        unit: unitName.optional().describe('Only this unit, such as pveproxy or pvedaemon.'),
        lines: z.number().int().min(1).max(10_000).optional().describe('Last lines to show. Default 200.'),
        since: z.string().regex(/^(?:-\d+[a-z]+|[0-9A-Za-z][0-9A-Za-z :.+-]*)$/, 'Expected a time such as "2024-01-31 12:00", yesterday or -1h').max(64).optional().describe('Such as "2024-01-31 12:00", yesterday or -1h.'),
        priority: z.enum(['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']).optional().describe('This level and above.'),
      },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const parts = [sh`journalctl --no-pager -o short-iso -n ${args.lines ?? 200}`];
        if (args.unit) parts.push(sh`-u ${args.unit}`);
        if (args.since) parts.push(sh`${`--since=${args.since}`}`);
        if (args.priority) parts.push(sh`-p ${args.priority}`);
        const res = await ctx.ssh.run(target, { text: parts.join(' '), access: 'read' });
        assertOk(res, 'journalctl');
        return present(res, { node: target.node });
      },
    }),
    tool({
      name: 'pve_ssh_list_dir',
      title: 'List a directory on a node',
      description: 'ls -la on a node, as rows.',
      domain: 'ssh',
      gate: 'ssh_read',
      idempotent: true,
      input: { node: targetNode, path: remotePath, ...paging },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const res = await ctx.ssh.run(target, { text: listDirScript(args.path), access: 'read' });
        assertOk(res, `Listing ${args.path}`);
        return { node: target.node, path: args.path, ...pageRows(parseLs(res.stdout), args.page_limit, args.page_offset), ...(res.truncated ? { truncated_output: true } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_read_file',
      title: 'Read a file on a node',
      description: 'Reads a text file on a node, up to a size cap. Refuses well-known secrets such as /etc/pve/priv/*, /root/.ssh/id_* and /etc/shadow, also through a link, unless PROXMOX_ALLOW_SENSITIVE is on.',
      domain: 'ssh',
      gate: 'ssh_read',
      idempotent: true,
      input: {
        node: targetNode,
        path: remotePath,
        max_bytes: z.number().int().min(1).optional().describe('Largest file to return. Default and upper limit: PROXMOX_SSH_MAX_OUTPUT_BYTES.'),
        allow_partial: z.boolean().optional().describe('Return the start of a file over the limit, instead of an error.'),
      },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        return { node: target.node, ...(await readRemoteFile(ctx, target, identity, args)) };
      },
    }),
    tool({
      name: 'pve_ssh_pct_list',
      title: 'pct list on a node',
      description: 'The containers of a node as pct sees them, with their lock. The API has the same list without the lock: pve_list_lxcs.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_read',
      idempotent: true,
      input: { node: targetNode },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const res = await ctx.ssh.run(target, { text: 'pct list', access: 'read' });
        assertRan(res, 'pct list');
        assertOk(res, 'pct list');
        return { node: target.node, rows: parsePctList(res.stdout), untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_qm_list',
      title: 'qm list on a node',
      description: 'The VMs of a node as qm sees them, with their process id.',
      domain: 'ssh',
      also: ['vm'],
      gate: 'ssh_read',
      idempotent: true,
      input: { node: targetNode },
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const res = await ctx.ssh.run(target, { text: 'qm list', access: 'read' });
        assertOk(res, 'qm list');
        return { node: target.node, rows: parseQmList(res.stdout), untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_exec',
      title: 'Run a command on a node',
      description: `Runs any shell command on a node. ${WARNING_ROOT} The protected guest list does not apply to what a command does, and neither does any other policy of this server. A non-zero exit code is reported, not an error. Tell the user what you run.`,
      domain: 'ssh',
      gate: 'ssh_write',
      destructive: true,
      openWorld: true,
      input: {
        node: targetNode,
        command: z.string().min(1).describe('Shell text, as typed at a root prompt.'),
        stdin: z.string().optional().describe('Given to the command as its input. Never logged.'),
        cwd: remotePath.optional().describe('Run in this directory.'),
        timeout_seconds: timeoutSeconds,
        max_output_bytes: maxOutputBytes,
      },
      confirmation: (args) => `Run this as root on node ${args.node ?? '(default)'}?\n${args.command}`,
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const cmd: ShellCommand = { text: args.cwd ? sh`cd -- ${args.cwd} || exit ${EXIT_CD_FAILED}\n${shRaw(args.command)}` : args.command, access: 'write', ...(args.stdin !== undefined ? { stdin: args.stdin } : {}) };
        const res = await ctx.ssh.run(target, cmd, execOptions(args, ctx));
        assertRan(res, 'The command');
        return present(res, { node: target.node });
      },
    }),
    tool({
      name: 'pve_ssh_write_file',
      title: 'Write a file on a node',
      description: `Writes a file on a node, whole or not at all, keeping the mode and owner of an existing file unless told otherwise. ${WARNING_ROOT}`,
      domain: 'ssh',
      gate: 'ssh_write',
      destructive: true,
      input: {
        node: targetNode,
        path: remotePath,
        content: z.string().describe('The new content. Never logged.'),
        encoding: z.enum(['utf8', 'base64']).optional().describe('How content is written. Default utf8.'),
        mode: fileMode.optional().describe('Such as 0644.'),
        owner: fileOwner.optional().describe('user or user:group.'),
        backup: z.boolean().optional().describe('Keep the old file as path.bak.TIMESTAMP.'),
        create_parents: z.boolean().optional().describe('Create missing directories.'),
      },
      confirmation: (args) => `Write ${args.content.length} characters to ${args.path} on node ${args.node ?? '(default)'}, as root?`,
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const stdin = args.encoding === 'base64' ? Buffer.from(args.content, 'base64') : args.content;
        const script = writeFileScript(args.path, { ...(args.mode ? { mode: args.mode } : {}), ...(args.owner ? { owner: args.owner } : {}), ...(args.backup ? { backup: true } : {}), ...(args.create_parents ? { createParents: true } : {}) });
        const res = await ctx.ssh.run(target, { text: script, access: 'write', stdin, display: `write ${args.path} (content on stdin)` });
        assertOk(res, `Writing ${args.path}`);
        if (res.dry_run) return { node: target.node, path: args.path };
        const [bytes, backup] = res.stdout.split('\n');
        return { node: target.node, path: args.path, bytes: Number(bytes), ...(backup ? { backup } : {}) };
      },
    }),
    tool({
      name: 'pve_ssh_upload',
      title: 'Upload a local file to a node',
      description: 'Copies a file from this server, under PROXMOX_LOCAL_DIR only, to a node over SFTP. SFTP runs as the SSH user, without sudo.',
      domain: 'ssh',
      gate: 'ssh_write',
      destructive: true,
      input: {
        node: targetNode,
        local_path: z.string().min(1).describe('Relative to PROXMOX_LOCAL_DIR, or absolute under it.'),
        path: remotePath.describe('Where it goes on the node. An existing file is replaced.'),
        mode: fileMode.optional().describe('Default 0644.'),
        timeout_seconds: timeoutSeconds,
      },
      confirmation: (args) => `Copy ${args.local_path} to ${args.path} on node ${args.node ?? '(default)'}, replacing any file there?`,
      handler: async (args, ctx) => {
        const local = resolveLocalPath(ctx.instance.localDir, args.local_path, { mustExist: true });
        if (!statSync(local).isFile()) throw new ProxmoxError('local_path_refused', `${args.local_path} is not a regular file.`);
        const target = await nodeTarget(ctx, args.node);
        const sftp = await ctx.ssh.sftp(target, 'write');
        try {
          await sftp.fastPut(local, args.path, { mode: parseInt(args.mode ?? '0644', 8), ...(args.timeout_seconds ? { timeoutMs: args.timeout_seconds * 1000 } : {}) });
        } finally {
          sftp.close();
        }
        return { node: target.node, path: args.path, bytes: statSync(local).size };
      },
    }),
    tool({
      name: 'pve_ssh_download',
      title: 'Download a file from a node',
      description: 'Copies a file from a node to this server, under PROXMOX_LOCAL_DIR only, over SFTP. Refuses well-known secrets, as pve_ssh_read_file does. SFTP runs as the SSH user, without sudo.',
      domain: 'ssh',
      gate: 'ssh_write',
      input: {
        node: targetNode,
        path: remotePath.describe('The file on the node.'),
        local_path: z.string().min(1).describe('Relative to PROXMOX_LOCAL_DIR, or absolute under it. Its directory must exist.'),
        overwrite: z.boolean().optional().describe('Replace a local file that exists. Default false.'),
        timeout_seconds: timeoutSeconds,
      },
      handler: async (args, ctx) => {
        const local = resolveLocalPath(ctx.instance.localDir, args.local_path, { mustExist: false });
        assertLocalTarget(local, args.overwrite, args.local_path);
        const target = await nodeTarget(ctx, args.node);
        const stat = await statRemoteFile(ctx, target, identity, args.path);
        if (!stat) {
          ctx.dryRunLog.push({ ssh: { node: target.node, sftp: 'fastGet', path: args.path, access: 'read' } });
          return { node: target.node, path: args.path, local_path: local };
        }
        await downloadTo(ctx, target, stat.real, local, args.timeout_seconds ? args.timeout_seconds * 1000 : undefined);
        return { node: target.node, path: args.path, local_path: local, bytes: statSync(local).size };
      },
    }),
    tool({
      name: 'pve_ssh_delete_file',
      title: 'Delete a file on a node',
      description: `Deletes one file on a node. Not directories. ${WARNING_ROOT}`,
      domain: 'ssh',
      gate: 'ssh_write',
      destructive: true,
      input: {
        node: targetNode,
        path: remotePath,
        missing_ok: z.boolean().optional().describe('A file already gone is not an error.'),
      },
      confirmation: (args) => `Delete ${args.path} on node ${args.node ?? '(default)'}?`,
      handler: async (args, ctx) => {
        const target = await nodeTarget(ctx, args.node);
        const res = await ctx.ssh.run(target, { text: deleteFileScript(args.path, args.missing_ok === true), access: 'write' });
        assertRan(res, `Deleting ${args.path}`);
        if (res.exit_code === EXIT_NOT_FOUND || /No such file/i.test(res.stderr)) throw new ProxmoxError('not_found', `${args.path} does not exist.`);
        assertOk(res, `Deleting ${args.path}`);
        return { node: target.node, path: args.path, deleted: !res.dry_run };
      },
    }),
  ];
}
