import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import type { Runtime } from '../runtime.js';
import { sh } from '../ssh/index.js';
import { SshSessions } from '../ssh/sessions.js';
import { nodeName, tool, vmid, type ToolDef } from './helpers.js';
import { assertWritable, locateLxc, pctFailure } from './ssh-common.js';

/** One manager per server, closed with it. In HTTP mode a session outlives the request that opened it. */
export function sessionsOf(runtime: Runtime): SshSessions {
  const sessions = runtime.state('ssh-sessions', () => new SshSessions());
  runtime.state('ssh-sessions-hook', () => runtime.onShutdown(() => sessions.closeAll()));
  return sessions;
}

const KEYS: Record<string, string> = {
  'ctrl-a': '\x01',
  'ctrl-b': '\x02',
  'ctrl-c': '\x03',
  'ctrl-d': '\x04',
  'ctrl-e': '\x05',
  'ctrl-k': '\x0b',
  'ctrl-l': '\x0c',
  'ctrl-r': '\x12',
  'ctrl-u': '\x15',
  'ctrl-w': '\x17',
  'ctrl-x': '\x18',
  'ctrl-z': '\x1a',
  enter: '\r',
  tab: '\t',
  esc: '\x1b',
  backspace: '\x7f',
  up: '\x1b[A',
  down: '\x1b[B',
  right: '\x1b[C',
  left: '\x1b[D',
  home: '\x1b[H',
  end: '\x1b[F',
  'page-up': '\x1b[5~',
  'page-down': '\x1b[6~',
};
const KEY_NAMES = Object.keys(KEYS) as [string, ...string[]];

/** How long open waits for the first output, and for pct to say the container is not running. */
const OPEN_WAIT_MS = 400;

const sessionId = z.string().regex(/^[a-f0-9-]{1,36}$/, 'Expected a session id').describe('From pve_ssh_session_open.');

/** PTY sessions, for what only works interactively. */
export function sshSessionTools(): ToolDef[] {
  return [
    tool({
      name: 'pve_ssh_session_open',
      title: 'Open an interactive terminal',
      description: 'Opens a terminal: a root shell on a node, or with vmid, pct enter into a container. For interactive programs only: pve_ssh_exec and pve_lxc_exec suit everything else better. This is root on the hypervisor, or in the container, and no policy of this server applies to what is typed. At most 8 at a time, closed after 15 minutes of not being used.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      destructive: true,
      openWorld: true,
      input: {
        node: nodeName.optional().describe('Node for a shell. Default: PROXMOX_DEFAULT_NODE, or the only node. With vmid, checked if given.'),
        vmid: vmid.optional().describe('A container to enter, instead of a shell on the node.'),
        cols: z.number().int().min(10).max(1000).optional().describe('Default 120.'),
        rows: z.number().int().min(5).max(1000).optional().describe('Default 40.'),
        term: z.string().regex(/^[a-zA-Z0-9._-]+$/, 'Expected a terminal type').max(64).optional().describe('Default xterm.'),
      },
      confirmation: (args) => (args.vmid !== undefined ? `Open a root terminal in container ${args.vmid}?` : `Open a root terminal on node ${args.node ?? '(default)'}?`),
      handler: async (args, ctx) => {
        const sessions = sessionsOf(ctx.runtime);
        let node = args.node;
        if (args.vmid !== undefined) {
          assertWritable(ctx, args.vmid);
          node = (await locateLxc(ctx, args.vmid, args.node)).node;
        } else {
          node ??= await ctx.nodes.defaultNode();
        }
        sessions.assertRoom();
        const command = args.vmid !== undefined ? sh`pct enter ${args.vmid}` : undefined;
        const channel = await ctx.ssh.shell({ node: node! }, { ...(command ? { command } : {}), ...(args.cols ? { cols: args.cols } : {}), ...(args.rows ? { rows: args.rows } : {}), ...(args.term ? { term: args.term } : {}) });
        const session = sessions.add(ctx.instance.name, node!, args.vmid, command ?? '(login shell)', channel);
        await session.waitForOutput(OPEN_WAIT_MS);
        const { output } = session.read();
        if (session.closedWith) {
          sessions.remove(session.id);
          const failure = pctFailure({ stdout: '', stderr: output.replace(/\r/g, ''), exit_code: session.closedWith.code, truncated: false, duration_ms: 0, timed_out: false }, args.vmid);
          if (failure) throw failure;
          throw new ProxmoxError('upstream_error', `The terminal closed right away: ${output.trim().slice(0, 500)}`, { details: { exit_code: session.closedWith.code, untrusted: true } });
        }
        return { session: session.id, node, ...(args.vmid !== undefined ? { vmid: args.vmid } : {}), output, next_step: 'pve_ssh_session_send', untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_session_send',
      title: 'Type into a terminal',
      description: 'Sends text and control keys to an open terminal, as if typed. A line runs only with enter at the end of it: put "\\n" in input, or enter in keys. Nothing here is checked: this is a root terminal.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      // Announced as destructive, but opening the session is what a human confirms: not every key press.
      destructiveWhen: () => false,
      openWorld: true,
      input: {
        session: sessionId,
        input: z.string().max(1_048_576).optional().describe('Text to type. Never logged.'),
        keys: z.array(z.enum(KEY_NAMES)).max(256).optional().describe('Keys to press after the text, such as ["ctrl-c"].'),
        cols: z.number().int().min(10).max(1000).optional().describe('Resize the terminal.'),
        rows: z.number().int().min(5).max(1000).optional().describe('Resize the terminal.'),
      },
      handler: async (args, ctx) => {
        const session = sessionsOf(ctx.runtime).get(args.session, ctx.instance.name);
        const data = (args.input ?? '') + (args.keys ?? []).map((k) => KEYS[k]).join('');
        if (ctx.dryRun) {
          ctx.dryRunLog.push({ ssh: { node: session.node, command: `(session ${session.id}: ${Buffer.byteLength(data)} bytes)`, access: 'write' } });
          return { session: session.id, sent_bytes: 0 };
        }
        if (args.cols !== undefined && args.rows !== undefined) session.resize(args.cols, args.rows);
        if (data) {
          session.send(data);
          ctx.runtime.recordWrite(ctx.instance.name, { status: 'sent', ssh: { node: session.node, session: session.id, bytes: Buffer.byteLength(data) } });
        }
        return { session: session.id, sent_bytes: Buffer.byteLength(data), next_step: 'pve_ssh_session_read' };
      },
    }),
    tool({
      name: 'pve_ssh_session_read',
      title: 'Read from a terminal',
      description: 'What a terminal printed since the last read, without escape sequences. Up to 1 MiB is kept: dropped_bytes says if older output was lost. closed is true once the program has ended.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: {
        session: sessionId,
        wait_ms: z.number().int().min(0).max(60_000).optional().describe('If there is nothing yet, wait this long for output. Default 500.'),
      },
      handler: async (args, ctx) => {
        const sessions = sessionsOf(ctx.runtime);
        const session = sessions.get(args.session, ctx.instance.name);
        await session.waitForOutput(args.wait_ms ?? 500);
        const { output, dropped_bytes } = session.read();
        const closed = session.closedWith;
        if (closed) sessions.remove(session.id);
        return { session: session.id, output, ...(dropped_bytes > 0 ? { dropped_bytes } : {}), closed: closed !== undefined, ...(closed ? { exit_code: closed.code } : {}), untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_session_close',
      title: 'Close a terminal',
      description: 'Closes a terminal, and what runs in it gets a hangup. Any output not yet read is returned.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      input: { session: sessionId },
      handler: async (args, ctx) => {
        const sessions = sessionsOf(ctx.runtime);
        const session = sessions.get(args.session, ctx.instance.name);
        if (ctx.dryRun) {
          ctx.dryRunLog.push({ ssh: { node: session.node, command: `(close session ${session.id})`, access: 'write' } });
          return { session: session.id };
        }
        const { output } = session.read();
        if (!session.closedWith) session.close();
        sessions.remove(session.id);
        ctx.runtime.recordWrite(ctx.instance.name, { status: 'sent', ssh: { node: session.node, session: session.id, closed: true } });
        return { session: session.id, closed: true, output, untrusted: true };
      },
    }),
    tool({
      name: 'pve_ssh_session_list',
      title: 'List open terminals',
      description: 'The terminals opened with pve_ssh_session_open.',
      domain: 'ssh',
      also: ['lxc'],
      gate: 'ssh_write',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => ({ rows: sessionsOf(ctx.runtime).list(ctx.instance.name) }),
    }),
  ];
}
