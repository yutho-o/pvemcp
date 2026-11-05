import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig, type Env } from '../src/config.js';
import type { DryRunEntry, WriteRecord } from '../src/proxmox/client.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { ScopedSsh, sh, shQuote, shRaw, type ExecResult, type SftpSession, type ShellChannel, type ShellCommand, type SshTransport } from '../src/ssh/index.js';
import { ALL_GATES, closeAll, connect } from './harness.js';

/**
 * The gates of ScopedSsh, at the chokepoint and through a real MCP server. The transport here
 * is a recording stand-in: the real one has its own tests.
 */

// Stands in for the SSH tools to come: what matters here is what ctx.ssh does to them.
vi.mock('../src/tools/ssh-node.js', async () => {
  const { tool } = await vi.importActual<typeof import('../src/tools/helpers.js')>('../src/tools/helpers.js');
  const { z } = await vi.importActual<typeof import('zod')>('zod');
  return {
    ...(await vi.importActual<object>('../src/tools/ssh-node.js')),
    sshNodeTools: () => [
      tool({
        name: 'pve_test_ssh_read',
        title: 'Test',
        description: 'Runs a read command.',
        domain: 'ssh',
        gate: 'ssh_read',
        input: { access: z.enum(['read', 'write']).optional() },
        handler: async (args, ctx) => ({ ...(await ctx.ssh.run({ node: 'pve1' }, { text: 'uptime', access: args.access ?? 'read' })) }),
      }),
      tool({
        name: 'pve_test_ssh_write',
        title: 'Test',
        description: 'Runs a write command, with a payload.',
        domain: 'ssh',
        gate: 'ssh_write',
        destructive: true,
        input: { stdin: z.string() },
        handler: async (args, ctx) => ({ ...(await ctx.ssh.run({ node: 'pve1' }, { text: 'tee /tmp/x', access: 'write', stdin: args.stdin })) }),
      }),
    ],
  };
});

afterEach(closeAll);

const OK: ExecResult = { stdout: 'ran', stderr: '', exit_code: 0, truncated: false, duration_ms: 1, timed_out: false };

function recordingTransport() {
  const sftpCalls: string[] = [];
  const session: SftpSession = {
    readFile: async () => Buffer.from('content'),
    writeFile: async (path) => void sftpCalls.push(`writeFile ${path}`),
    fastPut: async (_l, remote) => void sftpCalls.push(`fastPut ${remote}`),
    fastGet: async (remote) => void sftpCalls.push(`fastGet ${remote}`),
    stat: async () => ({ size: 1, mode: 0o644, mtime: 0, isDirectory: false, isFile: true }),
    readdir: async () => [],
    unlink: async (path) => void sftpCalls.push(`unlink ${path}`),
    rename: async (from) => void sftpCalls.push(`rename ${from}`),
    chmod: async (path) => void sftpCalls.push(`chmod ${path}`),
    close: () => undefined,
  };
  const channel: ShellChannel = { write: () => undefined, onData: () => undefined, onClose: () => undefined, close: () => undefined };
  const commands: ShellCommand[] = [];
  const shells: unknown[] = [];
  const transport: SshTransport = {
    exec: async (_target, command) => {
      commands.push(command);
      return OK;
    },
    sftp: async () => session,
    shell: async (_target, opts) => {
      shells.push(opts);
      return channel;
    },
    close: () => undefined,
  };
  return { transport, commands, shells, sftpCalls };
}

function scoped(env: Env, scope: { readOnly?: boolean; dryRun?: boolean } = {}) {
  const config = loadConfig({ PROXMOX_URL: 'https://192.0.2.1', PROXMOX_TOKEN: 'a@pve!t=s', PROXMOX_SSH_PASSWORD: 'x', ...env });
  const rec = recordingTransport();
  const dryRunLog: DryRunEntry[] = [];
  const audited: WriteRecord[] = [];
  const factory = vi.fn(() => rec.transport);
  const ssh = new ScopedSsh(config.instances.get('default')!, factory, {
    readOnly: scope.readOnly ?? false,
    dryRun: scope.dryRun ?? false,
    dryRunLog,
    onCommand: (e) => audited.push(e),
  });
  return { ssh, ...rec, dryRunLog, audited, factory };
}

async function typeOf(run: Promise<unknown>): Promise<string> {
  const err = await run.then(() => new Error('expected a refusal'), (e: unknown) => e);
  if (err instanceof ProxmoxError) return err.type;
  throw err;
}

const READ: ShellCommand = { text: 'uptime', access: 'read' };
const WRITE: ShellCommand = { text: 'reboot', access: 'write' };
const SSH_ON = { PROXMOX_ALLOW_SSH: 'true' };
const SSH_WRITES = { PROXMOX_ALLOW_SSH: 'true', PROXMOX_ALLOW_WRITES: 'true' };

describe('shQuote', () => {
  it('leaves nothing special inside the quotes', () => {
    expect(shQuote('plain')).toBe(`'plain'`);
    expect(shQuote('a b')).toBe(`'a b'`);
    expect(shQuote(`it's`)).toBe(`'it'\\''s'`);
    expect(shQuote('$(reboot); `id` | x > y')).toBe(`'$(reboot); \`id\` | x > y'`);
    expect(shQuote('-rf')).toBe(`'-rf'`);
    expect(shQuote('')).toBe(`''`);
    expect(shQuote(100)).toBe(`'100'`);
  });

  it('refuses NUL, which would cut the argument short', () => {
    expect(() => shQuote('a\0b')).toThrow(ProxmoxError);
  });
});

describe('the sh tag', () => {
  it('quotes every interpolation', () => {
    expect(sh`pct exec ${100} -- cat ${'/etc/os release; id'}`).toBe(`pct exec '100' -- cat '/etc/os release; id'`);
  });

  it('turns an array into several quoted words', () => {
    expect(sh`apt-get install -y -- ${['curl', 'a b']}`).toBe(`apt-get install -y -- 'curl' 'a b'`);
    expect(sh`x ${[]}`).toBe('x ');
  });

  it('inserts only what is marked raw, as it is', () => {
    expect(sh`${shRaw('cd /tmp &&')} ls ${'$HOME'}`).toBe(`cd /tmp && ls '$HOME'`);
    const inner = sh`echo ${'a;b'}`;
    expect(sh`sudo -n ${shRaw(inner)}`).toBe(`sudo -n echo 'a;b'`);
  });

  it('does not survive an injection attempt: the result stays one word', () => {
    const attack = `'; rm -rf / #`;
    expect(sh`cat ${attack}`).toBe(`cat ''\\''; rm -rf / #'`);
  });

  it('refuses NUL through any route', () => {
    expect(() => sh`x ${'a\0'}`).toThrow(ProxmoxError);
    expect(() => sh`x ${['a\0']}`).toThrow(ProxmoxError);
  });
});

describe('ScopedSsh gates', () => {
  it('refuses everything when SSH is off, whatever else is allowed, without touching the transport', async () => {
    const { ssh, factory } = scoped({ PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true' });
    expect(await typeOf(ssh.run({ node: 'pve1' }, READ))).toBe('ssh_disabled');
    expect(await typeOf(ssh.run({ node: 'pve1' }, WRITE))).toBe('ssh_disabled');
    expect(await typeOf(ssh.sftp({ node: 'pve1' }))).toBe('ssh_disabled');
    expect(await typeOf(ssh.shell({ node: 'pve1' }))).toBe('ssh_disabled');
    expect(factory).not.toHaveBeenCalled();
  });

  it('runs a read with SSH on, and logs nothing for the audit', async () => {
    const { ssh, commands, audited } = scoped(SSH_ON);
    expect((await ssh.run({ node: 'pve1' }, READ)).stdout).toBe('ran');
    expect(commands).toEqual([READ]);
    expect(audited).toEqual([]);
  });

  it('needs writes for a write', async () => {
    const { ssh, commands } = scoped(SSH_ON);
    expect(await typeOf(ssh.run({ node: 'pve1' }, WRITE))).toBe('write_disabled');
    expect(commands).toEqual([]);
  });

  it('refuses a write from a read tool, with every gate open', async () => {
    const { ssh, commands, factory } = scoped(SSH_WRITES, { readOnly: true });
    expect(await typeOf(ssh.run({ node: 'pve1' }, WRITE))).toBe('not_read_only');
    expect(await typeOf(ssh.shell({ node: 'pve1' }))).toBe('not_read_only');
    expect(await typeOf(ssh.sftp({ node: 'pve1' }, 'write'))).toBe('not_read_only');
    expect(commands).toEqual([]);
    expect(factory).not.toHaveBeenCalled();
    expect((await ssh.run({ node: 'pve1' }, READ)).stdout).toBe('ran');
  });

  it('records a write for the audit, with display instead of the text and only a digest of stdin', async () => {
    const { ssh, audited, commands } = scoped(SSH_WRITES);
    const stdin = 'root:hunter22';
    await ssh.run({ node: 'pve1' }, { text: 'chpasswd --secret', access: 'write', stdin, display: 'chpasswd', });
    expect(commands[0]!.stdin).toBe(stdin);
    expect(audited).toEqual([{ status: 'sent', ssh: { node: 'pve1', command: 'chpasswd', stdin: { bytes: stdin.length, sha256: createHash('sha256').update(stdin).digest('hex') } } }]);
    expect(JSON.stringify(audited)).not.toContain('hunter22');
  });

  it('refuses a command holding NUL', async () => {
    const { ssh, commands } = scoped(SSH_ON);
    expect(await typeOf(ssh.run({ node: 'pve1' }, { text: 'a\0b', access: 'read' }))).toBe('invalid_input');
    expect(commands).toEqual([]);
  });
});

describe('ScopedSsh dry run', () => {
  it('logs and does not connect, even without allowWrites', async () => {
    const { ssh, dryRunLog, factory } = scoped(SSH_ON, { dryRun: true });
    const res = await ssh.run({ node: 'pve1' }, { text: 'tee /etc/x', access: 'write', stdin: Buffer.from('payload'), display: 'write /etc/x' });
    expect(res).toMatchObject({ dry_run: true, exit_code: 0, stdout: '' });
    expect(factory).not.toHaveBeenCalled();
    expect(dryRunLog).toEqual([{ ssh: { node: 'pve1', command: 'write /etc/x', access: 'write', stdin: { bytes: 7, sha256: createHash('sha256').update('payload').digest('hex') } } }]);
    expect(JSON.stringify(dryRunLog)).not.toContain('payload');
  });

  it('still refuses when SSH is off', async () => {
    const { ssh, dryRunLog } = scoped({}, { dryRun: true });
    expect(await typeOf(ssh.run({ node: 'pve1' }, WRITE))).toBe('ssh_disabled');
    expect(dryRunLog).toEqual([]);
  });

  it('logs SFTP writes, refuses SFTP reads, and opens no session', async () => {
    const { ssh, dryRunLog, factory } = scoped(SSH_ON, { dryRun: true });
    const sftp = await ssh.sftp({ node: 'pve1' }, 'write');
    await sftp.writeFile('/tmp/x', 'secret-content');
    await sftp.unlink('/tmp/y');
    expect(await typeOf(sftp.readFile('/tmp/x'))).toBe('invalid_input');
    expect(factory).not.toHaveBeenCalled();
    expect(dryRunLog).toHaveLength(2);
    expect(JSON.stringify(dryRunLog)).not.toContain('secret-content');
  });

  it('opens no interactive session', async () => {
    const { ssh, shells, dryRunLog } = scoped(SSH_ON, { dryRun: true });
    expect(await typeOf(ssh.shell({ node: 'pve1' }, { command: 'pct enter 100' }))).toBe('invalid_input');
    expect(shells).toEqual([]);
    expect(dryRunLog).toHaveLength(1);
  });
});

describe('ScopedSsh sftp and shell', () => {
  it('lets a read session read, and stops it from writing', async () => {
    const { ssh, sftpCalls, audited } = scoped(SSH_WRITES);
    const sftp = await ssh.sftp({ node: 'pve1' });
    expect((await sftp.readFile('/etc/hostname')).toString()).toBe('content');
    expect(await typeOf(sftp.writeFile('/tmp/x', 'y'))).toBe('not_read_only');
    expect(await typeOf(sftp.unlink('/tmp/x'))).toBe('not_read_only');
    expect(sftpCalls).toEqual([]);
    expect(audited).toEqual([]);
  });

  it('audits what a write session changes', async () => {
    const { ssh, sftpCalls, audited } = scoped(SSH_WRITES);
    const sftp = await ssh.sftp({ node: 'pve1' }, 'write');
    await sftp.writeFile('/tmp/x', 'y');
    await sftp.chmod('/tmp/x', 0o600);
    expect(sftpCalls).toEqual(['writeFile /tmp/x', 'chmod /tmp/x']);
    expect(audited.map((a) => a.ssh)).toEqual([{ node: 'pve1', sftp: 'writeFile', path: '/tmp/x' }, { node: 'pve1', sftp: 'chmod', path: '/tmp/x' }]);
  });

  it('needs write access for a shell, and audits it', async () => {
    const closed = scoped(SSH_ON);
    expect(await typeOf(closed.ssh.shell({ node: 'pve1' }))).toBe('write_disabled');
    const open = scoped(SSH_WRITES);
    await open.ssh.shell({ node: 'pve1' }, { command: 'pct enter 100' });
    expect(open.shells).toEqual([{ command: 'pct enter 100' }]);
    expect(open.audited[0]!.ssh).toEqual({ node: 'pve1', command: 'pct enter 100', pty: true });
  });
});

describe('ctx.ssh through a real MCP server', () => {
  const env = { ...ALL_GATES };

  it('hides SSH tools until SSH is allowed, and write tools until writes are', async () => {
    const off = await connect({ env: { PROXMOX_ALLOW_WRITES: 'true' } });
    const hidden = await off.toolNames();
    expect(hidden).not.toContain('pve_test_ssh_read');
    expect(hidden).not.toContain('pve_test_ssh_write');

    const read = await connect({ env: { PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_PASSWORD: 'x' } });
    const names = await read.toolNames();
    expect(names).toContain('pve_test_ssh_read');
    expect(names).not.toContain('pve_test_ssh_write');
  });

  it('runs through the transport of the runtime, created once and lazily', async () => {
    const rec = recordingTransport();
    const factory = vi.fn(() => rec.transport);
    const { call } = await connect({ env, runtime: { sshTransport: factory } });
    expect(factory).not.toHaveBeenCalled();
    expect((await call('pve_test_ssh_read')).data.stdout).toBe('ran');
    await call('pve_test_ssh_read');
    expect(factory).toHaveBeenCalledTimes(1);
    expect(rec.commands).toHaveLength(2);
  });

  it('refuses a write from a read tool', async () => {
    const rec = recordingTransport();
    const { call } = await connect({ env, runtime: { sshTransport: () => rec.transport } });
    const res = await call('pve_test_ssh_read', { access: 'write' });
    expect(res.data.error_type).toBe('not_read_only');
    expect(rec.commands).toEqual([]);
  });

  it('shows a dry run in would_send, and does not connect', async () => {
    const factory = vi.fn(() => recordingTransport().transport);
    const { call } = await connect({ env, runtime: { sshTransport: factory } });
    const res = await call('pve_test_ssh_write', { stdin: 'top-secret', dry_run: true });
    expect(res.isError).toBe(false);
    expect(res.data.dry_run).toBe(true);
    expect(res.data.would_send[0].ssh).toMatchObject({ node: 'pve1', command: 'tee /tmp/x', access: 'write', stdin: { bytes: 10 } });
    expect(res.text).not.toContain('top-secret');
    expect(factory).not.toHaveBeenCalled();
  });

  it('asks a human first, and audits the command without its stdin', async () => {
    const { mkdtempSync, readFileSync, rmSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-ssh-'));
    try {
      const file = join(dir, 'audit.log');
      const rec = recordingTransport();
      let asked = 0;
      const { call } = await connect({
        env: { ...env, PROXMOX_AUDIT_LOG: file },
        runtime: { sshTransport: () => rec.transport },
        onElicit: () => {
          asked++;
          return { action: 'accept', content: { confirm: true } };
        },
      });
      expect((await call('pve_test_ssh_write', { stdin: 'top-secret' })).isError).toBe(false);
      expect(asked).toBe(1);
      expect(rec.commands[0]!.stdin).toBe('top-secret');
      const text = await vi.waitFor(() => {
        const content = readFileSync(file, 'utf8');
        expect(content).toContain('pve_test_ssh_write');
        return content;
      });
      expect(text).not.toContain('top-secret');
      const entry = JSON.parse(text.trim().split('\n').at(-1)!) as { args: { stdin: string }; writes: Array<{ ssh: { command: string } }> };
      expect(entry.args.stdin).toBe('[REDACTED]');
      expect(entry.writes[0]!.ssh.command).toBe('tee /tmp/x');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
