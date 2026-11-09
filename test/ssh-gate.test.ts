import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { closeAll, connect } from './harness.js';
import { closeSsh, connectSsh } from './ssh-harness.js';

/**
 * The gates of ctx.ssh through a real MCP server and a real SSH handshake.
 *
 * The gates of ScopedSsh at the chokepoint (SSH off, writes, read tools that try to write, the
 * audit record and its stdin digest, NUL, dry run, SFTP and shell sessions) are checked over a
 * recording transport in src/ssh/gate_tests.rs; shell quoting and the sh! macro in src/ssh/quote.rs.
 */

afterEach(async () => {
  await closeSsh();
  await closeAll();
});

const TEST_COMMAND = 'hostname; id -un; pveversion 2>&1';

describe('ctx.ssh through a real MCP server', () => {
  it('hides SSH tools until SSH is allowed, and write tools until writes are', async () => {
    const off = await connect({ env: { PROXMOX_ALLOW_WRITES: 'true' } });
    const hidden = await off.toolNames();
    expect(hidden).not.toContain('pve_ssh_test');
    expect(hidden).not.toContain('pve_ssh_exec');

    const read = await connect({ env: { PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_PASSWORD: 'x' } });
    const names = await read.toolNames();
    expect(names).toContain('pve_ssh_test');
    expect(names).not.toContain('pve_ssh_exec');
  });

  it('runs through one transport, created lazily', async () => {
    const h = await connectSsh();
    h.ssh.on(TEST_COMMAND, { stdout: 'pve1\nroot\npve-manager/9.1.0\n' });
    expect(h.ssh.connections).toBe(0);
    expect((await h.call('pve_ssh_test', { node: 'pve1' })).data.hostname).toBe('pve1');
    await h.call('pve_ssh_test', { node: 'pve1' });
    expect(h.ssh.connections).toBe(1);
    expect(h.ssh.commands).toHaveLength(2);
  });

  it('shows a dry run in would_send, and does not connect', async () => {
    const h = await connectSsh();
    const res = await h.call('pve_ssh_exec', { node: 'pve1', command: 'tee /tmp/x', stdin: 'top-secret', dry_run: true });
    expect(res.isError).toBe(false);
    expect(res.data.dry_run).toBe(true);
    expect(res.data.would_send[0].ssh).toMatchObject({ node: 'pve1', command: 'tee /tmp/x', access: 'write', stdin: { bytes: 10 } });
    expect(res.text).not.toContain('top-secret');
    expect(h.ssh.connections).toBe(0);
    expect(h.ssh.authAttempts).toEqual([]);
  });

  it('asks a human first, and audits the command without its stdin', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-ssh-'));
    try {
      const file = join(dir, 'audit.log');
      let asked = 0;
      const h = await connectSsh({
        env: { PROXMOX_AUDIT_LOG: file },
        onElicit: () => {
          asked++;
          return { action: 'accept', content: { confirm: true } };
        },
      });
      h.ssh.on('tee /tmp/x', { stdout: '' });
      expect((await h.call('pve_ssh_exec', { node: 'pve1', command: 'tee /tmp/x', stdin: 'top-secret' })).isError).toBe(false);
      expect(asked).toBe(1);
      expect(h.ssh.commands[0]!.command).toBe('tee /tmp/x');
      expect(h.ssh.commands[0]!.stdin.toString()).toBe('top-secret');
      const text = await vi.waitFor(() => {
        const content = readFileSync(file, 'utf8');
        expect(content).toContain('pve_ssh_exec');
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
