import { createServer, type Server as NetServer, type AddressInfo } from 'node:net';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FAKE_SSH_PASSWORD, FakeSsh, generateKey, ShellSandbox } from './fake-ssh.js';
import { closeSsh, connectSsh, POSIX_SHELL, tempDir, type SshHarness } from './ssh-harness.js';

/**
 * The real transport of the binary against a real SSH server, driven through the SSH tools: every
 * way a connection or a command can go. Timings the operator cannot set (idle time, channels at a
 * time, connect timeout, grace before closing a timed out channel) come from PVEMCP_TEST_SSH_TRANSPORT.
 */

afterEach(closeSsh);

const started: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const stop of started.splice(0)) await stop().catch(() => undefined);
});

interface Tuning {
  idleMs?: number;
  maxChannels?: number;
  connectTimeoutMs?: number;
  killGraceMs?: number;
}

async function start(options: ConstructorParameters<typeof FakeSsh>[0] = {}): Promise<FakeSsh> {
  const ssh = new FakeSsh(options);
  await ssh.start();
  started.push(() => ssh.stop());
  return ssh;
}

/** The binary, with SSH to this server for node pve1. A known host, checked strictly. */
function serverFor(ssh: FakeSsh, env: Record<string, string> = {}, tuning?: Tuning): Promise<SshHarness> {
  return connectSsh({ server: ssh, env: { ...env, ...(tuning ? { PVEMCP_TEST_SSH_TRANSPORT: JSON.stringify(tuning) } : {}) } });
}

/** The binary, with SSH to a port that is no SSH server: there is no host key to know. */
function serverForPort(port: number, tuning?: Tuning): Promise<SshHarness> {
  return connectSsh({
    server: { port } as unknown as FakeSsh,
    unknownHost: true,
    env: { PROXMOX_SSH_HOST_KEY_POLICY: 'off', ...(tuning ? { PVEMCP_TEST_SSH_TRANSPORT: JSON.stringify(tuning) } : {}) },
  });
}

const exec = (h: SshHarness, command: string, extra: Record<string, unknown> = {}) => h.call('pve_ssh_exec', { node: 'pve1', command, ...extra });

async function listen(server: NetServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  started.push(async () => {
    server.close();
  });
  return (server.address() as AddressInfo).port;
}

describe('the default transport', () => {
  it('completes a real handshake against a strictly checked known host', async () => {
    const ssh = await start();
    ssh.on('echo hi', { stdout: 'hi\n' });
    const res = await exec(await serverFor(ssh), 'echo hi');
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ stdout: 'hi\n', exit_code: 0, timed_out: false, truncated: false });
  });
});

describe('connection failures, each with its own type', () => {
  it('ssh_unreachable when nothing listens', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const { port } = closed.address() as AddressInfo;
    await new Promise((resolve) => closed.close(resolve));
    const res = await exec(await serverForPort(port), 'id');
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.error).toContain('ECONNREFUSED');
    expect(res.data.hint).toContain('PROXMOX_SSH_NODES');
  });

  it('ssh_timeout when a host accepts and then says nothing', async () => {
    const port = await listen(createServer(() => undefined));
    const h = await serverForPort(port, { connectTimeoutMs: 300 });
    const startedAt = Date.now();
    const res = await exec(h, 'id');
    expect(res.data.error_type).toBe('ssh_timeout');
    expect(Date.now() - startedAt).toBeLessThan(5000);
  });

  it('ssh_unreachable when a host drops the connection during the handshake', async () => {
    const port = await listen(createServer((socket) => socket.destroy()));
    expect((await exec(await serverForPort(port), 'id')).data.error_type).toBe('ssh_unreachable');
  });

  it('ssh_auth_failed on a wrong password, and no retry in a loop', async () => {
    const ssh = await start();
    const res = await exec(await serverFor(ssh, { PROXMOX_SSH_PASSWORD: 'wrong-password' }), 'id');
    expect(res.data.error_type).toBe('ssh_auth_failed');
    expect(res.text).not.toContain('wrong-password');
    expect(res.data.hint).toContain('Do not retry');
    expect(ssh.commands).toEqual([]);
    expect(ssh.connections).toBe(1);
  });

  it('ssh_auth_failed on an unknown user', async () => {
    const ssh = await start();
    expect((await exec(await serverFor(ssh, { PROXMOX_SSH_USER: 'nobody' }), 'id')).data.error_type).toBe('ssh_auth_failed');
  });

  it('ssh_auth_failed when a key needs a passphrase that was not given', async () => {
    const key = generateKey('ed25519', { passphrase: 'correct horse' });
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    const res = await exec(await serverFor(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id');
    expect(res.data.error_type).toBe('ssh_auth_failed');
    expect(res.data.hint).toContain('passphrase');
  });

  it('config_error when a key file goes missing after startup', async () => {
    const ssh = await start();
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, generateKey().private);
    const h = await serverFor(ssh, { PROXMOX_SSH_KEY_FILE: file });
    rmSync(file);
    expect((await exec(h, 'id')).data.error_type).toBe('config_error');
  });

  it('ssh_unreachable when the host refuses channels: nothing was run', async () => {
    const ssh = await start({ refuseChannels: true });
    const res = await exec(await serverFor(ssh), 'id');
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.hint).toContain('Nothing was run');
  });
});

describe('a host short of session slots', () => {
  it('waits and tries again, since nothing ran', async () => {
    const ssh = await start({ refuseFirstChannels: 3 });
    ssh.on('x', { stdout: 'y' });
    expect((await exec(await serverFor(ssh), 'x')).data.stdout).toBe('y');
    expect(ssh.commands).toHaveLength(1);
    expect(ssh.connections).toBe(1);
  });

  it('does the same for SFTP', async () => {
    const root = tempDir();
    const ssh = await start({ refuseFirstChannels: 2, sftpRoot: root });
    const h = await serverFor(ssh);
    writeFileSync(join(h.localDir, 'f.txt'), 'x');
    const res = await h.call('pve_ssh_upload', { node: 'pve1', local_path: 'f.txt', path: '/f' });
    expect(res.isError).toBe(false);
    expect(readFileSync(join(root, 'f'), 'utf8')).toBe('x');
  });

  it('gives up after a few seconds, saying nothing ran', async () => {
    const ssh = await start({ refuseChannels: true });
    const h = await serverFor(ssh);
    const startedAt = Date.now();
    const res = await exec(h, 'x');
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.error).toContain('refused');
    expect(Date.now() - startedAt).toBeLessThan(6000);
  });
});

describe('authentication', () => {
  it('uses a private key, with real signature verification', async () => {
    const key = generateKey();
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    ssh.on('id', { stdout: 'root\n' });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    expect((await exec(await serverFor(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id')).data.stdout).toBe('root\n');
    expect(ssh.authAttempts.at(-1)).toMatchObject({ method: 'publickey' });
  });

  it('uses an encrypted private key with its passphrase', async () => {
    const passphrase = 'correct horse';
    const key = generateKey('ed25519', { passphrase });
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    ssh.on('id', { stdout: 'root\n' });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    const h = await serverFor(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_KEY_PASSPHRASE: passphrase, PROXMOX_SSH_PASSWORD: '' });
    expect((await exec(h, 'id')).data.stdout).toBe('root\n');
  });

  it('refuses another key', async () => {
    const ssh = await start({ users: { root: { keys: [generateKey().public] } } });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, generateKey().private);
    expect((await exec(await serverFor(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id')).data.error_type).toBe('ssh_auth_failed');
  });

  it('answers a keyboard-interactive prompt with the password, as PAM setups require', async () => {
    const ssh = await start({ users: { root: { password: FAKE_SSH_PASSWORD, keyboardOnly: true } } });
    ssh.on('id', { stdout: 'root\n' });
    expect((await exec(await serverFor(ssh), 'id')).data.stdout).toBe('root\n');
    expect(ssh.authAttempts.at(-1)).toMatchObject({ method: 'keyboard-interactive', password: FAKE_SSH_PASSWORD });
  });
});

describe('commands', () => {
  it('reports stdout, stderr, the exit code and the duration', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'out', stderr: 'err', code: 3 });
    const res = await exec(await serverFor(ssh), 'x');
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ stdout: 'out', stderr: 'err', exit_code: 3, truncated: false, timed_out: false });
    expect(res.data.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('reports the host key it verified', async () => {
    const ssh = await start();
    ssh.on('hostname; id -un; pveversion 2>&1', { stdout: 'pve1\nroot\npve-manager/9.1.0\n' });
    const res = await (await serverFor(ssh)).call('pve_ssh_test', { node: 'pve1' });
    expect(res.data.host_key).toEqual({ type: 'ssh-ed25519', fingerprint: ssh.hostKey.fingerprint });
  });

  it('reports a command killed by a signal', async () => {
    const ssh = await start();
    ssh.on('x', { signal: 'KILL' });
    expect((await exec(await serverFor(ssh), 'x')).data).toMatchObject({ exit_code: null, signal: 'SIGKILL' });
  });

  it('gives stdin to the command, and always ends it', async () => {
    const ssh = await start();
    ssh.on('cat', (req) => ({ stdout: req.stdin }));
    const h = await serverFor(ssh);
    expect((await exec(h, 'cat', { stdin: 'piped' })).data.stdout).toBe('piped');
    // Without stdin, a command reading it must see the end at once, not hang until the timeout.
    expect((await exec(h, 'cat')).data.stdout).toBe('');
  });

  it('carries binary stdin as it is', async () => {
    const ssh = await start();
    let got: Buffer = Buffer.alloc(0);
    ssh.on(/./, (req) => {
      got = req.stdin;
      return { stdout: `${req.stdin.length}\n` };
    });
    const data = Buffer.from([0, 1, 2, 255, 254, 10, 13]);
    const res = await (await serverFor(ssh)).call('pve_ssh_write_file', { node: 'pve1', path: '/tmp/x', content: data.toString('base64'), encoding: 'base64' });
    expect(res.isError).toBe(false);
    expect(got.equals(data)).toBe(true);
  });

  it('handles output in UTF-8 cut across chunks', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: Buffer.from('☃'.repeat(50_000)) });
    expect((await exec(await serverFor(ssh), 'x')).data.stdout).toBe('☃'.repeat(50_000));
  });

  it('wraps in sudo when told to, as one quoted argument', async () => {
    const ssh = await start({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    ssh.on(/^sudo /, { stdout: 'ok' });
    await exec(await serverFor(ssh, { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' }), `pct exec '100' -- sh -c 'it'\\''s'`);
    expect(ssh.commands[0]!.command).toBe(`sudo -n sh -c 'pct exec '\\''100'\\'' -- sh -c '\\''it'\\''\\'\\'''\\''s'\\'''`);
  });

  it('does not use sudo as root, however it is configured', async () => {
    const ssh = await start();
    ssh.on('id', { stdout: 'ok' });
    await exec(await serverFor(ssh, { PROXMOX_SSH_SUDO: 'true' }), 'id');
    expect(ssh.commands[0]!.command).toBe('id');
  });
});

describe('timeouts', () => {
  it('signals, then destroys the channel, and reports it with the partial output', async () => {
    const ssh = await start();
    ssh.on('hang', { stdout: 'partial', hang: true });
    const res = await exec(await serverFor(ssh, {}, { killGraceMs: 50 }), 'hang', { timeout_seconds: 1 });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('ssh_timeout');
    expect(res.data.details).toMatchObject({ stdout: 'partial', exit_code: null });
    expect(res.data.hint).toContain('may still be running');
    expect(ssh.signals).toEqual(['TERM']);
    await vi.waitFor(() => expect(ssh.channelsClosed).toContain('hang'));
  }, 15_000);

  it('leaves the connection usable afterwards', async () => {
    const ssh = await start();
    ssh.on('hang', { hang: true });
    ssh.on('id', { stdout: 'root' });
    const h = await serverFor(ssh, {}, { killGraceMs: 50 });
    await exec(h, 'hang', { timeout_seconds: 1 });
    expect((await exec(h, 'id')).data.stdout).toBe('root');
    expect(ssh.connections).toBe(1);
  }, 15_000);

  it('applies PROXMOX_SSH_TIMEOUT_SECONDS by default', async () => {
    const ssh = await start();
    ssh.on('hang', { stdout: 'partial', hang: true });
    const res = await exec(await serverFor(ssh, { PROXMOX_SSH_TIMEOUT_SECONDS: '1' }), 'hang');
    expect(res.data.error_type).toBe('ssh_timeout');
    expect(res.data.details.stdout).toBe('partial');
  }, 15_000);
});

describe('output cap', () => {
  it('keeps the start, says so, and lets the command finish', async () => {
    const ssh = await start();
    ssh.on('big', { flood: 3 * 1024 * 1024, code: 0 });
    const res = await exec(await serverFor(ssh), 'big', { max_output_bytes: 1024 });
    expect(res.data.stdout).toHaveLength(1024);
    expect(res.data).toMatchObject({ truncated: true, exit_code: 0, timed_out: false, untrusted: true });
    expect(res.data.warning).toContain('dropped');
    expect(ssh.signals).toEqual([]);
  });

  it('applies PROXMOX_SSH_MAX_OUTPUT_BYTES by default, and as the upper limit', async () => {
    const ssh = await start();
    ssh.on('big', { flood: 200 * 1024 });
    const h = await serverFor(ssh, { PROXMOX_SSH_MAX_OUTPUT_BYTES: '4096' });
    const res = await exec(h, 'big');
    expect(res.data.stdout).toHaveLength(4096);
    expect(res.data.truncated).toBe(true);
    expect((await exec(h, 'big', { max_output_bytes: 100_000 })).data.stdout).toHaveLength(4096);
  });

  it('caps stderr as well', async () => {
    const ssh = await start();
    ssh.on('big', { stderr: 'e'.repeat(100_000) });
    const res = await exec(await serverFor(ssh), 'big', { max_output_bytes: 2048 });
    expect(res.data.stderr).toHaveLength(2048);
    expect(res.data.truncated).toBe(true);
  });

  it('stops a command that never ends and only prints', async () => {
    const ssh = await start();
    ssh.on('yes', { flood: 200 * 1024 * 1024, hang: true });
    const res = await exec(await serverFor(ssh, {}, { killGraceMs: 50 }), 'yes', { max_output_bytes: 1024, timeout_seconds: 60 });
    expect(res.data.truncated).toBe(true);
    expect(res.data.stdout).toHaveLength(1024);
    expect(ssh.signals).toEqual(['TERM']);
  }, 60_000);
});

describe('the pool', () => {
  it('does not connect before the first command', async () => {
    const ssh = await start();
    await serverFor(ssh);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(ssh.connections).toBe(0);
  });

  it('keeps one connection per node, whatever is asked at once', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y', delayMs: 10 });
    const h = await serverFor(ssh);
    await Promise.all(Array.from({ length: 12 }, () => exec(h, 'x')));
    await exec(h, 'x');
    expect(ssh.connections).toBe(1);
    expect(ssh.commands).toHaveLength(13);
  });

  it('limits channels at a time', async () => {
    const ssh = await start();
    ssh.on('x', { delayMs: 30 });
    const h = await serverFor(ssh, {}, { maxChannels: 3 });
    await Promise.all(Array.from({ length: 10 }, () => exec(h, 'x')));
    expect(ssh.maxOpenChannels).toBeLessThanOrEqual(3);
    expect(ssh.commands).toHaveLength(10);
  });

  it('closes when idle and opens again when needed', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const h = await serverFor(ssh, {}, { idleMs: 50 });
    await exec(h, 'x');
    expect(ssh.connections).toBe(1);
    await vi.waitFor(async () => {
      await new Promise((resolve) => setTimeout(resolve, 80));
      expect((ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0);
    });
    await exec(h, 'x');
    expect(ssh.connections).toBe(2);
  });

  it('is not closed by the idle timer while a command runs', async () => {
    const ssh = await start();
    ssh.on('slow', { stdout: 'done', delayMs: 200 });
    expect((await exec(await serverFor(ssh, {}, { idleMs: 30 }), 'slow')).data.stdout).toBe('done');
  });

  it('reconnects after a lost connection', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const h = await serverFor(ssh);
    await exec(h, 'x');
    ssh.dropConnections();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect((await exec(h, 'x')).data.stdout).toBe('y');
    expect(ssh.connections).toBe(2);
  });

  it('reports a connection lost in mid-command, and does not run it twice', async () => {
    const ssh = await start();
    let runs = 0;
    ssh.on('x', () => {
      runs++;
      setTimeout(() => ssh.dropConnections(), 20);
      return { hang: true };
    });
    const res = await exec(await serverFor(ssh), 'x');
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.hint).toContain('Check before running it again');
    expect(runs).toBe(1);
  });

  it('closes everything when the server stops', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const h = await serverFor(ssh);
    await exec(h, 'x');
    // Closing stdin stops the server, which closes its connections on the way out.
    await h.client.close();
    await vi.waitFor(() => expect((ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
  });

  it('does not keep a failed connection: the next call tries again', async () => {
    const ssh = await start();
    const h = await serverFor(ssh, { PROXMOX_SSH_PASSWORD: 'wrong' });
    await exec(h, 'x');
    await exec(h, 'x');
    expect(ssh.connections).toBe(2);
  });
});

describe('SFTP', () => {
  it('uploads a file with the requested mode', async () => {
    const root = tempDir();
    const ssh = await start({ sftpRoot: root });
    const h = await serverFor(ssh);
    const content = Buffer.alloc(300_000, 'z');
    writeFileSync(join(h.localDir, 'in.bin'), content);
    const res = await h.call('pve_ssh_upload', { node: 'pve1', local_path: 'in.bin', path: '/up.bin', mode: '0600' });
    expect(res.isError).toBe(false);
    expect(res.data.bytes).toBe(300_000);
    expect(readFileSync(join(root, 'up.bin')).equals(content)).toBe(true);
    expect(ssh.sftpOps.filter((o) => o.op === 'open' || o.op === 'fsetstat').some((o) => o.mode !== undefined && (o.mode & 0o777) === 0o600)).toBe(true);
  });

  it.skipIf(!POSIX_SHELL)('streams a file back, whole', async () => {
    const sandbox = new ShellSandbox(POSIX_SHELL!);
    const ssh = await start({ sandbox });
    started.push(async () => sandbox.remove());
    const h = await serverFor(ssh);
    const content = 'y'.repeat(300_000);
    sandbox.write('/tmp/big.txt', content);
    const res = await h.call('pve_ssh_download', { node: 'pve1', path: '/tmp/big.txt', local_path: 'out.txt' });
    expect(res.isError).toBe(false);
    expect(readFileSync(join(h.localDir, 'out.txt'), 'utf8')).toBe(content);
  });

  it('says when SFTP is off on the host', async () => {
    const ssh = await start();
    const h = await serverFor(ssh);
    writeFileSync(join(h.localDir, 'f.txt'), 'x');
    const res = await h.call('pve_ssh_upload', { node: 'pve1', local_path: 'f.txt', path: '/f' });
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.error).toContain('SFTP');
  });

  it('gives its channel back when closed', async () => {
    const ssh = await start({ sftpRoot: tempDir() });
    ssh.on('x', {});
    const h = await serverFor(ssh, {}, { maxChannels: 1 });
    writeFileSync(join(h.localDir, 'f.txt'), 'x');
    expect((await h.call('pve_ssh_upload', { node: 'pve1', local_path: 'f.txt', path: '/f' })).isError).toBe(false);
    expect((await exec(h, 'x')).isError).toBe(false);
    expect(ssh.commands).toHaveLength(1);
  });
});

describe('PTY', () => {
  it('opens on a connection of its own', async () => {
    const ssh = await start();
    ssh.on('x', {});
    const h = await serverFor(ssh);
    await exec(h, 'x');
    const res = await h.call('pve_ssh_session_open', { node: 'pve1', cols: 90, rows: 30, term: 'vt100' });
    expect(res.isError).toBe(false);
    expect(ssh.ptys[0]).toMatchObject({ cols: 90, rows: 30, term: 'vt100' });
    expect(ssh.connections).toBe(2);
    await h.call('pve_ssh_session_close', { session: res.data.session });
  });
  // Commands under a PTY, sudo around them, input, output, exit and resize: test/ssh-tools.test.ts.
});
