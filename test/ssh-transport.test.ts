import { createServer, type Server as NetServer, type AddressInfo } from 'node:net';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { NodeResolver } from '../src/proxmox/nodes.js';
import { createSshTransport, type SshTransport } from '../src/ssh/index.js';
import { PooledSshTransport, type TransportOptions } from '../src/ssh/transport.js';
import { FAKE_SSH_PASSWORD, FakeSsh, generateKey } from './fake-ssh.js';
import { closeSsh, connectSsh, tempDir } from './ssh-harness.js';

/** The real transport against a real SSH server: every way a connection or a command can go. */

afterEach(closeSsh);

const started: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const stop of started.splice(0)) await stop().catch(() => undefined);
});

async function start(options: ConstructorParameters<typeof FakeSsh>[0] = {}): Promise<FakeSsh> {
  const ssh = new FakeSsh(options);
  await ssh.start();
  started.push(() => ssh.stop());
  return ssh;
}

function transportTo(ssh: { port: number; knownHostsLine?: () => string }, env: Record<string, string> = {}, options: TransportOptions = {}): PooledSshTransport {
  const dir = tempDir();
  const file = join(dir, 'known_hosts');
  writeFileSync(file, ssh.knownHostsLine ? `${ssh.knownHostsLine()}\n` : '');
  const config = loadConfig({
    PROXMOX_URL: 'https://192.0.2.1',
    PROXMOX_TOKEN: 'a@pve!t=s',
    PROXMOX_ALLOW_SSH: 'true',
    PROXMOX_SSH_PASSWORD: FAKE_SSH_PASSWORD,
    PROXMOX_SSH_PORT: String(ssh.port),
    PROXMOX_SSH_NODES: 'pve1=127.0.0.1',
    PROXMOX_SSH_KNOWN_HOSTS: file,
    PROXMOX_SSH_HOST_KEY_POLICY: ssh.knownHostsLine ? 'strict' : 'off',
    ...env,
  });
  const instance = config.instances.get('default')!;
  const nodes = new NodeResolver({ get: async () => [] }, { apiHost: '192.0.2.1', sshNodes: instance.ssh.nodes });
  const transport = new PooledSshTransport(instance, nodes, options);
  started.push(() => transport.close() as Promise<void>);
  return transport;
}

const run = (transport: SshTransport, text: string, stdin?: string) => transport.exec({ node: 'pve1' }, { text, access: 'read', ...(stdin !== undefined ? { stdin } : {}) });

async function errorOf(promise: Promise<unknown>): Promise<ProxmoxError> {
  const err = await promise.then(() => new Error('expected a failure'), (e: unknown) => e);
  if (err instanceof ProxmoxError) return err;
  throw err;
}

describe('ssh2 itself', () => {
  it('loads on this platform and node, with optional native modules neither required nor missed', async () => {
    const ssh2 = await import('ssh2');
    const module = (ssh2 as unknown as { default: { Client: unknown; Server: unknown } }).default;
    expect(module.Client).toBeTypeOf('function');
    expect(module.Server).toBeTypeOf('function');
  });

  it('completes a real handshake with the default transport', async () => {
    const ssh = await start();
    ssh.on('echo hi', { stdout: 'hi\n' });
    const file = join(tempDir(), 'known_hosts');
    writeFileSync(file, `${ssh.knownHostsLine()}\n`);
    const config = loadConfig({ PROXMOX_URL: 'https://192.0.2.1', PROXMOX_TOKEN: 'a@pve!t=s', PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_PASSWORD: FAKE_SSH_PASSWORD, PROXMOX_SSH_PORT: String(ssh.port), PROXMOX_SSH_NODES: 'pve1=127.0.0.1', PROXMOX_SSH_KNOWN_HOSTS: file });
    const instance = config.instances.get('default')!;
    const transport = createSshTransport(instance, new NodeResolver({ get: async () => [] }, { apiHost: '192.0.2.1', sshNodes: instance.ssh.nodes }));
    started.push(async () => transport.close());
    expect(await run(transport, 'echo hi')).toMatchObject({ stdout: 'hi\n', exit_code: 0, timed_out: false, truncated: false });
  });
});

describe('connection failures, each with its own type', () => {
  it('ssh_unreachable when nothing listens', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const { port } = closed.address() as AddressInfo;
    await new Promise((resolve) => closed.close(resolve));
    const err = await errorOf(run(transportTo({ port }), 'id'));
    expect(err.type).toBe('ssh_unreachable');
    expect(err.message).toContain('ECONNREFUSED');
    expect(err.hint).toContain('PROXMOX_SSH_NODES');
  });

  it('ssh_timeout when a host accepts and then says nothing', async () => {
    const silent: NetServer = createServer(() => undefined);
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    started.push(async () => {
      silent.close();
    });
    const { port } = silent.address() as AddressInfo;
    const started_at = Date.now();
    const err = await errorOf(run(transportTo({ port }, {}, { connectTimeoutMs: 300 }), 'id'));
    expect(err.type).toBe('ssh_timeout');
    expect(Date.now() - started_at).toBeLessThan(5000);
  });

  it('ssh_unreachable when a host drops the connection during the handshake', async () => {
    const dropper = createServer((socket) => socket.destroy());
    await new Promise<void>((resolve) => dropper.listen(0, '127.0.0.1', resolve));
    started.push(async () => {
      dropper.close();
    });
    const err = await errorOf(run(transportTo({ port: (dropper.address() as AddressInfo).port }), 'id'));
    expect(err.type).toBe('ssh_unreachable');
  });

  it('ssh_auth_failed on a wrong password, and no retry in a loop', async () => {
    const ssh = await start();
    const err = await errorOf(run(transportTo(ssh, { PROXMOX_SSH_PASSWORD: 'wrong-password' }), 'id'));
    expect(err.type).toBe('ssh_auth_failed');
    expect(err.message).not.toContain('wrong-password');
    expect(err.hint).toContain('Do not retry');
    expect(ssh.commands).toEqual([]);
    expect(ssh.connections).toBe(1);
  });

  it('ssh_auth_failed on an unknown user', async () => {
    const ssh = await start();
    expect((await errorOf(run(transportTo(ssh, { PROXMOX_SSH_USER: 'nobody' }), 'id'))).type).toBe('ssh_auth_failed');
  });

  it('ssh_auth_failed when a key needs a passphrase that was not given', async () => {
    const passphrase = 'correct horse';
    const key = generateKey('ed25519', { passphrase });
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    const err = await errorOf(run(transportTo(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id'));
    expect(err.type).toBe('ssh_auth_failed');
    expect(err.hint).toContain('passphrase');
  });

  it('config_error when a key file goes missing after startup', async () => {
    const ssh = await start();
    const dir = tempDir();
    const file = join(dir, 'id_test');
    writeFileSync(file, generateKey().private);
    const transport = transportTo(ssh, { PROXMOX_SSH_KEY_FILE: file });
    const { rmSync } = await import('node:fs');
    rmSync(file);
    expect((await errorOf(run(transport, 'id'))).type).toBe('config_error');
  });

  it('ssh_unreachable when the host refuses channels: nothing was run', async () => {
    const ssh = await start({ refuseChannels: true });
    const err = await errorOf(run(transportTo(ssh), 'id'));
    expect(err.type).toBe('ssh_unreachable');
    expect(err.hint).toContain('Nothing was run');
  });
});

describe('a host short of session slots', () => {
  it('waits and tries again, since nothing ran', async () => {
    const ssh = await start({ refuseFirstChannels: 3 });
    ssh.on('x', { stdout: 'y' });
    expect((await run(transportTo(ssh), 'x')).stdout).toBe('y');
    expect(ssh.commands).toHaveLength(1);
    expect(ssh.connections).toBe(1);
  });

  it('does the same for SFTP', async () => {
    const ssh = await start({ refuseFirstChannels: 2, sftpRoot: tempDir() });
    const sftp = await transportTo(ssh).sftp({ node: 'pve1' });
    await sftp.writeFile('/f', 'x');
    sftp.close();
  });

  it('gives up after a few seconds, saying nothing ran', async () => {
    const ssh = await start({ refuseChannels: true });
    const started_at = Date.now();
    const err = await errorOf(run(transportTo(ssh), 'x'));
    expect(err.type).toBe('ssh_unreachable');
    expect(err.message).toContain('refused');
    expect(Date.now() - started_at).toBeLessThan(6000);
  });
});

describe('authentication', () => {
  it('uses a private key, with real signature verification', async () => {
    const key = generateKey();
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    ssh.on('id', { stdout: 'root\n' });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    expect((await run(transportTo(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id')).stdout).toBe('root\n');
    expect(ssh.authAttempts.at(-1)).toMatchObject({ method: 'publickey' });
  });

  it('uses an encrypted private key with its passphrase', async () => {
    const passphrase = 'correct horse';
    const key = generateKey('ed25519', { passphrase });
    const ssh = await start({ users: { root: { keys: [key.public] } } });
    ssh.on('id', { stdout: 'root\n' });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, key.private);
    expect((await run(transportTo(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_KEY_PASSPHRASE: passphrase, PROXMOX_SSH_PASSWORD: '' }), 'id')).stdout).toBe('root\n');
  });

  it('refuses another key', async () => {
    const ssh = await start({ users: { root: { keys: [generateKey().public] } } });
    const file = join(tempDir(), 'id_test');
    writeFileSync(file, generateKey().private);
    expect((await errorOf(run(transportTo(ssh, { PROXMOX_SSH_KEY_FILE: file, PROXMOX_SSH_PASSWORD: '' }), 'id'))).type).toBe('ssh_auth_failed');
  });

  it('answers a keyboard-interactive prompt with the password, as PAM setups require', async () => {
    const ssh = await start({ users: { root: { password: FAKE_SSH_PASSWORD, keyboardOnly: true } } });
    ssh.on('id', { stdout: 'root\n' });
    expect((await run(transportTo(ssh), 'id')).stdout).toBe('root\n');
    expect(ssh.authAttempts.at(-1)).toMatchObject({ method: 'keyboard-interactive', password: FAKE_SSH_PASSWORD });
  });
});

describe('commands', () => {
  it('reports stdout, stderr, the exit code and the duration', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'out', stderr: 'err', code: 3 });
    const res = await run(transportTo(ssh), 'x');
    expect(res).toMatchObject({ stdout: 'out', stderr: 'err', exit_code: 3, truncated: false, timed_out: false });
    expect(res.duration_ms).toBeGreaterThanOrEqual(0);
    expect(res.host_key).toEqual({ type: 'ssh-ed25519', fingerprint: ssh.hostKey.fingerprint });
  });

  it('reports a command killed by a signal', async () => {
    const ssh = await start();
    ssh.on('x', { signal: 'KILL' });
    expect(await run(transportTo(ssh), 'x')).toMatchObject({ exit_code: null, signal: 'SIGKILL' });
  });

  it('gives stdin to the command, and always ends it', async () => {
    const ssh = await start();
    ssh.on('cat', (req) => ({ stdout: req.stdin }));
    const transport = transportTo(ssh);
    expect((await run(transport, 'cat', 'piped')).stdout).toBe('piped');
    // Without stdin, a command reading it must see the end at once, not hang until the timeout.
    expect((await run(transport, 'cat')).stdout).toBe('');
  });

  it('carries binary stdin as it is', async () => {
    const ssh = await start();
    let got: Buffer = Buffer.alloc(0);
    ssh.on('x', (req) => {
      got = req.stdin;
      return {};
    });
    const data = Buffer.from([0, 1, 2, 255, 254, 10, 13]);
    await transportTo(ssh).exec({ node: 'pve1' }, { text: 'x', access: 'write', stdin: data });
    expect(got.equals(data)).toBe(true);
  });

  it('handles output in UTF-8 cut across chunks', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: Buffer.from('☃'.repeat(50_000)) });
    expect((await run(transportTo(ssh), 'x')).stdout).toBe('☃'.repeat(50_000));
  });

  it('wraps in sudo when told to, as one quoted argument', async () => {
    const ssh = await start({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    ssh.on(/^sudo /, { stdout: 'ok' });
    await run(transportTo(ssh, { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' }), `pct exec '100' -- sh -c 'it'\\''s'`);
    expect(ssh.commands[0]!.command).toBe(`sudo -n sh -c 'pct exec '\\''100'\\'' -- sh -c '\\''it'\\''\\'\\'''\\''s'\\'''`);
  });

  it('does not use sudo as root, however it is configured', async () => {
    const ssh = await start();
    ssh.on('id', { stdout: 'ok' });
    await run(transportTo(ssh, { PROXMOX_SSH_SUDO: 'true' }), 'id');
    expect(ssh.commands[0]!.command).toBe('id');
  });
});

describe('timeouts', () => {
  it('signals, then destroys the channel, and reports it', async () => {
    const ssh = await start();
    ssh.on('hang', { stdout: 'partial', hang: true });
    const transport = transportTo(ssh, {}, { killGraceMs: 50 });
    const res = await transport.exec({ node: 'pve1' }, { text: 'hang', access: 'read' }, { timeoutMs: 150 });
    expect(res).toMatchObject({ timed_out: true, stdout: 'partial', exit_code: null });
    expect(ssh.signals).toEqual(['TERM']);
    await vi.waitFor(() => expect(ssh.channelsClosed).toContain('hang'));
  });

  it('leaves the connection usable afterwards', async () => {
    const ssh = await start();
    ssh.on('hang', { hang: true });
    ssh.on('id', { stdout: 'root' });
    const transport = transportTo(ssh, {}, { killGraceMs: 50 });
    await transport.exec({ node: 'pve1' }, { text: 'hang', access: 'read' }, { timeoutMs: 100 });
    expect((await run(transport, 'id')).stdout).toBe('root');
    expect(ssh.connections).toBe(1);
  });

  it('is a typed error from a tool, with the partial output', async () => {
    const ssh = await start();
    ssh.on('hang', { stdout: 'partial', hang: true });
    const { call } = await connectSsh({ server: ssh, env: { PROXMOX_SSH_TIMEOUT_SECONDS: '1' } });
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'hang', timeout_seconds: 1 });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('ssh_timeout');
    expect(res.data.details.stdout).toBe('partial');
    expect(res.data.hint).toContain('may still be running');
  }, 15_000);
});

describe('output cap', () => {
  it('keeps the start, says so, and lets the command finish', async () => {
    const ssh = await start();
    ssh.on('big', { flood: 3 * 1024 * 1024, code: 0 });
    const res = await transportTo(ssh).exec({ node: 'pve1' }, { text: 'big', access: 'read' }, { maxBytes: 1024 });
    expect(res.stdout).toHaveLength(1024);
    expect(res).toMatchObject({ truncated: true, exit_code: 0, timed_out: false });
    expect(ssh.signals).toEqual([]);
  });

  it('applies PROXMOX_SSH_MAX_OUTPUT_BYTES by default', async () => {
    const ssh = await start();
    ssh.on('big', { flood: 200 * 1024 });
    const res = await run(transportTo(ssh, { PROXMOX_SSH_MAX_OUTPUT_BYTES: '4096' }), 'big');
    expect(res.stdout).toHaveLength(4096);
    expect(res.truncated).toBe(true);
  });

  it('caps stderr as well', async () => {
    const ssh = await start();
    ssh.on('big', { stderr: 'e'.repeat(100_000) });
    const res = await transportTo(ssh).exec({ node: 'pve1' }, { text: 'big', access: 'read' }, { maxBytes: 2048 });
    expect(res.stderr).toHaveLength(2048);
    expect(res.truncated).toBe(true);
  });

  it('stops a command that never ends and only prints', async () => {
    const ssh = await start();
    ssh.on('yes', { flood: 200 * 1024 * 1024, hang: true });
    const res = await transportTo(ssh, {}, { killGraceMs: 50 }).exec({ node: 'pve1' }, { text: 'yes', access: 'read' }, { maxBytes: 1024, timeoutMs: 60_000 });
    expect(res.truncated).toBe(true);
    expect(res.stdout).toHaveLength(1024);
    expect(ssh.signals).toEqual(['TERM']);
  }, 60_000);

  it('is flagged by the tools, for an arbitrary command', async () => {
    const ssh = await start();
    ssh.on('big', { flood: 100_000 });
    const { call } = await connectSsh({ server: ssh });
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'big', max_output_bytes: 2048 });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ truncated: true, exit_code: 0, untrusted: true });
    expect(res.data.warning).toContain('dropped');
    expect(res.data.stdout).toHaveLength(2048);
  });
});

describe('the pool', () => {
  it('does not connect before the first command', async () => {
    const ssh = await start();
    transportTo(ssh);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(ssh.connections).toBe(0);
  });

  it('keeps one connection per node, whatever is asked at once', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y', delayMs: 10 });
    const transport = transportTo(ssh);
    await Promise.all(Array.from({ length: 12 }, () => run(transport, 'x')));
    await run(transport, 'x');
    expect(ssh.connections).toBe(1);
    expect(ssh.commands).toHaveLength(13);
  });

  it('limits channels at a time', async () => {
    const ssh = await start();
    ssh.on('x', { delayMs: 30 });
    const transport = transportTo(ssh, {}, { maxChannels: 3 });
    await Promise.all(Array.from({ length: 10 }, () => run(transport, 'x')));
    expect(ssh.maxOpenChannels).toBeLessThanOrEqual(3);
    expect(ssh.commands).toHaveLength(10);
  });

  it('closes when idle and opens again when needed', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const transport = transportTo(ssh, {}, { idleMs: 50 });
    await run(transport, 'x');
    expect(ssh.connections).toBe(1);
    await vi.waitFor(async () => {
      await new Promise((resolve) => setTimeout(resolve, 80));
      expect((ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0);
    });
    await run(transport, 'x');
    expect(ssh.connections).toBe(2);
  });

  it('is not closed by the idle timer while a command runs', async () => {
    const ssh = await start();
    ssh.on('slow', { stdout: 'done', delayMs: 200 });
    const res = await run(transportTo(ssh, {}, { idleMs: 30 }), 'slow');
    expect(res.stdout).toBe('done');
  });

  it('reconnects after a lost connection', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const transport = transportTo(ssh);
    await run(transport, 'x');
    ssh.dropConnections();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect((await run(transport, 'x')).stdout).toBe('y');
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
    const err = await errorOf(run(transportTo(ssh), 'x'));
    expect(err.type).toBe('ssh_unreachable');
    expect(err.hint).toContain('Check before running it again');
    expect(runs).toBe(1);
  });

  it('closes everything at shutdown, and refuses from then on', async () => {
    const ssh = await start();
    ssh.on('x', { stdout: 'y' });
    const transport = transportTo(ssh);
    await run(transport, 'x');
    await transport.close();
    await vi.waitFor(() => expect((ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
    expect((await errorOf(run(transport, 'x'))).type).toBe('ssh_unreachable');
  });

  it('does not keep a failed connection: the next call tries again', async () => {
    const ssh = await start();
    const transport = transportTo(ssh, { PROXMOX_SSH_PASSWORD: 'wrong' });
    await errorOf(run(transport, 'x'));
    await errorOf(run(transport, 'x'));
    expect(ssh.connections).toBe(2);
  });
});

describe('SFTP', () => {
  it('writes, reads, stats, lists, renames, changes mode and deletes, with real paths', async () => {
    const dir = tempDir();
    const ssh = await start({ sftpRoot: dir });
    const sftp = await transportTo(ssh).sftp({ node: 'pve1' });
    await sftp.writeFile('/a.txt', 'hello', { mode: 0o600 });
    expect(readFileSync(join(dir, 'a.txt'), 'utf8')).toBe('hello');
    expect((await sftp.readFile('/a.txt')).toString()).toBe('hello');
    expect(await sftp.stat('/a.txt')).toMatchObject({ size: 5, isFile: true, isDirectory: false });
    expect((await sftp.readdir('/')).map((e) => e.name)).toEqual(['a.txt']);
    await sftp.rename('/a.txt', '/b.txt');
    await sftp.chmod('/b.txt', 0o644);
    await sftp.unlink('/b.txt');
    expect((await sftp.readdir('/')).map((e) => e.name)).toEqual([]);
    sftp.close();
  });

  it('streams a file both ways, with the requested mode', async () => {
    const dir = tempDir();
    const local = tempDir();
    const ssh = await start({ sftpRoot: dir });
    const sftp = await transportTo(ssh).sftp({ node: 'pve1' });
    const source = join(local, 'in.bin');
    const content = Buffer.alloc(300_000, 'z');
    writeFileSync(source, content);
    await sftp.fastPut(source, '/up.bin', { mode: 0o600 });
    expect(readFileSync(join(dir, 'up.bin')).equals(content)).toBe(true);
    expect(ssh.sftpOps.filter((o) => o.op === 'open' || o.op === 'fsetstat').some((o) => o.mode !== undefined && (o.mode & 0o777) === 0o600)).toBe(true);
    const back = join(local, 'out.bin');
    await sftp.fastGet('/up.bin', back);
    expect(readFileSync(back).equals(content)).toBe(true);
    sftp.close();
  });

  it('maps missing files to not_found', async () => {
    const ssh = await start({ sftpRoot: tempDir() });
    const sftp = await transportTo(ssh).sftp({ node: 'pve1' });
    expect((await errorOf(sftp.readFile('/nope'))).type).toBe('not_found');
    expect((await errorOf(sftp.stat('/nope'))).type).toBe('not_found');
    sftp.close();
  });

  it('says when SFTP is off on the host', async () => {
    const ssh = await start();
    const err = await errorOf(transportTo(ssh).sftp({ node: 'pve1' }));
    expect(err.type).toBe('ssh_unreachable');
    expect(err.message).toContain('SFTP');
  });

  it('refuses a closed session', async () => {
    const ssh = await start({ sftpRoot: tempDir() });
    const sftp = await transportTo(ssh).sftp({ node: 'pve1' });
    sftp.close();
    expect((await errorOf(sftp.readFile('/x'))).type).toBe('ssh_unreachable');
  });

  it('gives its channel back when closed', async () => {
    const ssh = await start({ sftpRoot: tempDir() });
    ssh.on('x', {});
    const transport = transportTo(ssh, {}, { maxChannels: 1 });
    const sftp = await transport.sftp({ node: 'pve1' });
    sftp.close();
    await run(transport, 'x');
    expect(ssh.commands).toHaveLength(1);
  });
});

describe('PTY', () => {
  it('opens a login shell with the size asked for, on a connection of its own', async () => {
    const ssh = await start();
    ssh.on('x', {});
    const transport = transportTo(ssh);
    await run(transport, 'x');
    const channel = await transport.shell({ node: 'pve1' }, { cols: 90, rows: 30, term: 'vt100' });
    expect(ssh.ptys[0]).toMatchObject({ cols: 90, rows: 30, term: 'vt100' });
    expect(ssh.connections).toBe(2);
    channel.close();
  });

  it('runs a command under a PTY, and sudo wraps it', async () => {
    const ssh = await start({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    const transport = transportTo(ssh, { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' });
    const channel = await transport.shell({ node: 'pve1' }, { command: `pct enter '101'` });
    expect(ssh.ptys[0]!.command).toBe(`sudo -n pct enter '101'`);
    channel.close();
  });

  it('carries input and output, and reports the exit', async () => {
    const ssh = await start();
    const channel = await transportTo(ssh).shell({ node: 'pve1' });
    const chunks: Buffer[] = [];
    channel.onData((chunk) => chunks.push(chunk));
    const closed = new Promise<{ code: number | null }>((resolve) => channel.onClose(resolve));
    channel.write('uname\n');
    await vi.waitFor(() => expect(Buffer.concat(chunks).toString()).toContain('ran: uname'));
    channel.write('exit\n');
    expect(await closed).toEqual({ code: 0 });
  });

  it('resizes', async () => {
    const ssh = await start();
    const channel = await transportTo(ssh).shell({ node: 'pve1' });
    channel.resize?.(200, 50);
    await vi.waitFor(() => expect(ssh.windowChanges).toEqual([{ cols: 200, rows: 50 }]));
    channel.close();
  });
});
