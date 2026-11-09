import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FAKE_SSH_PASSWORD, FakeSsh, generateKey } from './fake-ssh.js';
import { closeSsh, connectSsh, tempDir, type SshHarness } from './ssh-harness.js';

/**
 * Every host key decision on a real SSH handshake, with real keys and a real known_hosts file,
 * through the server binary: fails closed, before any credential is sent.
 *
 * The parsing underneath (markers, CRLF, unreadable lines, names, patterns, hashes, fingerprints,
 * key types, statuses, guest public key files) is checked in src/ssh/known_hosts.rs.
 */

const servers: FakeSsh[] = [];

afterEach(async () => {
  await closeSsh();
  await Promise.all(servers.splice(0).map((s) => s.stop()));
});

function hashedField(name: string): string {
  const salt = randomBytes(20);
  return `|1|${salt.toString('base64')}|${createHmac('sha1', salt).update(name).digest('base64')}`;
}

const TEST_COMMAND = 'hostname; id -un; pveversion 2>&1';

async function server(options: ConstructorParameters<typeof FakeSsh>[0] = {}): Promise<FakeSsh> {
  const ssh = new FakeSsh(options);
  await ssh.start();
  ssh.on(TEST_COMMAND, { stdout: 'pve1\nroot\npve-manager/9.1.0\n' });
  servers.push(ssh);
  return ssh;
}

/**
 * A server process with its own files, so that each case states exactly what is known. The
 * transport connects on the first tool call, so known_hosts is written before anything reads it.
 * Without text, known_hosts does not exist.
 */
async function serverFor(ssh: FakeSsh, env: Record<string, string>, knownHostsText?: string): Promise<SshHarness & { file: string }> {
  const file = join(tempDir(), 'known_hosts');
  if (knownHostsText !== undefined) writeFileSync(file, knownHostsText);
  const h = await connectSsh({ server: ssh, unknownHost: true, env: { PROXMOX_SSH_KNOWN_HOSTS: file, ...env } });
  return { ...h, file };
}

interface Refusal {
  type: string;
  message: string;
  hint?: string;
  details?: Record<string, unknown>;
}

async function attempt(h: SshHarness): Promise<Refusal | { fingerprint?: string }> {
  const res = await h.call('pve_ssh_test', { node: 'pve1' });
  if (res.isError) return { type: res.data.error_type, message: res.data.error, hint: res.data.hint, details: res.data.details };
  return { fingerprint: res.data.host_key?.fingerprint };
}

function expectRefused(result: unknown, type: string): asserts result is Refusal {
  expect(result).toHaveProperty('type', type);
}

describe('strict, on a real handshake', () => {
  it('refuses an unknown host, with the fingerprint and how to check it, and sends no credential', async () => {
    const ssh = await server();
    const result = await attempt(await serverFor(ssh, {}, ''));
    expectRefused(result, 'host_key_unknown');
    expect(result.details).toMatchObject({ fingerprint: ssh.hostKey.fingerprint, key_type: 'ssh-ed25519' });
    expect(result.hint).toContain('ssh-keygen -lf');
    expect(result.hint).toContain('PROXMOX_SSH_FINGERPRINTS');
    expect(ssh.authAttempts).toEqual([]);
    expect(ssh.commands).toEqual([]);
  });

  it('refuses when known_hosts does not exist', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, {})), 'host_key_unknown');
  });

  it('accepts a plain entry under [host]:port', async () => {
    const ssh = await server();
    expect(await attempt(await serverFor(ssh, {}, `${ssh.knownHostsLine()}\n`))).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    expect(ssh.authAttempts.some((a) => a.method === 'password' && a.password === FAKE_SSH_PASSWORD)).toBe(true);
  });

  it('does not take an entry for the same host on another port', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, `[127.0.0.1]:${ssh.port + 1} ${ssh.hostKey.public}\n127.0.0.1 ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(h), 'host_key_unknown');
  });

  it('accepts an entry in a comma list', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, `pve.example.org,[127.0.0.1]:${ssh.port},10.0.0.1 ${ssh.hostKey.public}\n`);
    expect(await attempt(h)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('accepts a hashed entry', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, `${hashedField(`[127.0.0.1]:${ssh.port}`)} ${ssh.hostKey.public}\n`);
    expect(await attempt(h)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('does not accept a hashed entry of another host', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, {}, `${hashedField('[127.0.0.2]:22')} ${ssh.hostKey.public}\n`)), 'host_key_unknown');
  });

  it('refuses a changed key, naming what was expected, and sends no credential', async () => {
    const ssh = await server();
    const other = generateKey();
    const result = await attempt(await serverFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${other.public}\n`));
    expectRefused(result, 'host_key_mismatch');
    expect(result.details).toMatchObject({ presented: ssh.hostKey.fingerprint, expected: [other.fingerprint] });
    expect(ssh.authAttempts).toEqual([]);
    expect(ssh.commands).toEqual([]);
  });

  it('refuses a hashed entry with a changed key', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, `${hashedField(`[127.0.0.1]:${ssh.port}`)} ${generateKey().public}\n`);
    expectRefused(await attempt(h), 'host_key_mismatch');
  });

  it('refuses a revoked key, even when it is also listed as good', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    const result = await attempt(h);
    expectRefused(result, 'host_key_mismatch');
    expect(result.message).toContain('revoked');
    expect(ssh.authAttempts).toEqual([]);
  });

  it('refuses a revoked key listed under a wildcard', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, {}, `@revoked * ${ssh.hostKey.public}\n`)), 'host_key_mismatch');
  });

  it('ignores @cert-authority: this is no certificate check, and it must not read as trust', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, {}, `@cert-authority [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`)), 'host_key_unknown');
  });

  it('honours a negated pattern', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, {}, `*,![127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`)), 'host_key_unknown');
  });

  it('asks for a known key type first: a host listed with RSA is not unknown because it also has ed25519', async () => {
    const rsa = generateKey('rsa');
    const ssh = await server({ extraHostKeys: [rsa] });
    expect(await attempt(await serverFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`))).toEqual({ fingerprint: rsa.fingerprint });
  });

  it('treats another key type with no match as unknown, and never trusts it on first use', async () => {
    const rsa = generateKey('rsa');
    const ssh = await server();
    const result = await attempt(await serverFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`));
    expectRefused(result, 'host_key_unknown');
    expect(result.details).toMatchObject({ known_with_other_types: [rsa.fingerprint] });

    const lenient = await serverFor(ssh, { PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' }, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`);
    expectRefused(await attempt(lenient), 'host_key_unknown');
    expect(readFileSync(lenient.file, 'utf8')).not.toContain(ssh.hostKey.public);
  });
});

describe('pinned fingerprints, on a real handshake', () => {
  it('connects with the right pin, whatever known_hosts says', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${ssh.hostKey.fingerprint}` }, '');
    expect(await attempt(h)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('refuses the wrong pin, even when known_hosts has the key', async () => {
    const ssh = await server();
    const pin = generateKey().fingerprint;
    const result = await attempt(await serverFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${pin}` }, `${ssh.knownHostsLine()}\n`));
    expectRefused(result, 'host_key_mismatch');
    expect(result.details).toMatchObject({ expected: [pin], presented: ssh.hostKey.fingerprint });
    expect(ssh.authAttempts).toEqual([]);
  });

  it('accepts a pin with the base64 padding ssh tools sometimes leave on', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, { PROXMOX_SSH_FINGERPRINTS: JSON.stringify({ pve1: `${ssh.hostKey.fingerprint}=` }) }, '');
    expect(await attempt(h)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('applies a pin to its node only', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve2=${ssh.hostKey.fingerprint}` }, '')), 'host_key_unknown');
  });

  it('still refuses a key marked revoked', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${ssh.hostKey.fingerprint}` }, `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(h), 'host_key_mismatch');
  });
});

describe('accept-new, on a real handshake', () => {
  const POLICY = { PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' };

  it('records an unknown host in a new file, then knows it', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, POLICY);
    expect(await attempt(h)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    const [line] = readFileSync(h.file, 'utf8').trim().split('\n');
    expect(line).toBe(`[127.0.0.1]:${ssh.port} ssh-ed25519 ${ssh.hostKey.blob.toString('base64')}`);
    // A new process, strict, finds it there.
    expect(await attempt(await serverFor(ssh, { PROXMOX_SSH_KNOWN_HOSTS: h.file }))).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('only appends, and handles a file with no final newline', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, POLICY, 'other.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUFsomething');
    await attempt(h);
    const lines = readFileSync(h.file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('other.example.org');
  });

  it('then refuses that same host with another key: this is first use only', async () => {
    const first = await server();
    const recorded = await serverFor(first, POLICY);
    await attempt(recorded);
    const file = recorded.file;

    const impostor = await server();
    // The other key on the same address: point the entry at this port, as a reused address would be.
    writeFileSync(file, readFileSync(file, 'utf8').replace(`[127.0.0.1]:${first.port}`, `[127.0.0.1]:${impostor.port}`));
    expectRefused(await attempt(await serverFor(impostor, { ...POLICY, PROXMOX_SSH_KNOWN_HOSTS: file })), 'host_key_mismatch');
    expect(impostor.authAttempts).toEqual([]);
  });

  it('never records a revoked key', async () => {
    const ssh = await server();
    const text = `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`;
    const h = await serverFor(ssh, POLICY, text);
    expectRefused(await attempt(h), 'host_key_mismatch');
    expect(readFileSync(h.file, 'utf8')).toBe(text);
  });

  it('fails closed when the file cannot be written', async () => {
    const ssh = await server();
    // A directory where the file should be: appending fails on every platform.
    const result = await attempt(await serverFor(ssh, { ...POLICY, PROXMOX_SSH_KNOWN_HOSTS: tempDir() }));
    expectRefused(result, 'host_key_unknown');
    expect(result.message).toContain('could not be recorded');
    expect(ssh.authAttempts).toEqual([]);
  });

  it('is off by default: strict does not write anything', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, {}, '');
    await attempt(h);
    expect(readFileSync(h.file, 'utf8')).toBe('');
  });
});

describe('policy off, on a real handshake', () => {
  const POLICY = { PROXMOX_SSH_HOST_KEY_POLICY: 'off' };

  it('connects to an unknown host, and to a changed one', async () => {
    const ssh = await server();
    expect(await attempt(await serverFor(ssh, POLICY, ''))).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    expect(await attempt(await serverFor(ssh, POLICY, `[127.0.0.1]:${ssh.port} ${generateKey().public}\n`))).toEqual({ fingerprint: ssh.hostKey.fingerprint });
  });

  it('does not write to known_hosts', async () => {
    const ssh = await server();
    const h = await serverFor(ssh, POLICY, '');
    await attempt(h);
    expect(readFileSync(h.file, 'utf8')).toBe('');
  });

  it('still refuses what the operator stated: a revoked key and a pin', async () => {
    const ssh = await server();
    expectRefused(await attempt(await serverFor(ssh, POLICY, `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`)), 'host_key_mismatch');
    expectRefused(await attempt(await serverFor(ssh, { ...POLICY, PROXMOX_SSH_FINGERPRINTS: `pve1=${generateKey().fingerprint}` }, '')), 'host_key_mismatch');
  });
});

describe('through a real MCP client', () => {
  it('gives the refusal as a typed error with the fingerprint, on the first tool call', async () => {
    const { call, ssh } = await connectSsh({ unknownHost: true });
    const res = await call('pve_ssh_test', { node: 'pve1' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('host_key_unknown');
    expect(res.data.details.fingerprint).toBe(ssh.hostKey.fingerprint);
    expect(res.data.hint).toContain('Do not retry');
    expect(ssh.authAttempts).toEqual([]);
  });

  it('reports the host key of a verified node', async () => {
    const { call, ssh } = await connectSsh();
    ssh.on(/^hostname;/, { stdout: 'pve1\nroot\npve-manager/9.1.0\n' });
    const res = await call('pve_ssh_test', { node: 'pve1' });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ connected: true, hostname: 'pve1', user: 'root', pveversion: 'pve-manager/9.1.0', host_key: { type: 'ssh-ed25519', fingerprint: ssh.hostKey.fingerprint } });
  });

  it('asks nothing of a changed key: no write tool goes through either', async () => {
    const other = await server({ hostKey: generateKey() });
    const { call, knownHosts } = await connectSsh({ server: other });
    writeFileSync(knownHosts, `[127.0.0.1]:${other.port} ${generateKey().public}\n`);
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'reboot' });
    expect(res.data.error_type).toBe('host_key_mismatch');
    expect(other.commands).toEqual([]);
  });
});
