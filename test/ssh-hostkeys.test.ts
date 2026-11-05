import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { NodeResolver } from '../src/proxmox/nodes.js';
import { checkKnownHosts, fingerprintOf, hostFieldMatches, knownHostsName, keyTypeOf, parseKnownHosts, parsePublicKeyLines } from '../src/ssh/known-hosts.js';
import { PooledSshTransport } from '../src/ssh/transport.js';
import { FAKE_SSH_PASSWORD, FakeSsh, generateKey, type GeneratedKey } from './fake-ssh.js';
import { closeSsh, connectSsh, tempDir } from './ssh-harness.js';

/**
 * Every host key decision on a real SSH handshake, with real keys and a real known_hosts file:
 * fails closed, before any credential is sent.
 */

afterEach(closeSsh);

function hashedField(name: string): string {
  const salt = randomBytes(20);
  return `|1|${salt.toString('base64')}|${createHmac('sha1', salt).update(name).digest('base64')}`;
}

async function server(options: ConstructorParameters<typeof FakeSsh>[0] = {}): Promise<FakeSsh> {
  const ssh = new FakeSsh(options);
  await ssh.start();
  return ssh;
}

/** A transport with its own files, so that each case states exactly what is known. */
function transportFor(ssh: FakeSsh, env: Record<string, string>, knownHostsText?: string): { transport: PooledSshTransport; file: string; close: () => Promise<void> } {
  const file = join(tempDir(), 'known_hosts');
  if (knownHostsText !== undefined) writeFileSync(file, knownHostsText);
  const config = loadConfig({
    PROXMOX_URL: 'https://192.0.2.1',
    PROXMOX_TOKEN: 'a@pve!t=s',
    PROXMOX_ALLOW_SSH: 'true',
    PROXMOX_SSH_PASSWORD: FAKE_SSH_PASSWORD,
    PROXMOX_SSH_PORT: String(ssh.port),
    PROXMOX_SSH_NODES: 'pve1=127.0.0.1',
    PROXMOX_SSH_KNOWN_HOSTS: file,
    ...env,
  });
  const instance = config.instances.get('default')!;
  const nodes = new NodeResolver({ get: async () => [] }, { apiHost: '192.0.2.1', sshNodes: instance.ssh.nodes });
  const transport = new PooledSshTransport(instance, nodes);
  return {
    transport,
    file,
    close: async () => {
      await transport.close();
      await ssh.stop();
    },
  };
}

async function attempt(transport: PooledSshTransport): Promise<ProxmoxError | { fingerprint?: string | undefined }> {
  try {
    const res = await transport.exec({ node: 'pve1' }, { text: 'id', access: 'read' });
    return { fingerprint: res.host_key?.fingerprint };
  } catch (err) {
    if (err instanceof ProxmoxError) return err;
    throw err;
  }
}

function expectRefused(result: unknown, type: string): asserts result is ProxmoxError {
  expect(result).toBeInstanceOf(ProxmoxError);
  expect((result as ProxmoxError).type).toBe(type);
}

describe('strict, on a real handshake', () => {
  it('refuses an unknown host, with the fingerprint and how to check it, and sends no credential', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, '');
    const result = await attempt(transport);
    expectRefused(result, 'host_key_unknown');
    expect(result.details).toMatchObject({ fingerprint: ssh.hostKey.fingerprint, key_type: 'ssh-ed25519' });
    expect(result.hint).toContain('ssh-keygen -lf');
    expect(result.hint).toContain('PROXMOX_SSH_FINGERPRINTS');
    expect(ssh.authAttempts).toEqual([]);
    expect(ssh.commands).toEqual([]);
    await close();
  });

  it('refuses when known_hosts does not exist', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {});
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('accepts a plain entry under [host]:port', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `${ssh.knownHostsLine()}\n`);
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    expect(ssh.authAttempts.some((a) => a.method === 'password' && a.password === FAKE_SSH_PASSWORD)).toBe(true);
    await close();
  });

  it('does not take an entry for the same host on another port', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `[127.0.0.1]:${ssh.port + 1} ${ssh.hostKey.public}\n127.0.0.1 ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('accepts an entry in a comma list', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `pve.example.org,[127.0.0.1]:${ssh.port},10.0.0.1 ${ssh.hostKey.public}\n`);
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await close();
  });

  it('accepts a hashed entry', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `${hashedField(`[127.0.0.1]:${ssh.port}`)} ${ssh.hostKey.public}\n`);
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await close();
  });

  it('does not accept a hashed entry of another host', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `${hashedField('[127.0.0.2]:22')} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('refuses a changed key, naming what was expected, and sends no credential', async () => {
    const ssh = await server();
    const other = generateKey();
    const { transport, close } = transportFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${other.public}\n`);
    const result = await attempt(transport);
    expectRefused(result, 'host_key_mismatch');
    expect(result.details).toMatchObject({ presented: ssh.hostKey.fingerprint, expected: [other.fingerprint] });
    expect(ssh.authAttempts).toEqual([]);
    expect(ssh.commands).toEqual([]);
    await close();
  });

  it('refuses a hashed entry with a changed key', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `${hashedField(`[127.0.0.1]:${ssh.port}`)} ${generateKey().public}\n`);
    expectRefused(await attempt(transport), 'host_key_mismatch');
    await close();
  });

  it('refuses a revoked key, even when it is also listed as good', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    const result = await attempt(transport);
    expectRefused(result, 'host_key_mismatch');
    expect(result.message).toContain('revoked');
    expect(ssh.authAttempts).toEqual([]);
    await close();
  });

  it('refuses a revoked key listed under a wildcard', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `@revoked * ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_mismatch');
    await close();
  });

  it('ignores @cert-authority: this is no certificate check, and it must not read as trust', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `@cert-authority [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('honours a negated pattern', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, {}, `*,![127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('asks for a known key type first: a host listed with RSA is not unknown because it also has ed25519', async () => {
    const rsa = generateKey('rsa');
    const ssh = await server({ extraHostKeys: [rsa] });
    const { transport, close } = transportFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`);
    expect(await attempt(transport)).toEqual({ fingerprint: rsa.fingerprint });
    await close();
  });

  it('treats another key type with no match as unknown, and never trusts it on first use', async () => {
    const rsa = generateKey('rsa');
    const ssh = await server();
    const strict = transportFor(ssh, {}, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`);
    const result = await attempt(strict.transport);
    expectRefused(result, 'host_key_unknown');
    expect(result.details).toMatchObject({ known_with_other_types: [rsa.fingerprint] });
    await strict.transport.close();

    const lenient = transportFor(ssh, { PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' }, `[127.0.0.1]:${ssh.port} ${rsa.public}\n`);
    expectRefused(await attempt(lenient.transport), 'host_key_unknown');
    expect(readFileSync(lenient.file, 'utf8')).not.toContain(ssh.hostKey.public);
    await lenient.close();
  });
});

describe('pinned fingerprints, on a real handshake', () => {
  it('connects with the right pin, whatever known_hosts says', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${ssh.hostKey.fingerprint}` }, '');
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await close();
  });

  it('refuses the wrong pin, even when known_hosts has the key', async () => {
    const ssh = await server();
    const pin = generateKey().fingerprint;
    const { transport, close } = transportFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${pin}` }, `${ssh.knownHostsLine()}\n`);
    const result = await attempt(transport);
    expectRefused(result, 'host_key_mismatch');
    expect(result.details).toMatchObject({ expected: [pin], presented: ssh.hostKey.fingerprint });
    expect(ssh.authAttempts).toEqual([]);
    await close();
  });

  it('accepts a pin with the base64 padding ssh tools sometimes leave on', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, { PROXMOX_SSH_FINGERPRINTS: JSON.stringify({ pve1: `${ssh.hostKey.fingerprint}=` }) }, '');
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await close();
  });

  it('applies a pin to its node only', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve2=${ssh.hostKey.fingerprint}` }, '');
    expectRefused(await attempt(transport), 'host_key_unknown');
    await close();
  });

  it('still refuses a key marked revoked', async () => {
    const ssh = await server();
    const { transport, close } = transportFor(ssh, { PROXMOX_SSH_FINGERPRINTS: `pve1=${ssh.hostKey.fingerprint}` }, `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(transport), 'host_key_mismatch');
    await close();
  });
});

describe('accept-new, on a real handshake', () => {
  const POLICY = { PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' };

  it('records an unknown host in a new file, then knows it', async () => {
    const ssh = await server();
    const { transport, file, close } = transportFor(ssh, POLICY);
    expect(await attempt(transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    const [line] = readFileSync(file, 'utf8').trim().split('\n');
    expect(line).toBe(`[127.0.0.1]:${ssh.port} ssh-ed25519 ${ssh.hostKey.blob.toString('base64')}`);
    await close();
  });

  it('only appends, and handles a file with no final newline', async () => {
    const ssh = await server();
    const { transport, file, close } = transportFor(ssh, POLICY, 'other.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUFsomething');
    await attempt(transport);
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('other.example.org');
    await close();
  });

  it('then refuses that same host with another key: this is first use only', async () => {
    const first = await server();
    const { transport, file } = transportFor(first, POLICY);
    await attempt(transport);
    await transport.close();
    const port = first.port;
    await first.stop();

    const impostor = await server();
    // The other key on the same address: rewrite the entry to this port, as a reused address would be.
    writeFileSync(file, readFileSync(file, 'utf8').replace(`:${port}]`, `:${impostor.port}]`).replace(`[127.0.0.1]:${port}`, `[127.0.0.1]:${impostor.port}`));
    const second = transportFor(impostor, { ...POLICY, PROXMOX_SSH_KNOWN_HOSTS: file });
    expectRefused(await attempt(second.transport), 'host_key_mismatch');
    expect(impostor.authAttempts).toEqual([]);
    await second.close();
  });

  it('never records a revoked key', async () => {
    const ssh = await server();
    const text = `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`;
    const { transport, file, close } = transportFor(ssh, POLICY, text);
    expectRefused(await attempt(transport), 'host_key_mismatch');
    expect(readFileSync(file, 'utf8')).toBe(text);
    await close();
  });

  it('fails closed when the file cannot be written', async () => {
    const ssh = await server();
    const dir = tempDir();
    // A directory where the file should be: appending fails on every platform.
    const { transport, close } = transportFor(ssh, { ...POLICY, PROXMOX_SSH_KNOWN_HOSTS: dir });
    const result = await attempt(transport);
    expectRefused(result, 'host_key_unknown');
    expect(result.message).toContain('could not be recorded');
    expect(ssh.authAttempts).toEqual([]);
    await close();
  });

  it('is off by default: strict does not write anything', async () => {
    const ssh = await server();
    const { transport, file, close } = transportFor(ssh, {}, '');
    await attempt(transport);
    expect(readFileSync(file, 'utf8')).toBe('');
    await close();
  });
});

describe('policy off, on a real handshake', () => {
  const POLICY = { PROXMOX_SSH_HOST_KEY_POLICY: 'off' };

  it('connects to an unknown host, and to a changed one', async () => {
    const ssh = await server();
    const unknown = transportFor(ssh, POLICY, '');
    expect(await attempt(unknown.transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await unknown.transport.close();
    const changed = transportFor(ssh, POLICY, `[127.0.0.1]:${ssh.port} ${generateKey().public}\n`);
    expect(await attempt(changed.transport)).toEqual({ fingerprint: ssh.hostKey.fingerprint });
    await changed.close();
  });

  it('does not write to known_hosts', async () => {
    const ssh = await server();
    const { transport, file, close } = transportFor(ssh, POLICY, '');
    await attempt(transport);
    expect(readFileSync(file, 'utf8')).toBe('');
    await close();
  });

  it('still refuses what the operator stated: a revoked key and a pin', async () => {
    const ssh = await server();
    const revoked = transportFor(ssh, POLICY, `@revoked [127.0.0.1]:${ssh.port} ${ssh.hostKey.public}\n`);
    expectRefused(await attempt(revoked.transport), 'host_key_mismatch');
    const pinned = transportFor(ssh, { ...POLICY, PROXMOX_SSH_FINGERPRINTS: `pve1=${generateKey().fingerprint}` }, '');
    expectRefused(await attempt(pinned.transport), 'host_key_mismatch');
    await ssh.stop();
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
    const other = new FakeSsh({ hostKey: generateKey() });
    await other.start();
    const { call, knownHosts } = await connectSsh({ server: other });
    writeFileSync(knownHosts, `[127.0.0.1]:${other.port} ${generateKey().public}\n`);
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'reboot' });
    expect(res.data.error_type).toBe('host_key_mismatch');
    expect(other.commands).toEqual([]);
    await other.stop();
  });
});

describe('known_hosts parsing', () => {
  const key: GeneratedKey = generateKey();
  const line = key.public.split(' ').slice(0, 2).join(' ');

  it('reads entries, markers, comments and blank lines', () => {
    const entries = parseKnownHosts(`# a comment\n\nhost1 ${line} a trailing comment\n  host2 ${line}\n@revoked host3 ${line}\n@cert-authority *.example.org ${line}\n`);
    expect(entries.map((e) => [e.marker, e.hosts])).toEqual([[undefined, 'host1'], [undefined, 'host2'], ['revoked', 'host3'], ['cert-authority', '*.example.org']]);
    expect(entries[0]!.key.equals(key.blob)).toBe(true);
  });

  it('survives CRLF line endings, as a file edited on Windows has', () => {
    expect(parseKnownHosts(`host1 ${line}\r\nhost2 ${line}\r\n`).map((e) => e.hosts)).toEqual(['host1', 'host2']);
  });

  it('ignores what it cannot read, and keeps the rest', () => {
    const entries = parseKnownHosts(`junk\nhost1 ${line}\nhost2 ssh-ed25519 not*base64\n@unknown-marker host3 ${line}\nhost4\n`);
    expect(entries.map((e) => e.hosts)).toEqual(['host1']);
  });

  it('names a host as ssh does', () => {
    expect(knownHostsName('PVE1', 22)).toBe('pve1');
    expect(knownHostsName('10.0.0.1', 2222)).toBe('[10.0.0.1]:2222');
    expect(knownHostsName('2001:db8::1', 22)).toBe('2001:db8::1');
    expect(knownHostsName('2001:db8::1', 2222)).toBe('[2001:db8::1]:2222');
  });

  it('matches patterns the way OpenSSH does', () => {
    expect(hostFieldMatches('pve1,pve2', 'pve2')).toBe(true);
    expect(hostFieldMatches('pve1,pve2', 'pve3')).toBe(false);
    expect(hostFieldMatches('PVE1', 'pve1')).toBe(true);
    expect(hostFieldMatches('*.example.org', 'a.example.org')).toBe(true);
    expect(hostFieldMatches('*.example.org', 'example.org')).toBe(false);
    expect(hostFieldMatches('pve?', 'pve1')).toBe(true);
    expect(hostFieldMatches('pve?', 'pve12')).toBe(false);
    expect(hostFieldMatches('*,!pve1', 'pve1')).toBe(false);
    expect(hostFieldMatches('*,!pve1', 'pve2')).toBe(true);
    // Dots in a pattern are dots.
    expect(hostFieldMatches('10.0.0.1', '10x0x0x1')).toBe(false);
    expect(hostFieldMatches('[10.0.0.1]:2222', '[10.0.0.1]:2222')).toBe(true);
  });

  it('checks a hash against its own salt, and refuses other hash versions', () => {
    const field = hashedField('pve1');
    expect(hostFieldMatches(field, 'pve1')).toBe(true);
    expect(hostFieldMatches(field, 'pve2')).toBe(false);
    expect(hostFieldMatches(field.replace('|1|', '|2|'), 'pve1')).toBe(false);
    expect(hostFieldMatches('|1|notenoughparts', 'pve1')).toBe(false);
  });

  it('computes fingerprints as ssh-keygen prints them', () => {
    expect(fingerprintOf(key.blob)).toBe(key.fingerprint);
    expect(key.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it('reads the key type out of the blob', () => {
    expect(keyTypeOf(generateKey('ecdsa').blob)).toBe('ecdsa-sha2-nistp256');
    expect(keyTypeOf(Buffer.from([0, 0, 0, 9, 1]))).toBe('unknown');
    expect(keyTypeOf(Buffer.alloc(2))).toBe('unknown');
  });

  it('says which status a key has', () => {
    const other = generateKey();
    const name = 'pve1';
    const entries = parseKnownHosts(`pve1 ${line}\n`);
    expect(checkKnownHosts(entries, name, key.blob).status).toBe('known');
    expect(checkKnownHosts(entries, name, other.blob).status).toBe('changed');
    expect(checkKnownHosts(entries, 'pve2', key.blob).status).toBe('unknown');
    expect(checkKnownHosts(parseKnownHosts(`pve1 ${generateKey('ecdsa').public}\n`), name, key.blob).status).toBe('other-type');
  });

  it('reads the public key files of a guest, and leaves out what does not parse', () => {
    const keys = parsePublicKeyLines(`${key.public}\nsomething else\nssh-rsa ${key.blob.toString('base64')} wrong type\n`);
    expect(keys).toHaveLength(1);
    expect(keys[0]!.equals(key.blob)).toBe(true);
  });
});
