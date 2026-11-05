import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { loadConfig, normalizeFingerprint, parseMap, type Env } from '../src/config.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { resolveLocalPath } from '../src/proxmox/localpath.js';
import { TLS_CERT, TLS_FINGERPRINT } from './tls-fixture.js';

const dir = mkdtempSync(join(tmpdir(), 'pvemcp-config-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const BASE: Env = { PROXMOX_URL: 'https://pve.example', PROXMOX_TOKEN: 'mcp@pve!t=secret' };

function load(env: Env = {}) {
  const config = loadConfig({ ...BASE, ...env });
  return { config, instance: config.instances.get(config.defaultInstance)! };
}

function refusal(env: Env): ProxmoxError {
  try {
    loadConfig({ ...BASE, ...env });
  } catch (err) {
    if (err instanceof ProxmoxError) return err;
    throw err;
  }
  throw new Error('expected a config error');
}

describe('URL', () => {
  it.each([
    ['https://pve.example', 'https://pve.example:8006'],
    ['https://pve.example/', 'https://pve.example:8006'],
    ['https://pve.example:8006', 'https://pve.example:8006'],
    ['https://pve.example:443', 'https://pve.example:443'],
    ['http://pve.example:80', 'http://pve.example:80'],
    ['pve.example', 'https://pve.example:8006'],
    ['https://pve.example:8006/api2/json', 'https://pve.example:8006'],
    ['https://proxy.example/pve/', 'https://proxy.example:8006/pve'],
    ['https://[fd00::1]', 'https://[fd00::1]:8006'],
    ['https://[fd00::1]:9000', 'https://[fd00::1]:9000'],
    ['https://10.0.0.1', 'https://10.0.0.1:8006'],
  ])('%s becomes %s', (raw, want) => {
    expect(load({ PROXMOX_URL: raw }).instance.url).toBe(want);
  });

  it('refuses credentials in the URL, other schemes, and nonsense', () => {
    expect(refusal({ PROXMOX_URL: 'https://user:pw@pve.example' }).type).toBe('config_error');
    expect(refusal({ PROXMOX_URL: 'ftp://pve.example' }).type).toBe('config_error');
    expect(refusal({ PROXMOX_URL: 'http://' }).type).toBe('config_error');
    expect(refusal({ PROXMOX_URL: undefined }).message).toContain('PROXMOX_URL');
  });
});

describe('credentials', () => {
  it('reads a full token, with or without the header prefix', () => {
    const { instance } = load();
    expect(instance.tokenId).toBe('mcp@pve!t');
    expect(instance.tokenSecret).toBe('secret');
    expect(instance.password).toBeUndefined();
    expect(load({ PROXMOX_TOKEN: 'PVEAPIToken=a@b!c=d' }).instance.tokenId).toBe('a@b!c');
  });

  it('reads a token in two parts', () => {
    const { instance } = load({ PROXMOX_TOKEN: undefined, PROXMOX_TOKEN_ID: 'a@b!c', PROXMOX_TOKEN_SECRET: 'd' });
    expect(instance.tokenId).toBe('a@b!c');
    expect(instance.tokenSecret).toBe('d');
  });

  it('reads a username and password', () => {
    const { instance } = load({ PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: 'root@pam', PROXMOX_PASSWORD: 'p' });
    expect(instance.username).toBe('root@pam');
    expect(instance.tokenId).toBeUndefined();
  });

  it('reads a credentials file, in both shapes', () => {
    const a = join(dir, 'cred-a');
    writeFileSync(a, '# my token\ntoken_id = a@b!c\ntoken_secret=d\n');
    expect(load({ PROXMOX_TOKEN: undefined, PROXMOX_CREDENTIALS_FILE: a }).instance.tokenSecret).toBe('d');
    const b = join(dir, 'cred-b');
    writeFileSync(b, 'x@y!z=w\r\n');
    expect(load({ PROXMOX_TOKEN: undefined, PROXMOX_CREDENTIALS_FILE: b }).instance.tokenId).toBe('x@y!z');
    const c = join(dir, 'cred-c');
    writeFileSync(c, 'username=root@pam\npassword=a=b\n');
    expect(load({ PROXMOX_TOKEN: undefined, PROXMOX_CREDENTIALS_FILE: c }).instance.password).toBe('a=b');
  });

  it('refuses what cannot work', () => {
    expect(refusal({ PROXMOX_TOKEN: 'nonsense' }).message).toContain('user@realm!tokenid=secret');
    expect(refusal({ PROXMOX_TOKEN: undefined }).message).toContain('no credentials');
    expect(refusal({ PROXMOX_TOKEN: undefined, PROXMOX_TOKEN_ID: 'a@b!c' }).message).toContain('both');
    expect(refusal({ PROXMOX_TOKEN: undefined, PROXMOX_TOKEN_SECRET: 'x' }).message).toContain('both');
    expect(refusal({ PROXMOX_TOKEN: undefined, PROXMOX_TOKEN_ID: 'nope', PROXMOX_TOKEN_SECRET: 'x' }).type).toBe('config_error');
    expect(refusal({ PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: 'root', PROXMOX_PASSWORD: 'p' }).message).toContain('realm');
    expect(refusal({ PROXMOX_TOKEN: undefined, PROXMOX_CREDENTIALS_FILE: join(dir, 'missing') }).message).toContain('Cannot read');
  });
});

describe('flags', () => {
  it('defaults to closed', () => {
    const { instance, config } = load();
    expect(instance).toMatchObject({ allowWrites: false, allowElevated: false, allowGuestExec: false, allowSsh: false, allowSensitive: false, dryRun: false, verifySsl: true });
    expect(config).toMatchObject({ taskWaitSeconds: 30, elicit: true, maxResponseChars: 120_000, toolsets: null, unblocked: [] });
    expect(instance.protectedVmids.size).toBe(0);
    expect(instance.timeoutMs).toBe(30_000);
  });

  it.each(['PROXMOX_ALLOW_WRITES', 'PROXMOX_ALLOW_ELEVATED', 'PROXMOX_ALLOW_GUEST_EXEC', 'PROXMOX_ALLOW_SSH', 'PROXMOX_ALLOW_SENSITIVE', 'PROXMOX_DRY_RUN', 'PROXMOX_VERIFY_SSL', 'PROXMOX_ELICIT', 'PROXMOX_SSH_SUDO'])('%s stops the server on a typo', (name) => {
    expect(refusal({ [name]: 'ture' }).message).toContain('not a boolean');
  });

  it.each([
    ['PROXMOX_TIMEOUT_SECONDS', '0'],
    ['PROXMOX_TIMEOUT_SECONDS', 'abc'],
    ['PROXMOX_TASK_WAIT_SECONDS', '3601'],
    ['PROXMOX_MAX_RESPONSE_CHARS', '1'],
    ['PROXMOX_SSH_PORT', '70000'],
    ['PROXMOX_SSH_TIMEOUT_SECONDS', '-1'],
    ['PROXMOX_SSH_MAX_OUTPUT_BYTES', '1.5'],
  ])('%s=%s stops the server', (name, value) => {
    expect(refusal({ [name]: value }).message).toContain('must be an integer');
  });

  it('reads the rest', () => {
    const { instance, config } = load({
      PROXMOX_ALLOW_WRITES: 'yes',
      PROXMOX_ALLOW_ELEVATED: '1',
      PROXMOX_VERIFY_SSL: 'false',
      PROXMOX_DEFAULT_NODE: 'pve2',
      PROXMOX_PROTECTED_VMIDS: '100, 101',
      PROXMOX_UNBLOCK: 'POST /nodes/{node}/execute, /access/ticket',
      PROXMOX_TASK_WAIT_SECONDS: '5',
      PROXMOX_ELICIT: 'off',
      PROXMOX_TOOLSETS: 'VM, lxc',
      PROXMOX_LOCAL_DIR: dir,
    });
    expect(instance).toMatchObject({ allowWrites: true, allowElevated: true, verifySsl: false, defaultNode: 'pve2', localDir: dir });
    expect([...instance.protectedVmids]).toEqual([100, 101]);
    expect(config.unblocked).toEqual(['POST /nodes/{node}/execute', '/access/ticket']);
    expect(config.taskWaitSeconds).toBe(5);
    expect(config.elicit).toBe(false);
    expect([...config.toolsets!]).toEqual(['vm', 'lxc']);
  });

  it('refuses a bad vmid or node name', () => {
    expect(refusal({ PROXMOX_PROTECTED_VMIDS: '100,abc' }).message).toContain('not a vmid');
    expect(refusal({ PROXMOX_DEFAULT_NODE: 'a/b' }).message).toContain('not a node name');
  });
});

describe('TLS settings', () => {
  it('normalizes a fingerprint', () => {
    const lower = TLS_FINGERPRINT.replace(/:/g, '').toLowerCase();
    expect(normalizeFingerprint(lower, 'x')).toBe(TLS_FINGERPRINT);
    expect(normalizeFingerprint(`sha256:${TLS_FINGERPRINT}`, 'x')).toBe(TLS_FINGERPRINT);
    expect(load({ PROXMOX_FINGERPRINT: TLS_FINGERPRINT }).instance.fingerprint).toBe(TLS_FINGERPRINT);
    expect(() => normalizeFingerprint('AA:BB', 'x')).toThrow(/sha256/);
  });

  it('reads the CA file, and refuses a missing one', () => {
    const file = join(dir, 'ca.pem');
    writeFileSync(file, TLS_CERT);
    expect(load({ PROXMOX_CA_FILE: file }).instance.ca).toBe(TLS_CERT);
    expect(refusal({ PROXMOX_CA_FILE: join(dir, 'nope') }).message).toContain('Cannot read');
  });
});

describe('SSH settings', () => {
  it('has fail-closed defaults', () => {
    const { ssh } = load().instance;
    expect(ssh).toMatchObject({ user: 'root', port: 22, sudo: false, hostKeyPolicy: 'strict', timeoutMs: 120_000, maxOutputBytes: 1_048_576, nodes: {}, fingerprints: {} });
    expect(ssh.knownHosts).toBe(join(homedir(), '.ssh', 'known_hosts'));
  });

  it('reads every setting', () => {
    const key = join(dir, 'id_test');
    writeFileSync(key, 'not really a key');
    const fingerprint = `SHA256:${'A'.repeat(43)}`;
    const { instance } = load({
      PROXMOX_ALLOW_SSH: 'true',
      PROXMOX_SSH_USER: 'ops',
      PROXMOX_SSH_PORT: '2222',
      PROXMOX_SSH_KEY_FILE: key,
      PROXMOX_SSH_KEY_PASSPHRASE: 'pp',
      PROXMOX_SSH_PASSWORD: 'pw',
      PROXMOX_SSH_AGENT: 'pageant',
      PROXMOX_SSH_NODES: 'pve1=10.0.0.1,pve2=10.0.0.2',
      PROXMOX_SSH_SUDO: 'true',
      PROXMOX_SSH_KNOWN_HOSTS: '~/custom_known_hosts',
      PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new',
      PROXMOX_SSH_FINGERPRINTS: `pve1=${fingerprint}`,
      PROXMOX_SSH_TIMEOUT_SECONDS: '10',
      PROXMOX_SSH_MAX_OUTPUT_BYTES: '2048',
      PROXMOX_GUEST_SSH_USER: 'admin',
      PROXMOX_GUEST_SSH_KEY_FILE: key,
      PROXMOX_GUEST_SSH_PASSWORD: 'gpw',
    });
    expect(instance.allowSsh).toBe(true);
    expect(instance.ssh).toEqual({
      user: 'ops',
      port: 2222,
      keyFile: key,
      keyPassphrase: 'pp',
      password: 'pw',
      agent: 'pageant',
      nodes: { pve1: '10.0.0.1', pve2: '10.0.0.2' },
      sudo: true,
      knownHosts: join(homedir(), 'custom_known_hosts'),
      hostKeyPolicy: 'accept-new',
      fingerprints: { pve1: fingerprint },
      timeoutMs: 10_000,
      maxOutputBytes: 2048,
      guestUser: 'admin',
      guestKeyFile: key,
      guestPassword: 'gpw',
    });
  });

  it('reads maps as JSON or as a list', () => {
    expect(parseMap('x', '{"a": "1", "b": "2"}')).toEqual({ a: '1', b: '2' });
    expect(parseMap('x', 'a=1, b=c=d')).toEqual({ a: '1', b: 'c=d' });
    expect(parseMap('x', { a: '1' })).toEqual({ a: '1' });
    expect(parseMap('x', undefined)).toEqual({});
    expect(() => parseMap('x', 'nope')).toThrow(/name=value/);
    expect(() => parseMap('x', '{bad json')).toThrow(/invalid JSON/);
    expect(() => parseMap('x', { 'a/b': '1' })).toThrow(/invalid entry/);
  });

  it('refuses a bad policy or fingerprint', () => {
    expect(refusal({ PROXMOX_SSH_HOST_KEY_POLICY: 'yolo' }).message).toContain('strict');
    expect(refusal({ PROXMOX_SSH_FINGERPRINTS: 'pve1=MD5:aa' }).message).toContain('SHA256');
  });

  it('only checks credentials and key files when SSH is on', () => {
    expect(load({ PROXMOX_SSH_KEY_FILE: join(dir, 'missing') }).instance.ssh.keyFile).toBe(join(dir, 'missing'));
    expect(refusal({ PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_KEY_FILE: join(dir, 'missing') }).message).toContain('Cannot read');
    expect(refusal({ PROXMOX_ALLOW_SSH: 'true' }).message).toContain('no SSH credential');
    expect(load({ PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_AGENT: 'pageant' }).instance.allowSsh).toBe(true);
  });
});

describe('several clusters', () => {
  function file(content: unknown): string {
    const path = join(dir, `instances-${Math.random().toString(16).slice(2)}.json`);
    writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
    return path;
  }

  it('reads instances, expands variables and takes defaults from the environment', () => {
    const config = loadConfig({
      PROXMOX_CONFIG: file({
        default: 'lab',
        instances: {
          prod: { url: 'https://prod', token: '${PROD_TOKEN}', allow_writes: false, protected_vmids: [100], ssh: { user: 'ops', nodes: { p1: '10.0.0.1' } } },
          lab: { url: 'https://lab:8007', token_id: 'a@b!c', token_secret: '${LAB_SECRET}', fingerprint: TLS_FINGERPRINT, description: 'Lab', default_node: 'n1', timeout_seconds: 5, local_dir: dir },
        },
      }),
      PROD_TOKEN: 'x@y!z=w',
      LAB_SECRET: 's',
      PROXMOX_ALLOW_WRITES: 'true',
      PROXMOX_SSH_PORT: '2200',
    });
    expect(config.defaultInstance).toBe('lab');
    const prod = config.instances.get('prod')!;
    const lab = config.instances.get('lab')!;
    expect(prod).toMatchObject({ url: 'https://prod:8006', tokenId: 'x@y!z', allowWrites: false });
    expect([...prod.protectedVmids]).toEqual([100]);
    expect(prod.ssh).toMatchObject({ user: 'ops', port: 2200, nodes: { p1: '10.0.0.1' } });
    expect(lab).toMatchObject({ url: 'https://lab:8007', tokenSecret: 's', allowWrites: true, fingerprint: TLS_FINGERPRINT, description: 'Lab', defaultNode: 'n1', timeoutMs: 5000, localDir: dir });
  });

  it('refuses what is wrong', () => {
    const load = (content: unknown, env: Env = {}) => loadConfig({ PROXMOX_CONFIG: file(content), ...env });
    expect(() => load('{not json')).toThrow(/Cannot read PROXMOX_CONFIG/);
    expect(() => load({ instances: {} })).toThrow(/defines no instances/);
    expect(() => load({ default: 'x', instances: { a: { url: 'https://a', token: 'a@b!c=d' } } })).toThrow(/Default instance/);
    expect(() => load({ instances: { 'bad name': { url: 'https://a', token: 'a@b!c=d' } } })).toThrow(/Invalid instance name/);
    expect(() => load({ instances: { a: { token: 'a@b!c=d' } } })).toThrow(/url is required/);
    expect(() => load({ instances: { a: { url: 'https://a', token: '${MISSING}' } } })).toThrow(/MISSING is not set/);
    expect(() => load({ instances: { a: { url: 'https://a', token: 'a@b!c=d', allow_writes: 'maybe' } } })).toThrow(/not a boolean/);
  });
});

describe('local paths', () => {
  const root = join(dir, 'transfers');

  it('refuses everything without PROXMOX_LOCAL_DIR', () => {
    expect(() => resolveLocalPath(undefined, 'x', { mustExist: false })).toThrow(/off on this server/);
  });

  it('accepts what is inside, relative or absolute, and refuses what is outside', () => {
    const { mkdirSync } = process.getBuiltinModule('node:fs');
    mkdirSync(join(root, 'sub'), { recursive: true });
    writeFileSync(join(root, 'sub', 'a.txt'), 'a');
    writeFileSync(join(dir, 'outside.txt'), 'b');
    expect(resolveLocalPath(root, 'sub/a.txt', { mustExist: true }).endsWith('a.txt')).toBe(true);
    expect(resolveLocalPath(root, join(root, 'sub', 'a.txt'), { mustExist: true }).endsWith('a.txt')).toBe(true);
    expect(resolveLocalPath(root, 'sub/new.txt', { mustExist: false }).endsWith('new.txt')).toBe(true);

    for (const path of ['../outside.txt', join(dir, 'outside.txt'), 'sub/../../outside.txt']) {
      let type: string | undefined;
      try {
        resolveLocalPath(root, path, { mustExist: true });
      } catch (err) {
        type = (err as ProxmoxError).type;
      }
      expect(type, path).toBe('local_path_refused');
    }
    expect(() => resolveLocalPath(root, '.', { mustExist: true })).toThrow(/outside/);
    expect(() => resolveLocalPath(root, 'missing.txt', { mustExist: true })).toThrow(/cannot be read/);
    expect(() => resolveLocalPath(root, 'no/such/dir/x', { mustExist: false })).toThrow(/cannot be read/);
    expect(() => resolveLocalPath(root, 'a\0b', { mustExist: false })).toThrow(/NUL/);
  });

  it('follows links before deciding', () => {
    // A junction: a file symlink needs a privilege on Windows, this needs none. Elsewhere the type is ignored.
    symlinkSync(dir, join(root, 'link'), 'junction');
    expect(() => resolveLocalPath(root, 'link/outside.txt', { mustExist: true })).toThrow(/outside/);
    expect(() => resolveLocalPath(root, 'link/new.txt', { mustExist: false })).toThrow(/outside/);
  });
});
