// The Proxmox client, through the tools of the Rust binary: what reaches the fake Proxmox, and what
// comes back. What no tool can reach (a read-only scope at the client itself, includeSensitive, a
// ticket close to its expiry) is in the unit tests of src/proxmox/client.rs.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FAKE_PASSWORD, FAKE_USER, FakePve, pveError, Reply, RESET, type FakeOptions } from './fake-pve.js';
import { closeAll, connect, type Env } from './harness.js';
import { OTHER_FINGERPRINT, TLS_CERT, TLS_FINGERPRINT, TLS_KEY } from './tls-fixture.js';

const cleanups: Array<() => unknown> = [];
afterEach(async () => {
  await closeAll();
  for (const c of cleanups.splice(0)) await c();
});

const DRY_RUN_UPID = 'UPID:dry-run:00000000:00000000:00000000:dryrun:0:dry-run@pam:';
const PASSWORD_ENV: Env = { PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: FAKE_USER, PROXMOX_PASSWORD: FAKE_PASSWORD };
const WRITES: Env = { PROXMOX_ALLOW_WRITES: 'true' };
const ELEVATED: Env = { PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true' };

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'pvemcp-'));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function setup(env: Env = {}, fakeOptions: FakeOptions = {}) {
  const fake = new FakePve(fakeOptions);
  await fake.start();
  const h = await connect({ fake, env });
  /** Any method and path, without waiting for a task. */
  const write = (method: string, path: string, params?: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
    h.call('pve_api_write', { method, path, ...(params ? { params } : {}), wait: false, ...extra });
  const read = (path: string, params?: Record<string, unknown>) => h.call('pve_api_read', { path, ...(params ? { params } : {}) });
  return { ...h, fake, write, read };
}

describe('token auth', () => {
  it('sends the API token header and unwraps data', async () => {
    const { fake, call } = await setup();
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
    const req = fake.requests[0]!;
    expect(req.headers.authorization).toMatch(/^PVEAPIToken=/);
    expect(req.auth).toBe('token');
    expect(req.rawUrl).toBe('/api2/json/version');
    expect(req.headers.cookie).toBeUndefined();
  });

  it('reports a rejected token as auth_failed, once', async () => {
    const { fake, call } = await setup({ PROXMOX_TOKEN: 'mcp@pve!test=wrong' });
    const { data } = await call('pve_get_version');
    expect(data.error_type).toBe('auth_failed');
    expect(data.http_status).toBe(401);
    expect(data.error).toContain('authentication failure');
    expect(fake.requests).toHaveLength(1);
  });

  it('refuses a method that takes no token before sending anything', async () => {
    const { fake, write } = await setup(ELEVATED);
    for (const [method, path] of [['PUT', '/access/password'], ['POST', '/access/tfa/root@pam'], ['DELETE', '/access/tfa/root@pam/x'], ['PUT', '/access/tfa/root@pam/x']] as const) {
      const { data } = await write(method, path);
      expect(data.error_type, `${method} ${path}`).toBe('forbidden');
      expect(data.hint).toContain('PROXMOX_USERNAME');
    }
    expect(fake.requests).toHaveLength(0);
  });
});

describe('ticket auth', () => {
  it('logs in with a form body, sends the cookie, and CSRF only on writes', async () => {
    const { fake, call, write } = await setup({ ...PASSWORD_ENV, ...WRITES });
    await call('pve_get_version');
    const login = fake.requests[0]!;
    expect(login.path).toBe('/access/ticket');
    expect(login.body).toEqual({ username: FAKE_USER, password: FAKE_PASSWORD });
    expect(login.headers['content-type']).toContain('x-www-form-urlencoded');

    const read = fake.requests[1]!;
    expect(read.auth).toBe('ticket');
    expect(read.headers.cookie).toMatch(/^PVEAuthCookie=/);
    expect(read.headers.csrfpreventiontoken).toBeUndefined();
    expect(read.headers.authorization).toBeUndefined();

    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).isError).toBe(false);
    const sent = fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/start')[0]!;
    expect(sent.auth).toBe('ticket');
    expect(sent.headers.csrfpreventiontoken).toBeDefined();
    expect(fake.logins).toBe(1);
  });

  it('logs in only once for concurrent requests', async () => {
    const { fake, call } = await setup(PASSWORD_ENV);
    await Promise.all([call('pve_get_version'), call('pve_list_nodes'), call('pve_get_cluster_status')]);
    expect(fake.logins).toBe(1);
  });

  it('renews on 401 and retries once, even for a write: nothing ran', async () => {
    const { fake, call, write } = await setup({ ...PASSWORD_ENV, ...WRITES });
    await call('pve_get_version');
    fake.expireTickets();
    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).isError).toBe(false);
    expect(fake.logins).toBe(2);
    const attempts = fake.requests.filter((r) => r.path === '/nodes/pve1/qemu/100/status/start');
    expect(attempts).toHaveLength(2);
    expect(attempts[0]!.auth).toBe('none');
    expect(attempts[1]!.auth).toBe('ticket');
  });

  it('gives up after one renewal', async () => {
    const { fake, call } = await setup(PASSWORD_ENV);
    fake.on('GET', '/version', () => pveError(401, 'authentication failure'));
    expect((await call('pve_get_version')).data.error_type).toBe('auth_failed');
    expect(fake.requests.filter((r) => r.path === '/version')).toHaveLength(2);
  });

  it('says so when the account needs TFA', async () => {
    const { call } = await setup(PASSWORD_ENV, { tfaUsers: [FAKE_USER] });
    const { data } = await call('pve_get_version');
    expect(data.error_type).toBe('auth_failed');
    expect(data.error).toContain('two-factor');
    expect(data.hint).toContain('PROXMOX_TOKEN');
  });

  it('reports a bad password without retrying', async () => {
    const { fake, call } = await setup({ ...PASSWORD_ENV, PROXMOX_PASSWORD: 'wrong' });
    expect((await call('pve_get_version')).data.error_type).toBe('auth_failed');
    expect(fake.requests).toHaveLength(1);
  });

  it('allows a method that refuses tokens', async () => {
    const { fake, write } = await setup({ ...PASSWORD_ENV, ...ELEVATED }, { permissive: true });
    const res = await write('PUT', '/access/password', { userid: 'a@pve', password: 'longenough', 'confirmation-password': 'x' });
    expect(res.isError, res.text).toBe(false);
    expect(fake.find('PUT', '/access/password')).toHaveLength(1);
  });
});

describe('request encoding', () => {
  it('sends query strings on GET and DELETE, form bodies on POST and PUT', async () => {
    const guests = [{ vmid: 101, type: 'lxc' as const }, { vmid: 102, type: 'lxc' as const, status: 'stopped' }];
    const { fake, read, write } = await setup(WRITES, { lenient: true, permissive: true, guests });
    await read('/cluster/resources', { type: 'vm' });
    expect(fake.requests.at(-1)!.rawUrl).toBe('/api2/json/cluster/resources?type=vm');

    // The fake is stateful: this guest is gone afterwards, so the writes below use another one.
    await write('DELETE', '/nodes/pve1/lxc/102', { purge: true, force: true });
    expect(fake.requests.at(-1)!.rawUrl).toBe('/api2/json/nodes/pve1/lxc/102?purge=1&force=1');
    expect(fake.requests.at(-1)!.rawBody).toBe('');

    await write('POST', '/nodes/pve1/lxc/101/status/start', { skiplock: false, timeout: 5 });
    expect(fake.requests.at(-1)!.body).toEqual({ skiplock: '0', timeout: '5' });
    expect(fake.requests.at(-1)!.headers['content-type']).toContain('application/x-www-form-urlencoded');

    await write('PUT', '/nodes/pve1/lxc/101/config', { net: { 0: 'name=eth0,bridge=vmbr0' }, description: 'a b' });
    expect(fake.requests.at(-1)!.body).toEqual({ net0: 'name=eth0,bridge=vmbr0', description: 'a b' });
  });

  it('repeats keys for arrays', async () => {
    const { fake, write } = await setup({ ...WRITES, PROXMOX_ALLOW_GUEST_EXEC: 'true' }, { permissive: true });
    await write('POST', '/nodes/pve1/qemu/100/agent/exec', { command: ['ls', '-l'] });
    expect(fake.requests.at(-1)!.body.command).toEqual(['ls', '-l']);
  });

  it('delivers sshkeys in the shape qemu-server expects, and LXC keys as they are', async () => {
    const { fake, write } = await setup(WRITES);
    const key = 'ssh-ed25519 AAAA+B/C= me@host';
    await write('PUT', '/nodes/pve1/qemu/100/config', { sshkeys: key });
    const seen = fake.requests.at(-1)!.body.sshkeys as string;
    expect(seen).toBe(encodeURIComponent(key));
    expect(decodeURIComponent(seen)).toBe(key);
    await write('PUT', '/nodes/pve1/lxc/101/config', { description: key });
    expect(fake.requests.at(-1)!.body.description).toBe(key);
  });

  it('encodes values through path_params, one segment each', async () => {
    const { fake, write } = await setup(WRITES);
    await write('DELETE', '/nodes/{node}/storage/{storage}/content/{volume}', undefined, { path_params: { node: 'pve1', storage: 'local', volume: 'local:iso/debian.iso' } });
    const req = fake.requests.at(-1)!;
    expect(req.rawUrl).toBe('/api2/json/nodes/pve1/storage/local/content/local:iso%2Fdebian.iso');
    expect(req.template).toBe('/nodes/{node}/storage/{storage}/content/{volume}');
    expect(req.pathParams.volume).toBe('local:iso/debian.iso');
  });

  it('refuses a write that carries a redaction placeholder, before sending it', async () => {
    const { fake, write } = await setup(WRITES);
    for (const value of ['[REDACTED]', '**********']) {
      expect((await write('PUT', '/nodes/pve1/qemu/100/config', { cipassword: value })).data.error_type).toBe('invalid_input');
    }
    expect(fake.requests).toHaveLength(0);
  });
});

describe('error mapping', () => {
  const cases: Array<[string, Reply, string]> = [
    ['validation', pveError(400, 'Parameter verification failed.', { vmid: 'type check failed' }), 'validation_failed'],
    ['forbidden', pveError(403, 'Permission check failed (/vms/100, VM.Audit)'), 'forbidden'],
    ['not found', pveError(404, 'no such thing'), 'not_found'],
    ['not implemented', pveError(501, "Method 'GET /version' not implemented"), 'not_supported'],
    ['lock', pveError(500, "can't lock file '/var/lock/qemu-server/lock-100.conf' - got timeout"), 'guest_locked'],
    ['locked', pveError(500, 'VM is locked (backup)'), 'guest_locked'],
    ['other 500', pveError(500, 'VM 999 not running'), 'upstream_error'],
    ['595', new Reply(595, 'No route to host'), 'node_unreachable'],
    ['596', new Reply(596, 'Connection timed out'), 'node_unreachable'],
  ];

  it.each(cases)('%s', async (_label, reply, type) => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', reply);
    expect((await call('pve_get_version')).data.error_type).toBe(type);
  });

  it('carries field errors and the reason phrase', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', pveError(400, 'Parameter verification failed.', { vmid: 'type check failed' }));
    const { data } = await call('pve_get_version');
    expect(data.details).toEqual({ fields: { vmid: 'type check failed' } });
    expect(data.error).toContain('Parameter verification failed.');
    fake.failNext('GET', '/version', new Reply(500, 'VM 999 not running', { data: null }));
    expect((await call('pve_get_version')).data.error).toContain('VM 999 not running');
  });

  it('puts the needed privileges from the catalog in the hint of a 403', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/nodes/{node}/status', pveError(403, 'Permission check failed'));
    expect((await call('pve_get_node_status', { node: 'pve1' })).data.hint).toContain('Sys.Audit');
  });

  it('scrubs key material out of an error message', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', new Reply(500, 'oops', { data: null, message: 'x -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- y' }));
    const res = await call('pve_get_version');
    expect(res.isError).toBe(true);
    expect(res.text).not.toContain('abc');
  });

  it('reports an HTML answer as bad_response, and points at the URL', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', new Reply(200, 'OK', '<!DOCTYPE html><html></html>', { 'Content-Type': 'text/html' }));
    const { data } = await call('pve_get_version');
    expect(data.error_type).toBe('bad_response');
    expect(data.hint).toContain('PROXMOX_URL');
  });

  it('reports invalid JSON on a write as bad_response, and hands plain text from a GET back', async () => {
    const { fake, write, read } = await setup(WRITES);
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/status/start', new Reply(200, 'OK', 'not json'));
    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).data.error_type).toBe('bad_response');
    fake.failNext('GET', '/nodes/{node}/journal', new Reply(200, 'OK', 'line one\nline \u001b[31mtwo'));
    expect((await read('/nodes/pve1/journal')).data.result).toBe('line one\nline two');
  });

  it('reports a refused connection as unreachable', async () => {
    const { fake, call } = await setup();
    await fake.stop();
    expect((await call('pve_get_version')).data.error_type).toBe('unreachable');
  });

  it('reports a timeout', async () => {
    const { fake, call } = await setup({ PROXMOX_TIMEOUT_SECONDS: '1' });
    fake.on('GET', '/version', () => new Promise((resolve) => setTimeout(() => resolve({}), 3000)));
    expect((await call('pve_get_version')).data.error_type).toBe('timeout');
  });
});

describe('retries', () => {
  it('retries a GET on 502, 503 and 504, twice', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', new Reply(502, 'Bad Gateway'));
    fake.failNext('GET', '/version', new Reply(503, 'Service Unavailable'));
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
    expect(fake.requests).toHaveLength(3);
  });

  it('gives up after two retries', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', new Reply(504, 'Gateway Timeout'), 5);
    expect((await call('pve_get_version')).data.http_status).toBe(504);
    expect(fake.requests).toHaveLength(3);
  });

  it('retries a GET on a connection reset', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', RESET);
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
    expect(fake.requests).toHaveLength(2);
  });

  it('does not retry a GET on a plain 500', async () => {
    const { fake, call } = await setup();
    fake.failNext('GET', '/version', new Reply(500, 'boom'));
    expect((await call('pve_get_version')).isError).toBe(true);
    expect(fake.requests).toHaveLength(1);
  });

  it.each([
    ['POST', '/nodes/pve1/qemu/100/status/start', '/nodes/{node}/qemu/{vmid}/status/start'],
    ['PUT', '/nodes/pve1/qemu/100/config', '/nodes/{node}/qemu/{vmid}/config'],
    ['DELETE', '/nodes/pve1/qemu/100', '/nodes/{node}/qemu/{vmid}'],
  ] as const)('never retries %s, on a gateway error or a reset', async (method, path, template) => {
    const { fake, write } = await setup(WRITES);
    fake.failNext(method, template, new Reply(503, 'Service Unavailable'));
    expect((await write(method, path)).isError).toBe(true);
    expect(fake.requests).toHaveLength(1);
    fake.failNext(method, template, RESET);
    expect((await write(method, path)).isError).toBe(true);
    expect(fake.requests).toHaveLength(2);
  });
});

describe('TLS', () => {
  const tls = { key: TLS_KEY, cert: TLS_CERT };

  it('refuses a self-signed certificate by default', async () => {
    const { fake, call } = await setup({}, { tls });
    const { data } = await call('pve_get_version');
    expect(data.error_type).toBe('tls_error');
    expect(data.hint).toContain('PROXMOX_FINGERPRINT');
    expect(fake.requests).toHaveLength(0);
  });

  it('connects with verification off', async () => {
    const { call } = await setup({ PROXMOX_VERIFY_SSL: 'false' }, { tls });
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
  });

  it('connects with the certificate as CA', async () => {
    const file = join(tempDir(), 'ca.pem');
    writeFileSync(file, TLS_CERT);
    const { call } = await setup({ PROXMOX_CA_FILE: file }, { tls });
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
  });

  it('connects with the right fingerprint pinned, on a self-signed certificate, keeping the connection for the next read', async () => {
    const { fake, call } = await setup({ PROXMOX_FINGERPRINT: TLS_FINGERPRINT }, { tls });
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
    expect((await call('pve_list_nodes')).data.rows).toHaveLength(1);
    expect(fake.requests).toHaveLength(2);
  });

  it('accepts the pin in lower case and without colons', async () => {
    const { call } = await setup({ PROXMOX_FINGERPRINT: TLS_FINGERPRINT.replace(/:/g, '').toLowerCase() }, { tls });
    expect((await call('pve_get_version')).data).toMatchObject({ version: '9.1.0' });
  });

  it('refuses a wrong pin before any request or credential is written, even with verification off', async () => {
    for (const env of [{ PROXMOX_FINGERPRINT: OTHER_FINGERPRINT }, { PROXMOX_FINGERPRINT: OTHER_FINGERPRINT, PROXMOX_VERIFY_SSL: 'false' }]) {
      const { fake, call } = await setup(env, { tls });
      const { data } = await call('pve_get_version');
      expect(data.error_type).toBe('tls_error');
      expect(data.error).toContain('PROXMOX_FINGERPRINT');
      expect(fake.requests).toHaveLength(0);
    }
  });

  it('applies the pin to writes too', async () => {
    const { fake, write } = await setup({ PROXMOX_FINGERPRINT: OTHER_FINGERPRINT, ...WRITES }, { tls });
    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).data.error_type).toBe('tls_error');
    expect(fake.requests).toHaveLength(0);
  });
});

describe('policy at the chokepoint', () => {
  it('refuses a write on a read-only cluster without sending anything', async () => {
    // Write tools are only listed when some cluster takes writes: this one does, the other does not.
    const fake = new FakePve();
    await fake.start();
    const dir = tempDir();
    const file = join(dir, 'instances.json');
    writeFileSync(file, JSON.stringify({ instances: { rw: { url: fake.url, token: 'mcp@pve!test=00000000-0000-0000-0000-000000000000', allow_writes: true }, ro: { url: fake.url, token: 'mcp@pve!test=00000000-0000-0000-0000-000000000000' } } }));
    const { call } = await connect({ fake, env: { PROXMOX_URL: undefined, PROXMOX_TOKEN: undefined, PROXMOX_CONFIG: file } });
    const res = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/status/start', instance: 'ro', wait: false });
    expect(res.data.error_type, res.text).toBe('write_disabled');
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses a change to a protected guest, in a dry run as well', async () => {
    const { fake, write, read } = await setup({ ...WRITES, PROXMOX_PROTECTED_VMIDS: '100' });
    expect((await write('POST', '/nodes/pve1/qemu/100/status/stop')).data.error_type).toBe('protected_guest');
    expect((await write('POST', '/nodes/pve1/qemu/100/status/stop', undefined, { dry_run: true })).data.error_type).toBe('protected_guest');
    expect(fake.requests).toHaveLength(0);
    await read('/nodes/pve1/qemu/100/status/current');
    expect(fake.requests).toHaveLength(1);
  });

  it('records a dry run instead of sending it, with secrets masked', async () => {
    const { fake, write } = await setup(WRITES);
    const created = await write('POST', '/nodes/{node}/qemu', { vmid: 200, cipassword: 'hunter2' }, { path_params: { node: 'pve1' }, dry_run: true });
    expect(created.data.task ?? created.data.upid).toBe(DRY_RUN_UPID);
    expect(created.data.would_send).toEqual([{ method: 'POST', path: '/nodes/pve1/qemu', params: { vmid: 200, cipassword: '[REDACTED]' } }]);
    expect(created.text).not.toContain('hunter2');
    const config = await write('PUT', '/nodes/pve1/qemu/100/config', {}, { dry_run: true });
    expect(config.data.dry_run).toBe(true);
    expect(fake.requests).toHaveLength(0);
  });

  it('still reads in a dry run', async () => {
    const { fake, call, write } = await setup({ ...WRITES, PROXMOX_DRY_RUN: 'true' });
    await call('pve_get_version');
    expect(fake.requests).toHaveLength(1);
    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).data.dry_run).toBe(true);
    expect(fake.requests).toHaveLength(1);
  });

  it('tells about every write, including a failed one, with params masked', async () => {
    const log = join(tempDir(), 'audit.log');
    const { fake, call, write } = await setup({ ...WRITES, PROXMOX_AUDIT_LOG: log });
    await call('pve_get_version');
    await write('PUT', '/nodes/pve1/qemu/100/config', { cipassword: 'hunter2' });
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/status/start', pveError(500, 'nope'));
    expect((await write('POST', '/nodes/pve1/qemu/100/status/start')).isError).toBe(true);
    const text = readFileSync(log, 'utf8');
    expect(text).not.toContain('hunter2');
    const writes = text
      .split('\n')
      .filter(Boolean)
      .flatMap((line) => (JSON.parse(line) as { writes: unknown[] }).writes);
    expect(writes).toEqual([
      { method: 'PUT', path: '/nodes/pve1/qemu/100/config', params: { cipassword: '[REDACTED]' }, status: '200' },
      { method: 'POST', path: '/nodes/pve1/qemu/100/status/start', status: '500' },
    ]);
  });

  it('redacts answers, and only hands over secrets when they are allowed', async () => {
    const closed = await setup(ELEVATED);
    const redacted = (await closed.write('POST', '/access/users/root@pam/token/x')).data;
    expect(redacted.value).toBe('[REDACTED]');
    expect(redacted['full-tokenid']).toBe('root@pam!x');

    const open = await setup({ ...ELEVATED, PROXMOX_ALLOW_SENSITIVE: 'true' });
    expect((await open.write('POST', '/access/users/root@pam/token/x')).data.value).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');

    open.fake.on('GET', '/nodes/{node}/qemu/{vmid}/config', () => ({ cipassword: 'x', name: 'n' }));
    expect((await open.read('/nodes/pve1/qemu/100/config')).data).toEqual({ cipassword: '[REDACTED]', name: 'n' });
  });

  it('keeps the concurrency limit', async () => {
    const { fake, call } = await setup();
    let active = 0;
    let peak = 0;
    fake.on('GET', '/version', async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 50));
      active--;
      return {};
    });
    await Promise.all(Array.from({ length: 12 }, () => call('pve_get_version')));
    expect(peak).toBeLessThanOrEqual(4);
    expect(peak).toBeGreaterThan(1);
  });
});

describe('upload', () => {
  it('streams a multipart body with the fields first', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'x.iso'), Buffer.from([0, 1, 2, 255, 13, 10, 45, 45]));
    const { fake, call } = await setup({ ...PASSWORD_ENV, ...WRITES, PROXMOX_LOCAL_DIR: dir });
    const res = await call('pve_upload_to_storage', { node: 'pve1', storage: 'local', content: 'iso', local_path: 'x.iso', wait: false });
    expect(res.isError, res.text).toBe(false);
    expect(String(res.data.task)).toMatch(/^UPID:pve1:/);
    const req = fake.find('POST', '/nodes/{node}/storage/{storage}/upload')[0]!;
    expect(req.body).toEqual({ content: 'iso' });
    expect(req.file).toMatchObject({ field: 'filename', filename: 'x.iso', bytes: 8 });
    expect([...req.file!.content]).toEqual([0, 1, 2, 255, 13, 10, 45, 45]);
    expect(req.headers.csrfpreventiontoken).toBeDefined();
  });

  it('goes through the same gates', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'x.iso'), 'x');
    const { fake, call } = await setup({ ...WRITES, PROXMOX_LOCAL_DIR: dir, PROXMOX_PROTECTED_VMIDS: '100', PROXMOX_DRY_RUN: 'true' });
    const res = await call('pve_upload_to_storage', { node: 'pve1', storage: 'local', content: 'iso', local_path: 'x.iso', wait: false });
    expect(res.data.dry_run).toBe(true);
    expect(fake.requests).toHaveLength(0);
  });
});
