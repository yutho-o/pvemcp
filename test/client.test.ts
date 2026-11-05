import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig, type Env } from '../src/config.js';
import { ProxmoxClient, type DryRunEntry, type WriteRecord } from '../src/proxmox/client.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { DRY_RUN_UPID } from '../src/proxmox/tasks.js';
import { FAKE_PASSWORD, FAKE_TOKEN, FAKE_USER, FakePve, pveError, Reply, RESET, type FakeOptions } from './fake-pve.js';
import { OTHER_FINGERPRINT, TLS_CERT, TLS_FINGERPRINT, TLS_KEY } from './tls-fixture.js';

const cleanups: Array<() => unknown> = [];
afterEach(async () => {
  for (const c of cleanups.splice(0)) await c();
});

async function setup(env: Env = {}, fakeOptions: FakeOptions = {}, onWrite?: (w: WriteRecord) => void, unblocked: string[] = []) {
  const fake = new FakePve(fakeOptions);
  await fake.start();
  const config = loadConfig({ PROXMOX_URL: fake.url, PROXMOX_TOKEN: FAKE_TOKEN, ...env });
  const client = new ProxmoxClient(config.instances.get('default')!, unblocked, onWrite);
  cleanups.push(() => client.close(), () => fake.stop());
  return { fake, client };
}

const PASSWORD_ENV: Env = { PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: FAKE_USER, PROXMOX_PASSWORD: FAKE_PASSWORD };

async function failure(run: Promise<unknown>): Promise<ProxmoxError> {
  const err = await run.then(() => new Error('expected a failure'), (e: unknown) => e);
  if (!(err instanceof ProxmoxError)) throw err;
  return err;
}

describe('token auth', () => {
  it('sends the API token header and unwraps data', async () => {
    const { fake, client } = await setup();
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
    const req = fake.requests[0]!;
    expect(req.headers.authorization).toBe(`PVEAPIToken=${FAKE_TOKEN}`);
    expect(req.auth).toBe('token');
    expect(req.rawUrl).toBe('/api2/json/version');
    expect(req.headers.cookie).toBeUndefined();
  });

  it('reports a rejected token as auth_failed, once', async () => {
    const { fake, client } = await setup({ PROXMOX_TOKEN: 'mcp@pve!test=wrong' });
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('auth_failed');
    expect(err.status).toBe(401);
    expect(err.message).toContain('authentication failure');
    expect(fake.requests).toHaveLength(1);
  });

  it('refuses a method that takes no token before sending anything', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true' });
    for (const [method, path] of [['PUT', '/access/password'], ['POST', '/access/tfa/root@pam'], ['DELETE', '/access/tfa/root@pam/x'], ['PUT', '/access/tfa/root@pam/x']] as const) {
      const err = await failure(client.request(method, path));
      expect(err.type).toBe('forbidden');
      expect(err.hint).toContain('PROXMOX_USERNAME');
    }
    expect(fake.requests).toHaveLength(0);
  });
});

describe('ticket auth', () => {
  it('logs in with a form body, sends the cookie, and CSRF only on writes', async () => {
    const { fake, client } = await setup({ ...PASSWORD_ENV, PROXMOX_ALLOW_WRITES: 'true' });
    await client.get('/version');
    const login = fake.requests[0]!;
    expect(login.path).toBe('/access/ticket');
    expect(login.body).toEqual({ username: FAKE_USER, password: FAKE_PASSWORD });
    expect(login.headers['content-type']).toContain('x-www-form-urlencoded');

    const read = fake.requests[1]!;
    expect(read.auth).toBe('ticket');
    expect(read.headers.cookie).toMatch(/^PVEAuthCookie=/);
    expect(read.headers.csrfpreventiontoken).toBeUndefined();
    expect(read.headers.authorization).toBeUndefined();

    await client.post('/nodes/pve1/qemu/100/status/start');
    const write = fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/start')[0]!;
    expect(write.auth).toBe('ticket');
    expect(write.headers.csrfpreventiontoken).toBeDefined();
    expect(fake.logins).toBe(1);
  });

  it('logs in only once for concurrent requests', async () => {
    const { fake, client } = await setup(PASSWORD_ENV);
    await Promise.all([client.get('/version'), client.get('/nodes'), client.get('/cluster/status')]);
    expect(fake.logins).toBe(1);
  });

  it('renews on 401 and retries once, even for a write: nothing ran', async () => {
    const { fake, client } = await setup({ ...PASSWORD_ENV, PROXMOX_ALLOW_WRITES: 'true' });
    await client.get('/version');
    fake.expireTickets();
    await client.post('/nodes/pve1/qemu/100/status/start');
    expect(fake.logins).toBe(2);
    const attempts = fake.requests.filter((r) => r.path === '/nodes/pve1/qemu/100/status/start');
    expect(attempts).toHaveLength(2);
    expect(attempts[0]!.auth).toBe('none');
    expect(attempts[1]!.auth).toBe('ticket');
  });

  it('gives up after one renewal', async () => {
    const { fake, client } = await setup(PASSWORD_ENV);
    fake.on('GET', '/version', () => pveError(401, 'authentication failure'));
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('auth_failed');
    expect(fake.requests.filter((r) => r.path === '/version')).toHaveLength(2);
  });

  it('renews a ticket that is close to its two-hour expiry, without waiting for a 401', async () => {
    const { fake, client } = await setup(PASSWORD_ENV);
    await client.get('/version');
    const internal = client as unknown as { ticket: { at: number } };
    internal.ticket.at -= 100 * 60 * 1000;
    await client.get('/version');
    expect(fake.logins).toBe(2);
    expect(fake.requests.filter((r) => r.path === '/version').every((r) => r.auth === 'ticket')).toBe(true);
  });

  it('says so when the account needs TFA', async () => {
    const { client } = await setup(PASSWORD_ENV, { tfaUsers: [FAKE_USER] });
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('auth_failed');
    expect(err.message).toContain('two-factor');
    expect(err.hint).toContain('PROXMOX_TOKEN');
  });

  it('reports a bad password without retrying', async () => {
    const { fake, client } = await setup({ ...PASSWORD_ENV, PROXMOX_PASSWORD: 'wrong' });
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('auth_failed');
    expect(fake.requests).toHaveLength(1);
  });

  it('allows a method that refuses tokens', async () => {
    const { fake, client } = await setup({ ...PASSWORD_ENV, PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true' }, { permissive: true });
    await client.request('PUT', '/access/password', { params: { userid: 'a@pve', password: 'longenough', 'confirmation-password': 'x' } });
    expect(fake.find('PUT', '/access/password')).toHaveLength(1);
  });
});

describe('request encoding', () => {
  it('sends query strings on GET and DELETE, form bodies on POST and PUT', async () => {
    const guests = [{ vmid: 101, type: 'lxc' as const }, { vmid: 102, type: 'lxc' as const, status: 'stopped' }];
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' }, { lenient: true, permissive: true, guests });
    await client.get('/cluster/resources', { params: { type: 'vm' } });
    expect(fake.requests.at(-1)!.rawUrl).toBe('/api2/json/cluster/resources?type=vm');

    // The fake is stateful: this guest is gone afterwards, so the writes below use another one.
    await client.delete('/nodes/pve1/lxc/102', { purge: true, force: true });
    expect(fake.requests.at(-1)!.rawUrl).toBe('/api2/json/nodes/pve1/lxc/102?purge=1&force=1');
    expect(fake.requests.at(-1)!.rawBody).toBe('');

    await client.post('/nodes/pve1/lxc/101/status/start', { skiplock: false, timeout: 5 });
    expect(fake.requests.at(-1)!.body).toEqual({ skiplock: '0', timeout: '5' });
    expect(fake.requests.at(-1)!.headers['content-type']).toContain('application/x-www-form-urlencoded');

    await client.put('/nodes/pve1/lxc/101/config', { net: { 0: 'name=eth0,bridge=vmbr0' }, description: 'a b' });
    expect(fake.requests.at(-1)!.body).toEqual({ net0: 'name=eth0,bridge=vmbr0', description: 'a b' });
  });

  it('repeats keys for arrays', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_GUEST_EXEC: 'true' }, { permissive: true });
    await client.post('/nodes/pve1/qemu/100/agent/exec', { command: ['ls', '-l'] });
    expect(fake.requests.at(-1)!.body.command).toEqual(['ls', '-l']);
  });

  it('delivers sshkeys in the shape qemu-server expects, and LXC keys as they are', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    const key = 'ssh-ed25519 AAAA+B/C= me@host';
    await client.put('/nodes/pve1/qemu/100/config', { sshkeys: key });
    const seen = fake.requests.at(-1)!.body.sshkeys as string;
    expect(seen).toBe(encodeURIComponent(key));
    expect(decodeURIComponent(seen)).toBe(key);
    await client.put('/nodes/pve1/lxc/101/config', { description: key });
    expect(fake.requests.at(-1)!.body.description).toBe(key);
  });

  it('encodes values through pathParams, one segment each', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    await client.delete('/nodes/{node}/storage/{storage}/content/{volume}', undefined, { pathParams: { node: 'pve1', storage: 'local', volume: 'local:iso/debian.iso' } });
    const req = fake.requests.at(-1)!;
    expect(req.rawUrl).toBe('/api2/json/nodes/pve1/storage/local/content/local:iso%2Fdebian.iso');
    expect(req.template).toBe('/nodes/{node}/storage/{storage}/content/{volume}');
    expect(req.pathParams.volume).toBe('local:iso/debian.iso');
  });

  it('refuses a write that carries a redaction placeholder, before sending it', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    for (const value of ['[REDACTED]', '**********']) {
      const err = await failure(client.put('/nodes/pve1/qemu/100/config', { cipassword: value }));
      expect(err.type).toBe('invalid_input');
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
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', reply);
    const err = await failure(client.get('/version'));
    expect(err.type).toBe(type);
  });

  it('carries field errors and the reason phrase', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', pveError(400, 'Parameter verification failed.', { vmid: 'type check failed' }));
    const err = await failure(client.get('/version'));
    expect(err.details).toEqual({ fields: { vmid: 'type check failed' } });
    expect(err.message).toContain('Parameter verification failed.');
    const reasonOnly = new Reply(500, 'VM 999 not running', { data: null });
    fake.failNext('GET', '/version', reasonOnly);
    expect((await failure(client.get('/version'))).message).toContain('VM 999 not running');
  });

  it('puts the needed privileges from the catalog in the hint of a 403', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/nodes/{node}/status', pveError(403, 'Permission check failed'));
    const err = await failure(client.get('/nodes/pve1/status'));
    expect(err.hint).toContain('Sys.Audit');
  });

  it('scrubs key material out of an error message', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', new Reply(500, 'oops', { data: null, message: 'x -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- y' }));
    const err = await failure(client.get('/version'));
    expect(err.message).not.toContain('abc');
  });

  it('reports an HTML answer as bad_response, and points at the URL', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', new Reply(200, 'OK', '<!DOCTYPE html><html></html>', { 'Content-Type': 'text/html' }));
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('bad_response');
    expect(err.hint).toContain('PROXMOX_URL');
  });

  it('reports invalid JSON on a write as bad_response, and hands plain text from a GET back', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/status/start', new Reply(200, 'OK', 'not json'));
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/start'))).type).toBe('bad_response');
    fake.failNext('GET', '/nodes/{node}/journal', new Reply(200, 'OK', 'line one\nline \u001b[31mtwo'));
    expect(await client.get('/nodes/pve1/journal')).toBe('line one\nline two');
  });

  it('reports a refused connection as unreachable', async () => {
    const { client, fake } = await setup();
    await fake.stop();
    expect((await failure(client.get('/version'))).type).toBe('unreachable');
  });

  it('reports a timeout', async () => {
    const { client, fake } = await setup();
    fake.on('GET', '/version', () => new Promise((resolve) => setTimeout(() => resolve({}), 2000)));
    expect((await failure(client.get('/version', { timeoutMs: 50 }))).type).toBe('timeout');
  });
});

describe('retries', () => {
  it('retries a GET on 502, 503 and 504, twice', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', new Reply(502, 'Bad Gateway'));
    fake.failNext('GET', '/version', new Reply(503, 'Service Unavailable'));
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
    expect(fake.requests).toHaveLength(3);
  });

  it('gives up after two retries', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', new Reply(504, 'Gateway Timeout'), 5);
    const err = await failure(client.get('/version'));
    expect(err.status).toBe(504);
    expect(fake.requests).toHaveLength(3);
  });

  it('retries a GET on a connection reset', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', RESET);
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
    expect(fake.requests).toHaveLength(2);
  });

  it('does not retry a GET on a plain 500', async () => {
    const { fake, client } = await setup();
    fake.failNext('GET', '/version', new Reply(500, 'boom'));
    await failure(client.get('/version'));
    expect(fake.requests).toHaveLength(1);
  });

  it.each([
    ['POST', '/nodes/pve1/qemu/100/status/start', '/nodes/{node}/qemu/{vmid}/status/start'],
    ['PUT', '/nodes/pve1/qemu/100/config', '/nodes/{node}/qemu/{vmid}/config'],
    ['DELETE', '/nodes/pve1/qemu/100', '/nodes/{node}/qemu/{vmid}'],
  ] as const)('never retries %s, on a gateway error or a reset', async (method, path, template) => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    fake.failNext(method, template, new Reply(503, 'Service Unavailable'));
    await failure(client.request(method, path));
    expect(fake.requests).toHaveLength(1);
    fake.failNext(method, template, RESET);
    await failure(client.request(method, path));
    expect(fake.requests).toHaveLength(2);
  });
});

describe('TLS', () => {
  const tls = { key: TLS_KEY, cert: TLS_CERT };

  it('refuses a self-signed certificate by default', async () => {
    const { fake, client } = await setup({}, { tls });
    const err = await failure(client.get('/version'));
    expect(err.type).toBe('tls_error');
    expect(err.hint).toContain('PROXMOX_FINGERPRINT');
    expect(fake.requests).toHaveLength(0);
  });

  it('connects with verification off', async () => {
    const { client } = await setup({ PROXMOX_VERIFY_SSL: 'false' }, { tls });
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
  });

  it('connects with the certificate as CA', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-'));
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
    const file = join(dir, 'ca.pem');
    writeFileSync(file, TLS_CERT);
    const { client } = await setup({ PROXMOX_CA_FILE: file }, { tls });
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
  });

  it('connects with the right fingerprint pinned, on a self-signed certificate, keeping the connection for the next read', async () => {
    const { fake, client } = await setup({ PROXMOX_FINGERPRINT: TLS_FINGERPRINT }, { tls });
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
    expect(await client.get('/nodes')).toHaveLength(1);
    expect(fake.requests).toHaveLength(2);
  });

  it('accepts the pin in lower case and without colons', async () => {
    const { client } = await setup({ PROXMOX_FINGERPRINT: TLS_FINGERPRINT.replace(/:/g, '').toLowerCase() }, { tls });
    expect(await client.get('/version')).toMatchObject({ version: '9.1.0' });
  });

  it('refuses a wrong pin before any request or credential is written, even with verification off', async () => {
    for (const env of [{ PROXMOX_FINGERPRINT: OTHER_FINGERPRINT }, { PROXMOX_FINGERPRINT: OTHER_FINGERPRINT, PROXMOX_VERIFY_SSL: 'false' }]) {
      const { fake, client } = await setup(env, { tls });
      const err = await failure(client.get('/version'));
      expect(err.type).toBe('tls_error');
      expect(err.message).toContain('PROXMOX_FINGERPRINT');
      expect(fake.requests).toHaveLength(0);
    }
  });

  it('applies the pin to writes too', async () => {
    const { fake, client } = await setup({ PROXMOX_FINGERPRINT: OTHER_FINGERPRINT, PROXMOX_ALLOW_WRITES: 'true' }, { tls });
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/start'))).type).toBe('tls_error');
    expect(fake.requests).toHaveLength(0);
  });
});

describe('policy at the chokepoint', () => {
  it('refuses a write on a read-only instance without sending anything', async () => {
    const { fake, client } = await setup();
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/start'))).type).toBe('write_disabled');
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses a write from a read scope even when writes are on', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' });
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/start', undefined, { readOnly: true }))).type).toBe('not_read_only');
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses a change to a protected guest, in a dry run as well', async () => {
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true', PROXMOX_PROTECTED_VMIDS: '100' });
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/stop'))).type).toBe('protected_guest');
    expect((await failure(client.post('/nodes/pve1/qemu/100/status/stop', undefined, { dryRun: true }))).type).toBe('protected_guest');
    expect(fake.requests).toHaveLength(0);
    await client.get('/nodes/pve1/qemu/100/status/current');
    expect(fake.requests).toHaveLength(1);
  });

  it('records a dry run instead of sending it, with secrets masked', async () => {
    const { fake, client } = await setup();
    const dryRunLog: DryRunEntry[] = [];
    const answer = await client.post('/nodes/{node}/qemu', { vmid: 200, cipassword: 'hunter2' }, { dryRun: true, dryRunLog, pathParams: { node: 'pve1' } });
    expect(answer).toBe(DRY_RUN_UPID);
    expect(dryRunLog).toEqual([{ method: 'POST', path: '/nodes/pve1/qemu', params: { vmid: 200, cipassword: '[REDACTED]' } }]);
    expect(await client.put('/nodes/pve1/qemu/100/config', {}, { dryRun: true })).toEqual({ dry_run: true });
    expect(fake.requests).toHaveLength(0);
  });

  it('still reads in a dry run', async () => {
    const { fake, client } = await setup({ PROXMOX_DRY_RUN: 'true' });
    await client.get('/version');
    expect(fake.requests).toHaveLength(1);
    await client.post('/nodes/pve1/qemu/100/status/start');
    expect(fake.requests).toHaveLength(1);
  });

  it('tells about every write, including a failed one, with params masked', async () => {
    const writes: WriteRecord[] = [];
    const { fake, client } = await setup({ PROXMOX_ALLOW_WRITES: 'true' }, {}, (w) => writes.push(w));
    await client.get('/version');
    await client.put('/nodes/pve1/qemu/100/config', { cipassword: 'hunter2' });
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/status/start', pveError(500, 'nope'));
    await failure(client.post('/nodes/pve1/qemu/100/status/start'));
    expect(writes).toEqual([
      { method: 'PUT', path: '/nodes/pve1/qemu/100/config', params: { cipassword: '[REDACTED]' }, status: '200' },
      { method: 'POST', path: '/nodes/pve1/qemu/100/status/start', status: '500' },
    ]);
  });

  it('redacts answers, and only hands over secrets when they are allowed and asked for', async () => {
    const elevated = { PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true' };
    const closed = await setup(elevated);
    const redacted = (await closed.client.post('/access/users/root@pam/token/x')) as Record<string, unknown>;
    expect(redacted.value).toBe('[REDACTED]');
    expect(redacted['full-tokenid']).toBe('root@pam!x');

    const open = await setup({ ...elevated, PROXMOX_ALLOW_SENSITIVE: 'true' });
    const shown = (await open.client.post('/access/users/root@pam/token/x')) as Record<string, unknown>;
    expect(shown.value).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');

    open.fake.on('GET', '/nodes/{node}/qemu/{vmid}/config', () => ({ cipassword: 'x', name: 'n' }));
    expect(await open.client.get('/nodes/pve1/qemu/100/config')).toEqual({ cipassword: '[REDACTED]', name: 'n' });
    expect(await open.client.get('/nodes/pve1/qemu/100/config', { includeSensitive: true })).toEqual({ cipassword: 'x', name: 'n' });
    expect(await closed.client.get('/version', { includeSensitive: true })).toMatchObject({ version: '9.1.0' });
  });

  it('keeps the concurrency limit', async () => {
    const { fake, client } = await setup();
    let active = 0;
    let peak = 0;
    fake.on('GET', '/version', async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 20));
      active--;
      return {};
    });
    await Promise.all(Array.from({ length: 12 }, () => client.get('/version')));
    expect(peak).toBeLessThanOrEqual(4);
    expect(peak).toBeGreaterThan(1);
  });
});

describe('upload', () => {
  it('streams a multipart body with the fields first', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-'));
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
    const file = join(dir, 'x.iso');
    writeFileSync(file, Buffer.from([0, 1, 2, 255, 13, 10, 45, 45]));
    const { fake, client } = await setup({ ...PASSWORD_ENV, PROXMOX_ALLOW_WRITES: 'true' });
    const upid = await client.upload('/nodes/{node}/storage/{storage}/upload', { content: 'iso' }, { localPath: file }, { pathParams: { node: 'pve1', storage: 'local' } });
    expect(String(upid)).toMatch(/^UPID:pve1:/);
    const req = fake.find('POST', '/nodes/{node}/storage/{storage}/upload')[0]!;
    expect(req.body).toEqual({ content: 'iso' });
    expect(req.file).toMatchObject({ field: 'filename', filename: 'x.iso', bytes: 8 });
    expect([...req.file!.content]).toEqual([0, 1, 2, 255, 13, 10, 45, 45]);
    expect(req.headers.csrfpreventiontoken).toBeDefined();
  });

  it('goes through the same gates', async () => {
    const { fake, client } = await setup();
    const err = await failure(client.upload('/nodes/{node}/storage/{storage}/upload', { content: 'iso' }, { localPath: 'nope' }, { pathParams: { node: 'pve1', storage: 'local' } }));
    expect(err.type).toBe('write_disabled');
    expect(fake.requests).toHaveLength(0);
  });
});
