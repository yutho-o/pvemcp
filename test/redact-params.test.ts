import { describe, expect, it } from 'vitest';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { encodePairs, encodeSshKeys, flattenParams } from '../src/proxmox/params.js';
import { catalog } from '../src/catalog/index.js';
import { assertNoRedactedValue, isSensitiveKey, REDACTED, redactJson, redactRequest, redactResponse, scrubText } from '../src/proxmox/redact.js';

describe('redaction', () => {
  it.each(['password', 'secret', 'token', 'eab-hmac-key', 'key', 'cipassword', 'encryption-key', 'keyring', 'keys', 'cert', 'certkey', 'client-key', 'confirmation-password', 'lock-token', 'corosync_authkey', 'ticket', 'CSRFPreventionToken', 'vncticket', 'smtp_password'])('treats %s as secret', (key) => {
    expect(isSensitiveKey(key)).toBe(true);
  });

  it.each(['sshkeys', 'ssh-public-keys', 'fingerprint', 'public_key', 'public-key', 'tokenid', 'full-tokenid', 'tokens', 'keyboard', 'token-coefficient', 'verify-certificate', 'keyctl', 'pre-enrolled-keys', 'master-pubkey', 'privsep', 'privs', 'unprivileged', 'digest', 'description', 'Key'])('keeps %s, which an agent needs', (key) => {
    expect(isSensitiveKey(key)).toBe(false);
  });

  it('masks nested secrets, keeps empty ones visible', () => {
    expect(redactJson({ a: { password: 'x', name: 'n' }, list: [{ secret: 's' }], cipassword: '' })).toEqual({
      a: { password: REDACTED, name: 'n' },
      list: [{ secret: REDACTED }],
      cipassword: '',
    });
  });

  it('keeps the metadata in tokens, and masks what is secret in it', () => {
    const users = [{ userid: 'root@pam', keys: 'x', tokens: [{ tokenid: 'mcp', privsep: 1, expire: 0 }] }];
    expect(redactJson(users)).toEqual([{ userid: 'root@pam', keys: REDACTED, tokens: [{ tokenid: 'mcp', privsep: 1, expire: 0 }] }]);
  });

  it('keeps APT repository options, whose name field is called Key', () => {
    const repo = { options: [{ Key: 'Types', Values: ['deb'] }] };
    expect(redactJson(repo)).toEqual(repo);
  });

  it('applies path rules to fields whose name says nothing', () => {
    expect(redactResponse('/cluster/acme/plugins', [{ plugin: 'cf', data: 'CF_Token=abc' }])).toEqual([{ plugin: 'cf', data: REDACTED }]);
    expect(redactResponse('/cluster/acme/plugins/{id}', { plugin: 'cf', data: 'CF_Token=abc' })).toEqual({ plugin: 'cf', data: REDACTED });
    expect(redactResponse('/access/users/{userid}/token/{tokenid}', { 'full-tokenid': 'a@b!c', value: 'uuid' })).toEqual({ 'full-tokenid': 'a@b!c', value: REDACTED });
    expect(redactResponse('/cluster/config/join', { corosync_authkey: 'x', pve_fp: 'AA' })).toEqual({ corosync_authkey: REDACTED, pve_fp: 'AA' });
    // Elsewhere those names are plain data.
    expect(redactResponse('/nodes/{node}/rrddata', { data: 'x', value: 'y' })).toEqual({ data: 'x', value: 'y' });
  });

  it('scrubs PEM private keys from any text, including an unterminated one', () => {
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----';
    expect(scrubText(`before ${pem} after`)).toBe(`before ${REDACTED} after`);
    expect(scrubText('x -----BEGIN RSA PRIVATE KEY-----\nabc')).toBe(`x ${REDACTED}`);
    expect(scrubText('-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----')).toContain('BEGIN CERTIFICATE');
    expect(redactJson({ log: pem })).toEqual({ log: REDACTED });
  });

  it('strips escape sequences and control characters, keeps line structure', () => {
    expect(scrubText('\u001b[31mred\u001b[0m')).toBe('red');
    expect(scrubText('\u001b]0;title\u0007ok')).toBe('ok');
    expect(scrubText('a\u0000b\u0008c\u009bd')).toBe('abcd');
    expect(scrubText('line1\nline2\tx\r\n')).toBe('line1\nline2\tx\r\n');
  });

  it('removes credentials from URLs', () => {
    expect(scrubText('http_proxy: http://user:pw@proxy:3128/x')).toBe(`http_proxy: http://${REDACTED}@proxy:3128/x`);
    expect(scrubText('https://example.com:8006/api')).toBe('https://example.com:8006/api');
  });

  it('refuses a placeholder written back as a real value', () => {
    const refuses = (v: unknown) => expect(() => assertNoRedactedValue(v, '/x')).toThrow(ProxmoxError);
    refuses(REDACTED);
    refuses('**********');
    refuses({ a: { b: [REDACTED] } });
    refuses({ cipassword: '**********' });
    refuses({ prop: `user=x,password=${REDACTED}` });
    expect(() => assertNoRedactedValue({ a: 'fine', n: 1, t: true, u: undefined }, '/x')).not.toThrow();
  });
});

describe('redaction, against the schema', () => {
  const namesOf = (lists: Array<string[] | undefined>) => [...new Set(lists.flatMap((l) => l ?? []))].sort();

  it('masks exactly these returned fields of the whole API', () => {
    const fields = namesOf(catalog.endpoints.flatMap((e) => [e.returns.properties, e.returns.itemProperties]));
    expect(fields.length).toBeGreaterThan(300);
    expect(fields.filter(isSensitiveKey)).toMatchInlineSnapshot(`
      [
        "CSRFPreventionToken",
        "cert",
        "cipassword",
        "corosync_authkey",
        "key",
        "keys",
        "lock-token",
        "password",
        "recovery",
        "secret",
        "ticket",
      ]
    `);
  });

  it('masks exactly these parameters of the whole API', () => {
    const params = namesOf(catalog.endpoints.map((e) => Object.keys(e.params)));
    expect(params.filter(isSensitiveKey)).toMatchInlineSnapshot(`
      [
        "cert",
        "certkey",
        "cipassword",
        "client-key",
        "confirmation-password",
        "eab-hmac-key",
        "encryption-key",
        "key",
        "keyring",
        "keys",
        "lock-token",
        "otel-headers",
        "otp",
        "password",
        "secret",
        "ticket",
        "token",
        "totp",
        "vncticket",
      ]
    `);
  });

  it.each(['tokenid', 'full-tokenid', 'tokens', 'sshkeys', 'ssh-public-keys', 'public_key', 'master-pubkey', 'fingerprint', 'keyboard', 'keyctl', 'token-coefficient', 'verify-certificate', 'privsep', 'totp-locked', 'public-key-bits', 'public-key-type', 'pve_fp', 'pem', 'filename', 'certificates'])(
    'keeps %s, which is public and useful',
    (key) => {
      expect(isSensitiveKey(key)).toBe(false);
    },
  );

  it('keeps the name of each setting in pending changes, and masks the value of a secret one', () => {
    const rows = [
      { key: 'cores', value: 2, pending: 4 },
      { key: 'cipassword', value: 'old', pending: 'new' },
      { key: 'memory', delete: 1 },
    ];
    const expected = [
      { key: 'cores', value: 2, pending: 4 },
      { key: 'cipassword', value: REDACTED, pending: REDACTED },
      { key: 'memory', delete: 1 },
    ];
    expect(redactResponse('/nodes/{node}/qemu/{vmid}/pending', rows)).toEqual(expected);
    expect(redactResponse('/nodes/pve1/qemu/100/pending', rows)).toEqual(expected);
    expect(redactResponse('/nodes/{node}/lxc/{vmid}/pending', rows)).toEqual(expected);
    expect(redactResponse('/nodes/{node}/qemu/{vmid}/cloudinit', rows)).toEqual(expected);
    // On any other answer, a field called key is still a key.
    expect(redactResponse('/nodes/{node}/subscription', { key: 'pve2c-abc' })).toEqual({ key: REDACTED });
  });

  it('keeps the settings named in the warnings of an import', () => {
    const answer = { warnings: [{ type: 'ignored', key: 'cores', value: '2' }] };
    expect(redactResponse('/nodes/{node}/storage/{storage}/import-metadata', answer)).toEqual(answer);
  });

  it('keeps the corosync token timeout, which is not a token', () => {
    expect(redactResponse('/cluster/config/totem', { token: 3000, version: 2 })).toEqual({ token: 3000, version: 2 });
    expect(redactResponse('/cluster/metrics/server/{id}', { token: 'abc' })).toEqual({ token: REDACTED });
  });

  it('masks the headers of a metric server, the headers and body of a webhook, and the path of its address', () => {
    expect(redactResponse('/cluster/metrics/server/{id}', { 'otel-headers': 'QXV0aDogeA==', 'otel-path': '/v1/metrics' })).toEqual({ 'otel-headers': REDACTED, 'otel-path': '/v1/metrics' });
    const hook = { name: 'chat', url: 'https://hooks.example.com/services/T00/B00/XXXX?x=1', method: 'post', header: ['name=Authorization,value=abc'], body: 'e30=', secret: ['name=x'] };
    const masked = { name: 'chat', url: `https://hooks.example.com/${REDACTED}`, method: 'post', header: REDACTED, body: REDACTED, secret: REDACTED };
    expect(redactResponse('/cluster/notifications/endpoints/webhook/{name}', hook)).toEqual(masked);
    expect(redactResponse('/cluster/notifications/endpoints/webhook', [hook])).toEqual([masked]);
    expect(redactResponse('/cluster/notifications/endpoints/webhook/{name}', { url: 'https://hooks.example.com' })).toEqual({ url: 'https://hooks.example.com' });
    // A plain url stays elsewhere: it says where a download comes from.
    expect(redactResponse('/nodes/{node}/aplinfo', [{ location: 'http://x/y', url: 'http://x/y' }])).toEqual([{ location: 'http://x/y', url: 'http://x/y' }]);
  });

  it('masks the signature of a subscription, which proves it to a server', () => {
    expect(redactResponse('/nodes/{node}/subscription', { status: 'active', signature: 'abc', serverid: 'X' })).toEqual({ status: 'active', signature: REDACTED, serverid: 'X' });
  });

  it('scrubs tokens and tickets quoted in free text', () => {
    expect(scrubText('Authorization: PVEAPIToken=root@pam!mcp=aaaa-bbbb')).toBe(`Authorization: PVEAPIToken=${REDACTED}`);
    expect(scrubText('Cookie: PVEAuthCookie=PVE:root@pam:65A1B2C3::c2ln; x=1')).toBe(`Cookie: PVEAuthCookie=${REDACTED}; x=1`);
    expect(scrubText('ticket PVE:root@pam:65A1B2C3::c2ln+/= end')).toBe(`ticket ${REDACTED} end`);
    expect(scrubText('vnc PVEVNC:65A1B2C3::c2ln end')).toBe(`vnc ${REDACTED} end`);
    // What looks like it, and is fine to read.
    expect(scrubText('UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:')).toBe('UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:');
    expect(scrubText('PVE: all good')).toBe('PVE: all good');
  });

  it.each<[string, Record<string, unknown>, Record<string, unknown>]>([
    ['/cluster/acme/plugins', { id: 'cf', data: 'CF_Token=abc' }, { id: 'cf', data: REDACTED }],
    ['/cluster/acme/plugins/cf', { data: 'CF_Token=abc' }, { data: REDACTED }],
    ['/nodes/pve1/qemu/100/agent/file-write', { file: '/etc/x', content: 'hunter2' }, { file: '/etc/x', content: REDACTED }],
    ['/nodes/pve1/qemu/100/agent/exec', { command: ['cat'], 'input-data': 'hunter2' }, { command: ['cat'], 'input-data': REDACTED }],
    ['/access/tfa/root@pam', { type: 'totp', value: '123456', totp: 'otpauth://x' }, { type: 'totp', value: REDACTED, totp: REDACTED }],
    ['/cluster/notifications/endpoints/webhook', { name: 'x', url: 'https://h.example/secret', header: ['a'], body: 'b' }, { name: 'x', url: `https://h.example/${REDACTED}`, header: REDACTED, body: REDACTED }],
    ['/cluster/metrics/server/x', { server: 'h', port: 1, 'otel-headers': 'abc', token: 't' }, { server: 'h', port: 1, 'otel-headers': REDACTED, token: REDACTED }],
    // The same names, elsewhere, say what the call does.
    ['/storage', { storage: 's', type: 'dir', content: 'iso,backup', password: 'p' }, { storage: 's', type: 'dir', content: 'iso,backup', password: REDACTED }],
    ['/nodes/pve1/hosts', { data: '127.0.0.1 localhost' }, { data: '127.0.0.1 localhost' }],
    ['/cluster/ceph/flags/noout', { value: 1 }, { value: 1 }],
  ])('shows a write to %s as it may be logged', (path, params, expected) => {
    expect(redactRequest(path, params)).toEqual(expected);
  });
});

describe('parameter encoding', () => {
  const flat = (params: Record<string, unknown>, path = '/nodes/{node}/lxc') => flattenParams(path, params);

  it('turns booleans into 1 and 0, numbers into text, and leaves undefined out', () => {
    expect(flat({ a: true, b: false, c: 5, d: 'x', e: undefined, f: null })).toEqual([['a', '1'], ['b', '0'], ['c', '5'], ['d', 'x']]);
  });

  it('repeats the key for arrays', () => {
    expect(flat({ command: ['ls', '-l'] })).toEqual([['command', 'ls'], ['command', '-l']]);
  });

  it('spreads indexed params', () => {
    expect(flat({ net: { 0: 'virtio,bridge=vmbr0', 2: 'e1000' } })).toEqual([['net0', 'virtio,bridge=vmbr0'], ['net2', 'e1000']]);
  });

  it('refuses a non-numeric index, which could write any parameter', () => {
    expect(() => flat({ net: { 'x&y=1': 'a' } })).toThrow(/numeric indexes/);
  });

  it('encodes QEMU sshkeys one extra time, with %20 and never +', () => {
    const key = 'ssh-ed25519 AAAA+B/C= me@host\n';
    const [pair] = flattenParams('/nodes/{node}/qemu/{vmid}/config', { sshkeys: key });
    expect(pair).toEqual(['sshkeys', 'ssh-ed25519%20AAAA%2BB%2FC%3D%20me%40host%0A']);
    const wire = encodePairs([pair!]);
    expect(wire).toBe('sshkeys=ssh-ed25519%2520AAAA%252BB%252FC%253D%2520me%2540host%250A');
    expect(wire).not.toContain('+');
    // What the Proxmox side does: form-decode, then URI-decode.
    expect(decodeURIComponent(decodeURIComponent(wire.slice('sshkeys='.length)))).toBe(key);
    expect(flattenParams('/nodes/{node}/qemu', { sshkeys: key })[0]![1]).toBe(pair![1]);
  });

  it('does not double-encode a value read back from a VM config', () => {
    expect(encodeSshKeys('ssh-ed25519%20AAAA%2BB%0A')).toBe('ssh-ed25519%20AAAA%2BB%0A');
  });

  it('leaves LXC ssh-public-keys plain', () => {
    const key = 'ssh-ed25519 AAAA+B me@host';
    expect(flattenParams('/nodes/{node}/lxc', { 'ssh-public-keys': key })).toEqual([['ssh-public-keys', key]]);
    expect(flattenParams('/nodes/{node}/lxc/{vmid}/config', { sshkeys: key })).toEqual([['sshkeys', key]]);
  });

  it('form-encodes spaces as %20', () => {
    expect(encodePairs([['a b', 'c d&e=f']])).toBe('a%20b=c%20d%26e%3Df');
  });
});
