import { Ajv } from 'ajv';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { afterEach, describe, expect, it } from 'vitest';
import { ALL_GATES, closeAll, connect, WRITES } from './harness.js';

/*
 * What a strict client does with the tool list: the Anthropic API checks input_schema against JSON
 * Schema 2020-12 and refuses top-level combinators, and clients on a subset of JSON Schema refuse
 * keywords they do not know. Nothing here depends on one client: it keeps to what they all take.
 */
afterEach(closeAll);

const CONFIGS = {
  'read-only default': {},
  'writes on': WRITES,
  'everything on': ALL_GATES,
  'api and ssh': { ...ALL_GATES, PROXMOX_TOOLSETS: 'api,ssh' },
};

const ALLOWED_KEYWORDS = new Set(['$schema', 'type', 'properties', 'required', 'additionalProperties', 'description', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'enum', 'items', 'minItems', 'maxItems', 'default', 'anyOf', 'title']);

/** Every keyword of a schema, with where it is. The names of properties are not keywords. */
function keywords(schema: unknown, where: string, out: Array<[string, string]> = []): Array<[string, string]> {
  if (Array.isArray(schema)) schema.forEach((s, i) => keywords(s, `${where}[${i}]`, out));
  else if (schema && typeof schema === 'object') {
    for (const [k, v] of Object.entries(schema)) {
      out.push([k, where]);
      if (k === 'properties') for (const [p, sub] of Object.entries(v as object)) keywords(sub, `${where}.${p}`, out);
      else if (k === 'items' || k === 'additionalProperties' || k === 'anyOf') keywords(v, `${where}.${k}`, out);
    }
  }
  return out;
}

describe('the tool list a strict client receives', () => {
  for (const [name, env] of Object.entries(CONFIGS)) {
    it(`is valid in configuration: ${name}`, async () => {
      const { client } = await connect({ env });
      const { tools } = await client.listTools();
      expect(tools.length).toBeGreaterThan(0);
      const draft7 = new Ajv({ strict: false, validateFormats: false });
      const draft2020 = new Ajv2020({ strict: true, allowUnionTypes: true, validateFormats: false });
      for (const t of tools) {
        expect(t.name).toMatch(/^[a-z0-9_]{1,64}$/);
        // Clients add their own prefix: mcp__proxmox__ takes 14 of the 64 characters some of them allow.
        expect(t.name.length, t.name).toBeLessThanOrEqual(50);
        const schema = t.inputSchema as Record<string, unknown>;
        expect(schema.type, t.name).toBe('object');
        for (const combinator of ['anyOf', 'oneOf', 'allOf', 'not', 'enum']) expect(schema, t.name).not.toHaveProperty(combinator);
        expect(() => draft7.compile(schema), t.name).not.toThrow();
        const { $schema: _ignored, ...plain } = schema;
        expect(() => draft2020.compile(plain), t.name).not.toThrow();
        for (const [keyword, where] of keywords(schema, t.name)) expect(ALLOWED_KEYWORDS.has(keyword), `${where}: ${keyword}`).toBe(true);
        for (const [param, sub] of Object.entries((schema.properties ?? {}) as Record<string, Record<string, unknown>>)) {
          expect(param, t.name).toMatch(/^[a-zA-Z0-9_.-]{1,64}$/);
          expect(sub.description, `${t.name}.${param}`).toBeTruthy();
        }
        for (const required of (schema.required ?? []) as string[]) expect(schema.properties, t.name).toHaveProperty([required]);
      }
      expect(() => JSON.stringify(tools)).not.toThrow();
    });
  }

  it('has no empty additionalProperties, which some clients read as a schema to fill', async () => {
    const { client } = await connect({ env: ALL_GATES });
    for (const t of (await client.listTools()).tools) {
      for (const [keyword, where] of keywords(t.inputSchema, t.name)) expect(keyword === 'propertyNames', where).toBe(false);
      expect(JSON.stringify(t.inputSchema), t.name).not.toContain('"additionalProperties":{}');
    }
  });

  it('keeps the default list within its budget, and says so if it grows', async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.length).toBe(228);
    expect(Buffer.byteLength(JSON.stringify(tools))).toBeLessThan(240 * 1024);
  });
});

describe('arguments', () => {
  it('a curated tool refuses an argument it does not have, instead of dropping it', async () => {
    const { call } = await connect({ env: WRITES });
    const res = await call('pve_guest_power', { vmid: 100, action: 'start', timeout_seconds: 5 });
    expect(res.isError).toBe(true);
    expect(res.text).toContain('timeout_seconds');
  });

  it('a generated tool still takes numbered parameters written flat, and checks the keys of the map form', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const flat = await call('pve_update_vm_config', { vmid: 100, net0: 'virtio,bridge=vmbr0' });
    expect(flat.isError).toBe(false);
    expect(fake.find('PUT', '/nodes/{node}/qemu/{vmid}/config')[0]!.body.net0).toBe('virtio,bridge=vmbr0');
    const before = fake.find('PUT', '/nodes/{node}/qemu/{vmid}/config').length;
    const bad = await call('pve_update_vm_config', { vmid: 100, net: { eth0: 'virtio,bridge=vmbr0' } });
    expect(bad.isError).toBe(true);
    expect(fake.find('PUT', '/nodes/{node}/qemu/{vmid}/config').length).toBe(before);
  });

  it('an unknown argument is refused before a human is asked to confirm the call', async () => {
    const asked: string[] = [];
    const { call, fake } = await connect({
      env: WRITES,
      onElicit: (message) => {
        asked.push(message);
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const res = await call('pve_delete_vm', { vmid: 100, purgee: true });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('invalid_input');
    expect(asked).toEqual([]);
    expect(fake.find('DELETE', '/nodes/{node}/qemu/{vmid}')).toEqual([]);
  });

  it('a container is not privileged by omission', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const refused = await call('pve_create_lxc', { vmid: 310, ostemplate: 'local:vztmpl/x.tar.zst' });
    expect(refused.isError).toBe(true);
    expect(refused.data.error_type).toBe('elevated_disabled');
    expect(refused.data.error).toContain('unprivileged=1');
    expect(fake.find('POST', '/nodes/{node}/lxc')).toEqual([]);
    const through = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/lxc', params: { vmid: 310, ostemplate: 'local:vztmpl/x.tar.zst' } });
    expect(through.data.error_type).toBe('elevated_disabled');
    const ok = await call('pve_create_lxc', { vmid: 310, ostemplate: 'local:vztmpl/x.tar.zst', unprivileged: true });
    expect(ok.isError).toBe(false);
    expect(fake.find('POST', '/nodes/{node}/lxc')[0]!.body.unprivileged).toBe('1');
  });
});
