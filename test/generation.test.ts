import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { catalog, findEndpoint, templateParams, type HttpMethod } from '../src/catalog/index.js';
import { endpointTools } from '../src/tools/endpoints.js';
import { domainOf, toolName } from '../src/tools/naming.js';
import { FAKE_PASSWORD, FAKE_USER } from './fake-pve.js';
import { ALL_GATES, closeAll, connect, WRITES } from './harness.js';

afterEach(closeAll);

const byName = new Map(endpointTools().map((t) => [t.name, t]));

function def(method: HttpMethod, template: string) {
  const found = byName.get(toolName(method, template));
  if (!found) throw new Error(`No tool for ${method} ${template}`);
  return found;
}

/** The schema an MCP client is shown for this tool. */
async function shownSchema(method: HttpMethod, template: string): Promise<any> {
  const { client } = await connect({ fake: { permissive: true }, env: ALL_GATES });
  const { tools } = await client.listTools();
  return tools.find((t) => t.name === toolName(method, template))!.inputSchema;
}

/** Calls the tool of an endpoint on a fake that checks parameters against the catalog, and gives what went out. */
async function send(method: HttpMethod, template: string, args: Record<string, unknown>) {
  const { call, fake } = await connect({ fake: { permissive: true }, env: { ...ALL_GATES, PROXMOX_TASK_WAIT_SECONDS: '0' } });
  const res = await call(toolName(method, template), args);
  const seen = fake.find(method, template);
  return { res, seen: seen.at(-1), count: seen.length };
}

const QEMU = '/nodes/{node}/qemu';
const VM = `${QEMU}/{vmid}`;
const LXC = '/nodes/{node}/lxc';

describe('what reaches Proxmox, under the exact name it expects', () => {
  it('POST /nodes/{node}/qemu, with every kind of name at once', async () => {
    const key = 'ssh-ed25519 AAAA+B/C= me@host';
    const { res, seen } = await send('POST', QEMU, {
      node: 'pve1',
      vmid: 200,
      name: 'web',
      memory: '2048',
      cores: 4,
      numa: true,
      net: { 0: 'virtio,bridge=vmbr0', 1: 'e1000,bridge=vmbr1' },
      scsi: { 0: 'local-lvm:32,iothread=1' },
      ide: { 2: 'local:iso/debian.iso,media=cdrom' },
      numa_n: { 0: 'cpus=0-1,memory=1024' },
      ipconfig: { 0: 'ip=dhcp' },
      hostpci: { 0: '0000:01:00.0,pcie=1' },
      efidisk0: 'local-lvm:1,efitype=4m',
      tpmstate0: 'local-lvm:1,version=v2.0',
      smbios1: 'uuid=7dd0e4a1-5d6d-4d7a-8d7a-000000000000',
      rng0: 'source=/dev/urandom',
      sshkeys: key,
      'allow-ksm': false,
      'live-restore': false,
    });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({
      vmid: '200',
      name: 'web',
      memory: '2048',
      cores: '4',
      numa: '1',
      net0: 'virtio,bridge=vmbr0',
      net1: 'e1000,bridge=vmbr1',
      scsi0: 'local-lvm:32,iothread=1',
      ide2: 'local:iso/debian.iso,media=cdrom',
      numa0: 'cpus=0-1,memory=1024',
      ipconfig0: 'ip=dhcp',
      hostpci0: '0000:01:00.0,pcie=1',
      efidisk0: 'local-lvm:1,efitype=4m',
      tpmstate0: 'local-lvm:1,version=v2.0',
      smbios1: 'uuid=7dd0e4a1-5d6d-4d7a-8d7a-000000000000',
      rng0: 'source=/dev/urandom',
      // Once for the form, read back here, and once for qemu-server.
      sshkeys: encodeURIComponent(key),
      'allow-ksm': '0',
      'live-restore': '0',
    });
    expect(seen!.rawBody).toContain('sshkeys=ssh-ed25519%2520AAAA%252BB%252FC%253D%2520me%2540host');
  });

  it('net0 and scsi0 as arguments, which is how Proxmox writes them', async () => {
    const { res, seen } = await send('POST', QEMU, { node: 'pve1', vmid: 200, net0: 'virtio,bridge=vmbr0', scsi0: 'local-lvm:32', 'ide[2]': 'none,media=cdrom', numa0: 'cpus=0', net1: 'e1000' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({ vmid: '200', net0: 'virtio,bridge=vmbr0', scsi0: 'local-lvm:32', ide2: 'none,media=cdrom', numa0: 'cpus=0', net1: 'e1000' });
  });

  it.each(['PUT', 'POST'] as const)('%s /nodes/{node}/qemu/{vmid}/config, with the ones that control the change', async (method) => {
    const { res, seen } = await send(method, `${VM}/config`, {
      node: 'pve1',
      vmid: 100,
      delete: 'unused0,cores',
      digest: 'abc',
      force: 1,
      revert: 'memory',
      skiplock: 'yes',
      sshkeys: 'ssh-rsa AAAA x',
      net: { 3: 'virtio' },
      ...(method === 'POST' ? { background_delay: '5' } : {}),
    });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({
      delete: 'unused0,cores',
      digest: 'abc',
      force: '1',
      revert: 'memory',
      skiplock: '1',
      sshkeys: 'ssh-rsa%20AAAA%20x',
      net3: 'virtio',
      ...(method === 'POST' ? { background_delay: '5' } : {}),
    });
  });

  it('POST /nodes/{node}/lxc: ssh-public-keys stays plain', async () => {
    const key = 'ssh-ed25519 AAAA+B me@host';
    const { res, seen } = await send('POST', LXC, {
      node: 'pve1',
      vmid: 201,
      ostemplate: 'local:vztmpl/debian.tar.zst',
      'ssh-public-keys': key,
      rootfs: 'local-lvm:8',
      net: { 0: 'name=eth0,bridge=vmbr0,ip=dhcp' },
      mp: { 0: 'local-lvm:8,mp=/data' },
      dev: { 0: '/dev/fuse' },
      unprivileged: 1,
      memory: '512',
    });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({
      vmid: '201',
      ostemplate: 'local:vztmpl/debian.tar.zst',
      'ssh-public-keys': key,
      rootfs: 'local-lvm:8',
      net0: 'name=eth0,bridge=vmbr0,ip=dhcp',
      mp0: 'local-lvm:8,mp=/data',
      dev0: '/dev/fuse',
      unprivileged: '1',
      memory: '512',
    });
  });

  it('POST /storage: dashes, a secret, a property string', async () => {
    const { res, seen } = await send('POST', '/storage', {
      storage: 'pbs1',
      type: 'pbs',
      content: 'backup',
      'content-dirs': 'backup=dumps',
      'encryption-key': 'autogen',
      'master-pubkey': 'LS0t',
      'prune-backups': 'keep-last=3,keep-daily=7',
      bwlimit: 'default=1000',
    });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({
      storage: 'pbs1',
      type: 'pbs',
      content: 'backup',
      'content-dirs': 'backup=dumps',
      'encryption-key': 'autogen',
      'master-pubkey': 'LS0t',
      'prune-backups': 'keep-last=3,keep-daily=7',
      bwlimit: 'default=1000',
    });
  });

  it('SDN fabrics: the union of the variants, with arrays as repeated parameters', async () => {
    const fabric = await send('POST', '/cluster/sdn/fabrics/fabric', { id: 'f1', protocol: 'ospf', area: '0', ip_prefix: '10.0.0.0/24', redistribute: ['source=connected,route-map=m1', 'source=static'] });
    expect(fabric.res.isError, fabric.res.text).toBe(false);
    expect(fabric.seen!.body).toEqual({ id: 'f1', protocol: 'ospf', area: '0', ip_prefix: '10.0.0.0/24', redistribute: ['source=connected,route-map=m1', 'source=static'] });
    expect(fabric.seen!.rawBody).toContain('redistribute=source%3Dconnected%2Croute-map%3Dm1&redistribute=source%3Dstatic');

    const node = await send('POST', '/cluster/sdn/fabrics/node/{fabric_id}', { fabric_id: 'f1', node_id: 'pve1', protocol: 'wireguard', peers: ['type=internal,node=pve2'], allowed_ips: '10.0.0.0/24', interfaces: ['name=eth0'] });
    expect(node.res.isError, node.res.text).toBe(false);
    expect(node.seen!.pathParams.fabric_id).toBe('f1');
    expect(node.seen!.body).toEqual({ node_id: 'pve1', protocol: 'wireguard', peers: 'type=internal,node=pve2', allowed_ips: '10.0.0.0/24', interfaces: 'name=eth0' });
  });

  it('PUT /cluster/ha/rules/{rule}: the type Proxmox needs to pick the variant', async () => {
    const { res, seen } = await send('PUT', '/cluster/ha/rules/{rule}', { rule: 'r1', type: 'node-affinity', strict: true, nodes: 'pve1:2,pve2' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.pathParams.rule).toBe('r1');
    expect(seen!.body).toEqual({ type: 'node-affinity', strict: '1', nodes: 'pve1:2,pve2' });
    expect(def('POST', '/cluster/ha/rules').input).toHaveProperty('type');
  });

  it('prefix lists: a placeholder the schema does not declare, next to a parameter of a similar name', async () => {
    const template = '/cluster/sdn/prefix-lists/{id}/entries/{url_seq}';
    const put = await send('PUT', template, { id: 'p1', url_seq: 10, seq: 20, action: 'permit', delete: ['ge', 'le'] });
    expect(put.res.isError, put.res.text).toBe(false);
    expect(put.seen!.pathParams).toEqual({ id: 'p1', url_seq: '10' });
    expect(put.seen!.body).toEqual({ seq: '20', action: 'permit', delete: ['ge', 'le'] });

    const del = await send('DELETE', template, { id: 'p1', url_seq: '10' });
    expect(del.res.isError, del.res.text).toBe(false);
    expect(del.seen!.path).toBe('/cluster/sdn/prefix-lists/p1/entries/10');
    expect(del.seen!.rawBody).toBe('');
  });

  it('route maps: a dash in a placeholder', async () => {
    const template = '/cluster/sdn/route-maps/entries/{route-map-id}/entry/{order}';
    const { res, seen } = await send('PUT', template, { 'route-map-id': 'rm1', order: 5, action: 'permit', 'exit-action': 'next', match: ['key=x'], set: ['key=y'] });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.path).toBe('/cluster/sdn/route-maps/entries/rm1/entry/5');
    expect(seen!.body).toEqual({ action: 'permit', 'exit-action': 'next', match: 'key=x', set: 'key=y' });
  });

  it('a mapping name or a PCI id in the path', async () => {
    const { res, seen } = await send('GET', '/nodes/{node}/hardware/pci/{pci-id-or-mapping}/mdev', { node: 'pve1', 'pci-id-or-mapping': '0000:01:00.0' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.pathParams['pci-id-or-mapping']).toBe('0000:01:00.0');
  });

  it('DELETE: parameters travel in the query, with their dashes', async () => {
    const { res, seen } = await send('DELETE', VM, { node: 'pve1', vmid: 100, purge: true, 'destroy-unreferenced-disks': 1, skiplock: false });
    // The fake refuses to destroy a running guest, like Proxmox: what matters is what it was sent.
    expect(res.data.error_type, res.text).toBe('upstream_error');
    expect(seen!.query).toEqual({ purge: '1', 'destroy-unreferenced-disks': '1', skiplock: '0' });
    expect(seen!.rawBody).toBe('');
  });

  it('a list of guests as a repeated parameter', async () => {
    const { res, seen } = await send('POST', '/cluster/bulk-action/guest/start', { vms: [100, '101'], 'max-workers': '2' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({ vms: ['100', '101'], 'max-workers': '2' });
    expect(seen!.rawBody).toContain('vms=100&vms=101');
  });

  it('numbered parameters elsewhere in the API', async () => {
    const cluster = await send('POST', '/cluster/config', { clustername: 'c1', link: { 0: '10.0.0.1' }, link1: '10.0.1.1' });
    expect(cluster.res.isError, cluster.res.text).toBe(false);
    expect(cluster.seen!.body).toEqual({ clustername: 'c1', link0: '10.0.0.1', link1: '10.0.1.1' });

    const node = await send('PUT', '/nodes/{node}/config', { node: 'pve1', acmedomain: { 0: 'domain=a.example' }, 'startall-onboot-delay': '10' });
    expect(node.res.isError, node.res.text).toBe(false);
    expect(node.seen!.body).toEqual({ acmedomain0: 'domain=a.example', 'startall-onboot-delay': '10' });
  });
});

describe('what an agent may send', () => {
  const parse = (method: HttpMethod, template: string, args: Record<string, unknown>) => z.object(def(method, template).input).loose().safeParse(args);
  const SNAP = `${VM}/status/start`;

  it.each([1, 0, '1', '0', true, false, 'true', 'false', 'on', 'off', 'yes', 'no', 'ON', 'False', ' 1 '])('takes %j for a boolean, as Proxmox does', (value) => {
    expect(parse('POST', SNAP, { vmid: 100, skiplock: value }).success).toBe(true);
  });

  it.each(['maybe', 2, -1, '', {}, []])('refuses %j for a boolean', (value) => {
    expect(parse('POST', SNAP, { vmid: 100, skiplock: value }).success).toBe(false);
  });

  it('turns them all into what goes on the wire', async () => {
    for (const [value, wire] of [
      ['on', '1'],
      ['off', '0'],
      ['yes', '1'],
      ['no', '0'],
      [1, '1'],
      [0, '0'],
    ] as const) {
      const { res, seen } = await send('POST', SNAP, { node: 'pve1', vmid: 100, skiplock: value });
      expect(res.isError, res.text).toBe(false);
      expect(seen!.body.skiplock).toBe(wire);
    }
  });

  it('takes digits in text for a number, inside the same limits', () => {
    const vmid = (value: unknown) => parse('POST', SNAP, { vmid: value }).success;
    expect(vmid(100)).toBe(true);
    expect(vmid('100')).toBe(true);
    expect(vmid(999999999)).toBe(true);
    expect(vmid(99)).toBe(false);
    expect(vmid('99')).toBe(false);
    expect(vmid(1000000000)).toBe(false);
    expect(vmid(100.5)).toBe(false);
    expect(vmid('100.5')).toBe(false);
    expect(vmid('abc')).toBe(false);
    expect(vmid(undefined)).toBe(false);
  });

  it('reads a node from the vmid given as text', async () => {
    const { res, seen } = await send('POST', SNAP, { vmid: '100' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.pathParams).toEqual({ node: 'pve1', vmid: '100' });
  });

  it('takes a number where the schema says string: memory became a string in Proxmox 9', async () => {
    const { res, seen } = await send('POST', QEMU, { node: 'pve1', vmid: 200, memory: 2048, description: 12, cores: '4' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toMatchObject({ memory: '2048', description: '12', cores: '4' });
  });

  it('takes a number for an enum made of digits, and refuses what the enum does not hold', () => {
    const digits = catalog.endpoints.flatMap((e) =>
      Object.entries(e.params)
        .filter(([name, p]) => p.type === 'string' && p.enum?.some((v) => /^\d+$/.test(v)) && byName.get(toolName(e.method, e.path))?.input[name])
        .map(([name, p]) => ({ schema: byName.get(toolName(e.method, e.path))!.input[name] as z.ZodType, value: Number(p.enum!.find((v) => /^\d+$/.test(v))) })),
    );
    expect(digits.length).toBeGreaterThan(0);
    for (const { schema, value } of digits) {
      expect(schema.safeParse(value).success).toBe(true);
      expect(schema.safeParse('no-such-value').success).toBe(false);
    }
    const flag = def('PUT', '/cluster/ceph/flags/{flag}').input.flag as z.ZodType;
    expect(flag.safeParse('noout').success).toBe(true);
    expect(flag.safeParse('nope').success).toBe(false);
  });

  it('takes a single value for a list, and 100,101 for a list of ids', async () => {
    const one = await send('POST', '/cluster/bulk-action/guest/start', { vms: 100 });
    expect(one.seen!.body.vms).toBe('100');
    const text = await send('POST', '/cluster/bulk-action/guest/start', { vms: '100,101' });
    expect(text.seen!.body.vms).toEqual(['100', '101']);
    const items = await send('POST', '/cluster/sdn/fabrics/fabric', { id: 'f1', protocol: 'ospf', area: '0', redistribute: 'source=static' });
    expect(items.seen!.body.redistribute).toBe('source=static');
  });

  it('checks the items of a list against their enum', () => {
    const schema = def('PUT', '/cluster/sdn/prefix-lists/{id}').input.delete as z.ZodType;
    expect(schema.safeParse(['entries']).success).toBe(findEndpoint('PUT', '/cluster/sdn/prefix-lists/{id}')!.params.delete!.items!.enum!.includes('entries'));
    expect(schema.safeParse(['no-such-field']).success).toBe(false);
  });

  it('takes a number as the value of a numbered parameter and of a flat one', async () => {
    const { res, seen } = await send('PUT', `${VM}/config`, { node: 'pve1', vmid: 100, net: { 0: 12 }, ide2: 34 });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({ net0: '12', ide2: '34' });
  });

  it('takes these in text as well: wait and paging', async () => {
    const started = await send('POST', SNAP, { node: 'pve1', vmid: 100, wait: 'no', wait_seconds: '5' });
    expect(started.res.isError, started.res.text).toBe(false);
    const listed = await send('GET', '/nodes', { page_limit: '1', page_offset: '0' });
    expect(listed.res.isError, listed.res.text).toBe(false);
    expect(listed.res.data.count).toBeLessThanOrEqual(1);
  });

  it('accepts names with unusual characters in a node and in the values of a path', async () => {
    for (const node of ['pve1', 'pve-1', 'PVE', 'a.b.example', '1node']) {
      expect((def('GET', '/nodes/{node}/status').input.node as z.ZodType).safeParse(node).success, node).toBe(true);
    }
    expect((def('GET', '/nodes/{node}/status').input.node as z.ZodType).safeParse('../x').success).toBe(false);
    const { res, seen } = await send('GET', '/nodes/{node}/storage/{storage}/content/{volume}', { node: 'pve1', storage: 'local', volume: 'local:iso/my file.iso' });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.pathParams.volume).toBe('local:iso/my file.iso');
  });

  it('applies no pattern on the client: the value may be valid in a version newer than the schema', () => {
    const patterned = catalog.endpoints.flatMap((e) => Object.entries(e.params).filter(([, p]) => p.pattern && !p.enum && p.type === 'string').map(([name]) => ({ e, name })));
    expect(patterned.length).toBeGreaterThan(0);
    for (const { e, name } of patterned) {
      if (templateParams(e.path).includes(name) || name.endsWith('[n]')) continue;
      const schema = byName.get(toolName(e.method, e.path))?.input[name] as z.ZodType | undefined;
      if (!schema) continue;
      const min = e.params[name]!.minLength ?? 1;
      expect(schema.safeParse('~'.repeat(Math.max(min, 1))).success, `${e.method} ${e.path} ${name}`).toBe(true);
    }
  });

  it('refuses an argument the tool does not have, instead of dropping it and reporting success', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, nosuch: 1, cores: 2 });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.error).toContain('"nosuch"');
    expect(fake.writes()).toHaveLength(0);
  });

  it('says which argument was meant', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const res = await call(toolName('POST', LXC), { node: 'pve1', vmid: 200, ostemplate: 'x', ssh_public_keys: 'k' });
    expect(res.isError).toBe(true);
    expect(res.data.hint).toContain('"ssh-public-keys"');
    expect(fake.writes()).toHaveLength(0);
  });

  it('refuses an object for a flat numbered argument, which would not survive the form encoding', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, net0: { model: 'virtio' } });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('invalid_input');
    expect(fake.writes()).toHaveLength(0);
  });

  it('does not take the number at the end of an unknown name for an index', async () => {
    const { call } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, nosuch0: 'x' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('invalid_input');
  });

  it('keeps the server arguments out of what is sent, on endpoints that do not use them', async () => {
    const { res, seen } = await send('PUT', `${VM}/config`, { node: 'pve1', vmid: 100, cores: 2, page_limit: 5 });
    expect(res.isError, res.text).toBe(false);
    expect(seen!.body).toEqual({ cores: '2' });
  });
});

describe('the schema a client is shown', () => {
  it('has real numbers for its limits, including those the API writes as text', async () => {
    for (const endpoint of catalog.endpoints) {
      for (const [name, param] of Object.entries(endpoint.params)) {
        for (const limit of ['minimum', 'maximum', 'minLength', 'maxLength'] as const) {
          if (param[limit] !== undefined) expect(typeof param[limit], `${endpoint.method} ${endpoint.path} ${name}`).toBe('number');
        }
      }
    }
    expect(findEndpoint('POST', `${VM}/move_disk`)!.params.bwlimit!.minimum).toBe(0);
    const schema = await shownSchema('POST', `${VM}/move_disk`);
    expect(schema.properties.bwlimit).toMatchObject({ type: 'integer', minimum: 0 });
    // Not the limits of a double, on every whole number of the API.
    expect(schema.properties.bwlimit.maximum).toBeUndefined();
  });

  it('is a clean object on the hardest endpoints: types, required, descriptions, no leftovers of zod', async () => {
    const { client } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const { tools } = await client.listTools();
    const of = (method: HttpMethod, template: string) => tools.find((t) => t.name === toolName(method, template))!.inputSchema as any;

    const vm = of('POST', QEMU);
    expect(vm.type).toBe('object');
    expect(vm.required).toEqual(['vmid']);
    expect(vm.properties.vmid).toMatchObject({ type: 'integer', minimum: 100, maximum: 999999999 });
    expect(vm.properties.numa.type).toBe('boolean');
    expect(vm.properties.net.type).toBe('object');
    expect(vm.properties.net.description).toContain('bridge=');
    expect(vm.properties.net.description).toContain('net0');
    expect(vm.properties.numa_n.description).toContain('numa0');
    expect(vm.properties.scsi.description).toContain('iothread');
    expect(vm.properties.memory.type).toBe('string');
    expect(vm.properties.sshkeys.type).toBe('string');

    const fabric = of('POST', '/cluster/sdn/fabrics/fabric');
    expect(fabric.required.sort()).toEqual(['id', 'protocol']);
    expect(fabric.properties.redistribute).toMatchObject({ type: 'array', items: { type: 'string' } });
    expect(fabric.properties.redistribute.description).toContain('source*=');
    expect(fabric.properties.redistribute.description).toContain('route-map=');

    expect(of('PUT', '/cluster/ha/rules/{rule}').required.sort()).toEqual(['rule', 'type']);
    expect(of('POST', '/cluster/bulk-action/guest/start').properties.vms).toMatchObject({ type: 'array', items: { type: 'integer' } });
    expect(of('PUT', '/cluster/sdn/prefix-lists/{id}').properties.delete.items.enum.length).toBeGreaterThan(0);

    for (const t of tools.filter((tool) => byName.has(tool.name))) {
      const text = JSON.stringify(t.inputSchema);
      expect(text, t.name).not.toContain('"~standard"');
      for (const property of Object.values((t.inputSchema as any).properties ?? {}) as any[]) {
        expect(typeof property.description, `${t.name}: an argument with no description`).toBe('string');
        expect(property.type !== undefined || property.anyOf !== undefined || property.enum !== undefined, `${t.name}: ${JSON.stringify(property).slice(0, 120)}`).toBe(true);
      }
    }
  });

  it('declares no property string as truncated or missing its keys', () => {
    for (const endpoint of catalog.endpoints) {
      for (const [name, param] of Object.entries(endpoint.params)) {
        if (param.propertyString) expect(param.description ?? '', `${endpoint.method} ${endpoint.path} ${name}`).not.toMatch(/\.\.\.$/);
      }
    }
  });

  it('marks what a client should know about repeating a call', async () => {
    const { client } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const { tools } = await client.listTools();
    const hints = (method: HttpMethod, template: string) => tools.find((t) => t.name === toolName(method, template))!.annotations!;
    for (const [method, template] of [
      ['PUT', `${VM}/sendkey`],
      ['PUT', `${VM}/resize`],
      ['PUT', '/nodes/{node}/disks/wipedisk'],
      ['PUT', '/nodes/{node}/network'],
      ['PUT', '/cluster/sdn'],
      ['PUT', '/nodes/{node}/apt/repositories'],
      ['PUT', '/nodes/{node}/certificates/acme/certificate'],
      ['POST', `${VM}/snapshot`],
    ] as Array<[HttpMethod, string]>) {
      expect(hints(method, template).idempotentHint, `${method} ${template}`).toBe(false);
    }
    expect(hints('PUT', `${VM}/config`).idempotentHint).toBe(true);
    expect(hints('GET', `${VM}/config`).idempotentHint).toBe(true);
    expect(hints('DELETE', VM).idempotentHint).toBe(true);
  });

  it('marks what goes outside the cluster', async () => {
    const { client } = await connect({ fake: { permissive: true }, env: ALL_GATES });
    const { tools } = await client.listTools();
    const openWorld = (method: HttpMethod, template: string) => tools.find((t) => t.name === toolName(method, template))!.annotations!.openWorldHint;
    for (const [method, template] of [
      ['POST', '/nodes/{node}/storage/{storage}/download-url'],
      ['POST', '/nodes/{node}/storage/{storage}/oci-registry-pull'],
      ['POST', '/nodes/{node}/aplinfo'],
      ['GET', '/nodes/{node}/query-url-metadata'],
      ['GET', '/nodes/{node}/query-oci-repo-tags'],
      ['GET', '/nodes/{node}/scan/nfs'],
      ['POST', '/nodes/{node}/apt/update'],
      ['POST', '/cluster/acme/account'],
      ['POST', `${VM}/remote_migrate`],
    ] as Array<[HttpMethod, string]>) {
      expect(openWorld(method, template), `${method} ${template}`).toBe(true);
    }
    expect(openWorld('GET', `${VM}/config`)).toBe(false);
    expect(openWorld('GET', '/nodes/{node}/scan/lvm')).toBe(false);
  });

  it('says in the description when arguments change what a tool is', () => {
    expect(def('PUT', `${VM}/config`).description).toContain('Destructive with some argument values');
    expect(def('PUT', `${VM}/config`).description).toContain('PROXMOX_ALLOW_ELEVATED: hookscript');
    expect(def('POST', '/nodes/{node}/vzdump').description).toContain('script, dumpdir, tmpdir');
    expect(def('POST', `${VM}/status/start`).description).not.toContain('Destructive');
    // Elevated already: nothing to announce.
    expect(def('POST', '/storage').description).not.toContain('reach the host');
  });

  it('puts tools in every domain that needs them', () => {
    expect(domainOf('/nodes/{node}/aplinfo')).toEqual({ domain: 'storage', also: ['lxc'] });
    expect(domainOf('/nodes/{node}/dns')).toEqual({ domain: 'node', also: ['network'] });
    expect(domainOf('/nodes/{node}/hosts')).toEqual({ domain: 'node', also: ['network'] });
    expect(domainOf('/nodes/{node}/storage/{storage}/content')).toEqual({ domain: 'storage', also: ['backup'] });
    expect(domainOf('/nodes/{node}/storage/{storage}/content/{volume}')).toEqual({ domain: 'storage', also: ['backup'] });
    expect(domainOf('/nodes/{node}/storage/{storage}/status')).toEqual({ domain: 'storage' });
    expect(domainOf('/nodes/{node}/time')).toEqual({ domain: 'node' });
  });
});

describe('gates and questions that depend on the arguments', () => {
  it('refuses a hook script with writes on, before asking anyone and before sending anything', async () => {
    let asked = 0;
    const { call, fake } = await connect({
      fake: { permissive: true },
      env: WRITES,
      onElicit: () => {
        asked++;
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, hookscript: 'local:snippets/x.sh' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('elevated_disabled');
    expect(asked).toBe(0);
    expect(fake.writes()).toHaveLength(0);
  });

  it.each<[string, Record<string, unknown>]>([
    ['hostpci in a tool argument', { hostpci: { 0: '01:00.0' } }],
    ['hostpci0 as a flat argument', { hostpci0: '01:00.0' }],
    ['kvm arguments', { args: '-device x' }],
    ['a device of the host on a serial port', { serial0: '/dev/ttyS0' }],
    ['a USB device of the host', { usb0: 'host=1234:5678' }],
  ])('refuses %s, with writes on', async (_what, args) => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: WRITES });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, ...args });
    expect(res.data.error_type).toBe('elevated_disabled');
    expect(fake.writes()).toHaveLength(0);
  });

  it('does not let pve_api_write around it', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: WRITES });
    const res = await call('pve_api_write', { method: 'PUT', path: '/nodes/pve1/qemu/100/config', params: { hookscript: 'x' } });
    expect(res.data.error_type).toBe('elevated_disabled');
    expect(fake.writes()).toHaveLength(0);
  });

  it('lets ordinary configuration through with writes on', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: WRITES });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, cores: 2, serial0: 'socket', usb0: 'spice', net0: 'virtio,bridge=vmbr0' });
    expect(res.isError, res.text).toBe(false);
    expect(fake.writes().at(-1)!.body).toEqual({ cores: '2', serial0: 'socket', usb0: 'spice', net0: 'virtio,bridge=vmbr0' });
  });

  it('allows it all once elevated changes are on', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: { ...WRITES, PROXMOX_ALLOW_ELEVATED: 'true' } });
    const res = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, hookscript: 'local:snippets/x.sh' });
    expect(res.isError, res.text).toBe(false);
    expect(fake.writes().at(-1)!.body).toEqual({ hookscript: 'local:snippets/x.sh' });
  });

  it('asks a human when the arguments make it destructive, and only then', async () => {
    const messages: string[] = [];
    const { call } = await connect({
      fake: { permissive: true },
      env: WRITES,
      onElicit: (message) => {
        messages.push(message);
        return { action: 'decline' };
      },
    });
    const removes = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, delete: 'unused0' });
    expect(removes.data.error_type).toBe('user_cancelled');
    expect(messages).toHaveLength(1);

    const harmless = await call('pve_update_vm_config', { node: 'pve1', vmid: 100, delete: 'cores' });
    expect(harmless.isError, harmless.text).toBe(false);
    expect(messages).toHaveLength(1);
  });

  it('asks for what cannot be taken back, or that cuts a guest or a node off', async () => {
    const asked = new Set<string>();
    const { call } = await connect({
      fake: { permissive: true },
      env: ALL_GATES,
      onElicit: (message) => {
        asked.add(message);
        return { action: 'decline' };
      },
    });
    for (const [method, template, args] of [
      ['POST', `${VM}/agent/exec`, { node: 'pve1', vmid: 100, command: ['ls'] }],
      ['PUT', `${VM}/sendkey`, { node: 'pve1', vmid: 100, key: 'ret' }],
      ['POST', '/nodes/{node}/services/{service}/restart', { node: 'pve1', service: 'pveproxy' }],
      ['PUT', '/nodes/{node}/network', { node: 'pve1' }],
      ['POST', '/nodes/{node}/disks/zfs', { node: 'pve1', name: 'z', raidlevel: 'single', devices: '/dev/sdb' }],
      ['POST', '/cluster/config/join', { hostname: 'h', password: 'p', fingerprint: 'AA', link0: 'x' }],
    ] as Array<[HttpMethod, string, Record<string, unknown>]>) {
      const res = await call(toolName(method, template), args);
      expect(res.data.error_type, `${method} ${template}: ${res.text}`).toBe('user_cancelled');
    }
    expect(asked.size).toBe(6);
  });

  it('keeps a protected guest out of reach through its volumes and lists', async () => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: { ...ALL_GATES, PROXMOX_PROTECTED_VMIDS: '100' } });
    const results = [
      await call(toolName('DELETE', '/nodes/{node}/storage/{storage}/content/{volume}'), { node: 'pve1', storage: 'local-lvm', volume: 'local-lvm:vm-100-disk-0' }),
      await call(toolName('POST', '/nodes/{node}/stopall'), { node: 'pve1', vms: '100,101' }),
      await call(toolName('POST', '/cluster/bulk-action/guest/shutdown'), { vms: [100] }),
      await call(toolName('DELETE', '/cluster/replication/{id}'), { id: '100-0' }),
    ];
    for (const res of results) expect(res.data.error_type, res.text).toBe('protected_guest');
    expect(fake.writes()).toHaveLength(0);
  });
});

describe('what a write leaves behind', () => {
  // Some of these endpoints refuse API tokens.
  const PASSWORD_LOGIN = { PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: FAKE_USER, PROXMOX_PASSWORD: FAKE_PASSWORD };
  const secrets: Array<[string, HttpMethod, string, Record<string, unknown>, string]> = [
    ['an ACME plugin credential', 'POST', '/cluster/acme/plugins', { id: 'cf', type: 'dns', api: 'cf', data: 'Q0ZfVG9rZW49c2VjcmV0dmFsdWU=' }, 'Q0ZfVG9rZW49c2VjcmV0dmFsdWU='],
    ['a file written in a guest', 'POST', `${VM}/agent/file-write`, { node: 'pve1', vmid: 100, file: '/etc/x', content: 'secretvalue' }, 'secretvalue'],
    ['the input of a command', 'POST', `${VM}/agent/exec`, { node: 'pve1', vmid: 100, command: ['cat'], 'input-data': 'secretvalue' }, 'secretvalue'],
    ['the headers of a webhook', 'POST', '/cluster/notifications/endpoints/webhook', { name: 'w', url: 'https://h.example/secretvalue', method: 'post', header: ['name=a,value=secretvalue'] }, 'secretvalue'],
    ['the headers of a metric server', 'POST', '/cluster/metrics/server/{id}', { id: 'm', type: 'opentelemetry', server: 'h', port: 1, 'otel-headers': 'secretvalue' }, 'secretvalue'],
    ['a one-time code', 'POST', '/access/tfa/{userid}', { userid: 'root@pam', type: 'totp', totp: 'otpauth://x', value: 'secretvalue' }, 'secretvalue'],
  ];

  it.each(secrets)('does not show %s in a dry run', async (_what, method, template, args, secret) => {
    const { call, fake } = await connect({ fake: { permissive: true }, env: { ...ALL_GATES, ...PASSWORD_LOGIN } });
    const res = await call(toolName(method, template), { ...args, dry_run: true });
    expect(res.isError, res.text).toBe(false);
    expect(res.data.would_send).toHaveLength(1);
    expect(res.text).not.toContain(secret);
    expect(fake.writes()).toHaveLength(0);
  });

  it('does not write them to the audit log either, and they do reach Proxmox', async () => {
    const file = join(tmpdir(), `pvemcp-generation-${process.pid}-${Date.now()}.log`);
    try {
      const { call, fake, runtime } = await connect({ fake: { permissive: true }, env: { ...ALL_GATES, ...PASSWORD_LOGIN, PROXMOX_AUDIT_LOG: file, PROXMOX_TASK_WAIT_SECONDS: '0' } });
      for (const [, method, template, args] of secrets) {
        const res = await call(toolName(method, template), args);
        expect(res.isError, `${method} ${template}: ${res.text}`).toBe(false);
      }
      // By path, the same masks apply.
      const direct = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/agent/file-write', params: { file: '/etc/x', content: 'secretvalue' } });
      expect(direct.isError, direct.text).toBe(false);
      await runtime.shutdown();
      const log = readFileSync(file, 'utf8');
      expect(log.trim().split('\n').length).toBeGreaterThanOrEqual(secrets.length);
      expect(log).not.toContain('secretvalue');
      expect(log).not.toContain('Q0ZfVG9rZW49');
      expect(fake.find('POST', `${VM}/agent/file-write`).at(-1)!.body.content).toBe('secretvalue');
    } finally {
      rmSync(file, { force: true });
    }
  });
});
