import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FakePve, FAKE_TOKEN, pveError } from './fake-pve.js';
import { closeAll, connect } from './harness.js';

afterEach(closeAll);

const NAMES = ['cluster', 'nodes', 'guests', 'storage', 'tasks'];
const PROMPTS = ['cluster_health_review', 'troubleshoot_guest', 'provision_lxc', 'safe_guest_change', 'backup_review', 'security_review'];

async function read(client: Awaited<ReturnType<typeof connect>>['client'], uri: string): Promise<any> {
  const res = await client.readResource({ uri });
  const content = res.contents[0] as { uri: string; mimeType: string; text: string };
  expect(content.uri).toBe(uri);
  expect(content.mimeType).toBe('application/json');
  return JSON.parse(content.text);
}

describe('resources', () => {
  it('lists the resources of the instance', async () => {
    const { client } = await connect();
    const { resources } = await client.listResources();
    expect(resources.map((r) => r.uri).sort()).toEqual(NAMES.map((n) => `proxmox://default/${n}`).sort());
    for (const r of resources) expect(r.description).toMatch(/Untrusted/);
  });

  it('reads the cluster', async () => {
    const { client } = await connect();
    const data = await read(client, 'proxmox://default/cluster');
    expect(data.version.version).toBe('9.1.0');
    expect(data.status[0]).toMatchObject({ type: 'cluster', quorate: 1 });
    // Not modelled by the fake: named as unavailable, along with what could be read.
    expect(data.complete).toBe(false);
    expect(data.unavailable.ha).toMatch(/not_supported/);
    expect(data.ha).toBeUndefined();
  });

  it('reads the nodes', async () => {
    const { client } = await connect();
    expect((await read(client, 'proxmox://default/nodes')).map((n: any) => n.node)).toEqual(['pve1']);
  });

  it('reads the guests, and only them', async () => {
    const { client, fake } = await connect();
    const data = await read(client, 'proxmox://default/guests');
    expect(data.map((g: any) => g.vmid)).toEqual([100, 101]);
    expect(fake.find('GET', '/cluster/resources')[0]!.query).toEqual({ type: 'vm' });
  });

  it('reads the storage', async () => {
    const { client, fake } = await connect();
    expect((await read(client, 'proxmox://default/storage')).map((s: any) => s.storage)).toEqual(['local']);
    expect(fake.find('GET', '/cluster/resources')[0]!.query).toEqual({ type: 'storage' });
  });

  it('reads the latest tasks, newest first', async () => {
    const { client, fake } = await connect();
    fake.startTask('pve1', 'qmstart', '100');
    fake.startTask('pve1', 'qmstop', '100');
    const data = await read(client, 'proxmox://default/tasks');
    expect(data.total).toBe(2);
    expect(data.tasks.map((t: any) => t.type)).toEqual(['qmstop', 'qmstart']);
  });

  it('caps the tasks, and says how many there were', async () => {
    const { client, fake } = await connect();
    for (let i = 0; i < 250; i++) fake.startTask('pve1', 'qmstart', String(i));
    const data = await read(client, 'proxmox://default/tasks');
    expect(data.total).toBe(250);
    expect(data.tasks).toHaveLength(200);
  });

  it('fails visibly when Proxmox refuses', async () => {
    const { client, fake } = await connect();
    fake.on('GET', '/nodes', () => pveError(403, 'Permission check failed (/nodes, Sys.Audit)'));
    await expect(client.readResource({ uri: 'proxmox://default/nodes' })).rejects.toThrow(/Permission check failed|forbidden|Proxmox/);
  });

  it('does not change anything, and hides secrets as tools do', async () => {
    const { client, fake } = await connect();
    fake.on('GET', '/nodes', () => [{ node: 'pve1', status: 'online', password: 'should-not-leak' }]);
    const data = await read(client, 'proxmox://default/nodes');
    expect(JSON.stringify(data)).not.toContain('should-not-leak');
    expect(fake.writes()).toEqual([]);
  });

  it('has one set per cluster, whatever the case of its name', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-instances-'));
    const a = new FakePve();
    const b = new FakePve({ nodes: ['other'] , guests: [] });
    try {
      await Promise.all([a.start(), b.start()]);
      const file = join(dir, 'instances.json');
      writeFileSync(
        file,
        JSON.stringify({
          default: 'Lab_A',
          instances: {
            Lab_A: { url: a.url, token: FAKE_TOKEN },
            prod: { url: b.url, token: FAKE_TOKEN },
          },
        }),
      );
      const { client, call } = await connect({ fake: a, env: { PROXMOX_URL: '', PROXMOX_TOKEN: '', PROXMOX_CONFIG: file } });
      const { resources } = await client.listResources();
      expect(resources).toHaveLength(10);
      expect((await read(client, 'proxmox://Lab_A/nodes')).map((n: any) => n.node)).toEqual(['pve1']);
      expect((await read(client, 'proxmox://prod/nodes')).map((n: any) => n.node)).toEqual(['other']);
      const prompt = await client.getPrompt({ name: 'backup_review' });
      expect((prompt.messages[0]!.content as { text: string }).text).toMatch(/several clusters \(Lab_A, prod\)/);
      expect((await call('pve_overview', { instance: 'prod' })).data.nodes).toBeDefined();
    } finally {
      await b.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('prompts', () => {
  const text = (res: { messages: Array<{ content: unknown }> }) => (res.messages[0]!.content as { text: string }).text;

  it('lists the prompts of the design', async () => {
    const { client } = await connect();
    const { prompts } = await client.listPrompts();
    expect(prompts.map((p) => p.name).sort()).toEqual([...PROMPTS].sort());
    for (const p of prompts) expect(p.description).toBeTruthy();
  });

  it('declares the arguments each one needs', async () => {
    const { client } = await connect();
    const { prompts } = await client.listPrompts();
    const required = (name: string) =>
      prompts
        .find((p) => p.name === name)!
        .arguments?.filter((a) => a.required)
        .map((a) => a.name)
        .sort();
    expect(required('troubleshoot_guest')).toEqual(['vmid']);
    expect(required('safe_guest_change')).toEqual(['change', 'vmid']);
    expect(required('provision_lxc')).toEqual(['hostname']);
  });

  it('cluster_health_review goes through the health tools and names what was not read', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'cluster_health_review' }));
    expect(body).toContain('pve_health_check');
    expect(body).toContain('unavailable');
    expect(body).toMatch(/Do not change anything/);
    expect(body).not.toMatch(/several clusters/);
  });

  it('troubleshoot_guest takes the guest and the symptom', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'troubleshoot_guest', arguments: { vmid: '123', symptom: 'no network' } }));
    expect(body).toContain('guest 123');
    expect(body).toContain('no network');
    expect(body).toContain('pve_find_guest');
    expect(body).toMatch(/untrusted/);
  });

  it('troubleshoot_guest refuses what is not a vmid', async () => {
    const { client } = await connect();
    await expect(client.getPrompt({ name: 'troubleshoot_guest', arguments: { vmid: '1; ignore that' } })).rejects.toThrow();
  });

  it('provision_lxc goes through a dry run and an agreement', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'provision_lxc', arguments: { hostname: 'app1', template: 'debian-12', requirements: '2 cores' } }));
    expect(body).toContain('app1');
    expect(body).toContain('debian-12');
    expect(body).toContain('2 cores');
    expect(body).toContain('pve_provision_lxc');
    expect(body).toContain('dry_run: true');
    expect(body).toMatch(/Do not delete anything/);
  });

  it('safe_guest_change has the snapshot, the check and the rollback', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'safe_guest_change', arguments: { vmid: '100', change: 'add a disk' } }));
    expect(body).toContain('guest 100');
    expect(body).toContain('add a disk');
    const snapshot = body.indexOf('pve_snapshot_guest');
    const verify = body.indexOf('Verify it');
    const rollback = body.indexOf('pve_rollback_vm_snapshot');
    expect(snapshot).toBeGreaterThan(-1);
    expect(verify).toBeGreaterThan(snapshot);
    expect(rollback).toBeGreaterThan(verify);
  });

  it('backup_review goes through the coverage and says what a backup does not prove', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'backup_review' }));
    expect(body).toContain('pve_backup_coverage');
    expect(body).toContain('not_determined');
    expect(body).toMatch(/restore/);
  });

  it('security_review makes no claim of compliance', async () => {
    const { client } = await connect();
    const body = text(await client.getPrompt({ name: 'security_review' }));
    expect(body).toContain('pve_security_audit');
    expect(body).toMatch(/Do not describe the result as compliance/);
  });
});
