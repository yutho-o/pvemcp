import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { ProxmoxClient } from '../src/proxmox/client.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { NodeResolver } from '../src/proxmox/nodes.js';
import { DRY_RUN_UPID, isUpid, parseUpid, taskLogTail, waitForTask } from '../src/proxmox/tasks.js';
import { FAKE_TOKEN, FakePve, type FakeOptions } from './fake-pve.js';

const cleanups: Array<() => unknown> = [];
afterEach(async () => {
  for (const c of cleanups.splice(0)) await c();
});

async function setup(options: FakeOptions = {}) {
  const fake = new FakePve(options);
  await fake.start();
  const config = loadConfig({ PROXMOX_URL: fake.url, PROXMOX_TOKEN: FAKE_TOKEN });
  const client = new ProxmoxClient(config.instances.get('default')!);
  cleanups.push(() => client.close(), () => fake.stop());
  return { fake, client };
}

const FAST = { pollMs: 1, maxPollMs: 2 };

describe('UPID', () => {
  const upid = 'UPID:pve1:0000A1B2:0012C3D4:5F9A1B2C:qmstart:100:root@pam:';

  it('parses', () => {
    expect(parseUpid(upid)).toEqual({ upid, node: 'pve1', pid: 0xa1b2, pstart: 0x12c3d4, starttime: 0x5f9a1b2c, type: 'qmstart', id: '100', user: 'root@pam' });
    expect(parseUpid('UPID:n-1:00000001:00000002:00000003:vzdump::mcp@pve!tok:').id).toBe('');
    expect(isUpid(upid)).toBe(true);
    expect(isUpid(DRY_RUN_UPID)).toBe(true);
  });

  it.each(['', 'ok', 'UPID:', 'UPID:pve1:1:2:3:x:y:z:', `${upid}extra`, 'UPID:pve/1:0000A1B2:0012C3D4:5F9A1B2C:qmstart:100:root@pam:', 5, null])('refuses %s', (value) => {
    expect(isUpid(value)).toBe(false);
  });

  it('throws invalid_input on a bad one', () => {
    expect(() => parseUpid('nope')).toThrow(ProxmoxError);
  });
});

describe('waitForTask', () => {
  it('polls the node of the UPID until it stops, and returns the end of the log', async () => {
    const { fake, client } = await setup({ nodes: ['pve1', 'pve2'] });
    const upid = fake.startTask('pve2', 'qmstart', '100', { polls: 3, log: ['one', 'two', 'TASK OK'] });
    const result = await waitForTask(client, upid, FAST);
    expect(result).toEqual({ upid, node: 'pve2', status: 'stopped', exitstatus: 'OK', log_tail: ['one', 'two', 'TASK OK'] });
    const reads = fake.find('GET', '/nodes/{node}/tasks/{upid}/status');
    expect(reads).toHaveLength(4);
    expect(reads[0]!.pathParams.node).toBe('pve2');
    expect(reads[0]!.pathParams.upid).toBe(upid);
  });

  it('counts WARNINGS as a success with a warning', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'vzdump', '', { exitstatus: 'WARNINGS: 2' });
    const result = await waitForTask(client, upid, FAST);
    expect(result.exitstatus).toBe('WARNINGS: 2');
    expect(result.warning).toContain('warnings: 2');
  });

  it('turns any other exit into task_failed, with the log tail', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'qmstart', '100', { exitstatus: 'command failed', log: ['boom', 'TASK ERROR: command failed'] });
    const err = await waitForTask(client, upid, FAST).catch((e: unknown) => e as ProxmoxError);
    expect(err).toBeInstanceOf(ProxmoxError);
    expect((err as ProxmoxError).type).toBe('task_failed');
    expect((err as ProxmoxError).details).toMatchObject({ exitstatus: 'command failed', log_tail: ['boom', 'TASK ERROR: command failed'] });
  });

  it('gives up with task_timeout when it outlasts the delay, without cancelling it', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'qmstart', '100', { polls: 100_000 });
    const err = await waitForTask(client, upid, { ...FAST, timeoutMs: 30 }).catch((e: unknown) => e as ProxmoxError);
    expect((err as ProxmoxError).type).toBe('task_timeout');
    expect(fake.tasks.get(upid)!.stopped).toBe(false);
    expect(fake.writes()).toHaveLength(0);
  });

  it('backs off between polls', async () => {
    const delays: number[] = [];
    let last = Date.now();
    let polls = 0;
    const api = {
      get: async (path: string) => {
        if (path.endsWith('/log')) return [];
        const now = Date.now();
        delays.push(now - last);
        last = now;
        return polls++ < 4 ? { status: 'running' } : { status: 'stopped', exitstatus: 'OK' };
      },
    };
    await waitForTask(api, 'UPID:pve1:00000001:00000002:00000003:x:y:z@pam:', { pollMs: 10, maxPollMs: 40 });
    expect(delays.at(-1)!).toBeGreaterThan(delays[1]! - 5);
  });

  it('stops on abort', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'qmstart', '100', { polls: 100_000 });
    const controller = new AbortController();
    const waiting = waitForTask(client, upid, { pollMs: 1000, timeoutMs: 60_000, signal: controller.signal });
    setTimeout(() => controller.abort(new Error('stop waiting')), 20);
    await expect(waiting).rejects.toThrow('stop waiting');
  });

  it('never touches the API for the dry-run task', async () => {
    const { fake, client } = await setup();
    const result = await waitForTask(client, DRY_RUN_UPID);
    expect(result.exitstatus).toBe('OK');
    expect(fake.requests).toHaveLength(0);
  });

  it('reports an API failure while polling as it is', async () => {
    const { fake, client } = await setup();
    const err = await waitForTask(client, fake.startTask('pve1', 'x', 'y').replace('pve1', 'gone'), FAST).catch((e: unknown) => e as ProxmoxError);
    expect((err as ProxmoxError).type).toBe('upstream_error');
  });
});

describe('taskLogTail', () => {
  it('keeps the last lines, and survives an unreadable log', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'x', 'y', { log: Array.from({ length: 30 }, (_, i) => `line ${i}`) });
    expect(await taskLogTail(client, upid, 2)).toEqual(['line 28', 'line 29']);
    expect(await taskLogTail(client, upid.replace('pve1', 'gone'))).toEqual([]);
  });

  it('pages through a log longer than one read', async () => {
    const { fake, client } = await setup();
    const upid = fake.startTask('pve1', 'x', 'y', { log: Array.from({ length: 12_000 }, (_, i) => `line ${i}`) });
    expect(await taskLogTail(client, upid, 1)).toEqual(['line 11999']);
  });
});

describe('NodeResolver', () => {
  async function resolver(options: FakeOptions = {}, resolverOptions: Partial<ConstructorParameters<typeof NodeResolver>[1]> = {}) {
    const { fake, client } = await setup(options);
    const nodes = new NodeResolver(client, { apiHost: 'api.example', ...resolverOptions });
    return { fake, nodes };
  }

  it('finds a guest, and caches the answer', async () => {
    const { fake, nodes } = await resolver({ nodes: ['pve1', 'pve2'], guests: [{ vmid: 100, node: 'pve2', type: 'lxc', name: 'db', status: 'stopped' }] });
    expect(await nodes.resolveGuest(100)).toEqual({ vmid: 100, node: 'pve2', type: 'lxc', name: 'db', status: 'stopped' });
    await nodes.resolveGuest(100);
    expect(fake.find('GET', '/cluster/resources')).toHaveLength(1);
    expect(fake.find('GET', '/cluster/resources')[0]!.query.type).toBe('vm');
  });

  it('reads again after invalidate, and after the cache expires', async () => {
    const { fake, nodes } = await resolver();
    await nodes.resolveGuest(100);
    fake.guests.get(100)!.node = 'pve1';
    nodes.invalidate();
    await nodes.resolveGuest(100);
    expect(fake.find('GET', '/cluster/resources')).toHaveLength(2);

    const quick = await resolver({}, { cacheMs: 0 });
    await quick.nodes.resolveGuest(100);
    await quick.nodes.resolveGuest(100);
    expect(quick.fake.find('GET', '/cluster/resources')).toHaveLength(2);
  });

  it('looks again before saying that a guest does not exist', async () => {
    const { fake, nodes } = await resolver();
    await nodes.resolveGuest(100);
    fake.addGuest({ vmid: 300 });
    expect((await nodes.resolveGuest(300)).vmid).toBe(300);
    const err = await nodes.resolveGuest(999).catch((e: unknown) => e as ProxmoxError);
    expect((err as ProxmoxError).type).toBe('not_found');
  });

  it('uses the default node, else the only one, else lists them', async () => {
    expect(await (await resolver({ nodes: ['a', 'b'] }, { defaultNode: 'b' })).nodes.defaultNode()).toBe('b');
    expect(await (await resolver({ nodes: ['only'], guests: [] })).nodes.defaultNode()).toBe('only');
    const err = await (await resolver({ nodes: ['a', 'b'], guests: [] })).nodes.defaultNode().catch((e: unknown) => e as ProxmoxError);
    expect((err as ProxmoxError).type).toBe('invalid_input');
    expect((err as ProxmoxError).message).toContain('a, b');
  });

  it('finds the SSH host: pinned, else from the cluster, else the API host on one node', async () => {
    const pinned = await resolver({ nodes: ['a', 'b'] }, { sshNodes: { a: '10.0.0.1' } });
    expect(await pinned.nodes.sshHost('a')).toBe('10.0.0.1');
    expect(await pinned.nodes.sshHost('b')).toBe('192.0.2.2');
    await expect(pinned.nodes.sshHost('c')).rejects.toThrow(/No address known/);

    const single = await resolver();
    single.fake.on('GET', '/cluster/status', () => [{ type: 'cluster', name: 'x' }, { type: 'node', name: 'pve1' }]);
    expect(await single.nodes.sshHost('pve1')).toBe('api.example');
  });
});
