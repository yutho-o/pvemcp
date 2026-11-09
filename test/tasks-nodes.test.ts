// Tasks and node resolution, through the tools of the Rust binary. The cases that need a clock or
// an API shaped by hand (back-off, timeouts in milliseconds, cache expiry, UPID parsing) are Rust
// unit tests in src/proxmox/tasks.rs and src/proxmox/nodes.rs.
import { afterEach, describe, expect, it } from 'vitest';
import { FakePve, type FakeOptions } from './fake-pve.js';
import { closeAll, connect, WRITES } from './harness.js';

afterEach(closeAll);

const DRY_RUN_UPID = 'UPID:dry-run:00000000:00000000:00000000:dryrun:0:dry-run@pam:';

async function started(options: FakeOptions = {}) {
  const fake = new FakePve(options);
  await fake.start();
  return fake;
}

describe('waiting for a task', () => {
  it('polls the node of the UPID until it stops, and returns the end of the log', async () => {
    const fake = await started({ nodes: ['pve1', 'pve2'] });
    const upid = fake.startTask('pve2', 'qmstart', '100', { polls: 2, log: ['one', 'two', 'TASK OK'] });
    const { call } = await connect({ fake });
    const res = await call('pve_wait_task', { upid });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ upid, node: 'pve2', status: 'stopped', exitstatus: 'OK', log_tail: ['one', 'two', 'TASK OK'] });
    const reads = fake.find('GET', '/nodes/{node}/tasks/{upid}/status');
    expect(reads).toHaveLength(3);
    expect(reads[0]!.pathParams.node).toBe('pve2');
    expect(reads[0]!.pathParams.upid).toBe(upid);
  });

  it('counts WARNINGS as a success with a warning', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'vzdump', '', { exitstatus: 'WARNINGS: 2' });
    const res = await (await connect({ fake })).call('pve_wait_task', { upid });
    expect(res.isError).toBe(false);
    expect(res.data.exitstatus).toBe('WARNINGS: 2');
    expect(res.data.warning).toContain('warnings: 2');
  });

  it('turns any other exit into task_failed, with the log tail', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'qmstart', '100', { exitstatus: 'command failed', log: ['boom', 'TASK ERROR: command failed'] });
    const res = await (await connect({ fake })).call('pve_wait_task', { upid });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('task_failed');
    expect(res.data.details).toMatchObject({ exitstatus: 'command failed', log_tail: ['boom', 'TASK ERROR: command failed'] });
  });

  it('gives up when it outlasts the delay, without cancelling the task', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'qmstart', '100', { polls: 100_000 });
    const res = await (await connect({ fake })).call('pve_wait_task', { upid, wait_seconds: 1 });
    expect(JSON.stringify(res.data)).toMatch(/still_running|task_timeout/);
    expect(fake.tasks.get(upid)!.stopped).toBe(false);
    expect(fake.writes()).toHaveLength(0);
  });

  it('never touches the API for the dry-run task', async () => {
    const fake = await started();
    const res = await (await connect({ fake })).call('pve_wait_task', { upid: DRY_RUN_UPID });
    expect(res.data.exitstatus).toBe('OK');
    expect(fake.requests).toHaveLength(0);
  });

  it('reports an API failure while polling as it is', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'x', 'y').replace('pve1', 'gone');
    const res = await (await connect({ fake })).call('pve_wait_task', { upid });
    expect(res.data.error_type).toBe('upstream_error');
  });

  it('refuses something that is not a UPID', async () => {
    const res = await (await connect()).call('pve_wait_task', { upid: 'nope' });
    expect(res.data.error_type).toBe('invalid_input');
  });

  it('waits for the task a write starts, through the scope of the call', async () => {
    const fake = await started({ nodes: ['pve1', 'pve2'], guests: [{ vmid: 100, node: 'pve2', type: 'qemu', status: 'stopped' }] });
    const res = await (await connect({ fake, env: WRITES })).call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ node: 'pve2', status: 'stopped', exitstatus: 'OK' });
  });
});

describe('the task log tail', () => {
  it('keeps the last lines, and survives an unreadable log', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'x', 'y', { log: Array.from({ length: 30 }, (_, i) => `line ${i}`) });
    const { call } = await connect({ fake });
    expect((await call('pve_get_task_log_tail', { upid, lines: 2 })).data.log_tail).toEqual(['line 28', 'line 29']);
    const unreadable = await call('pve_get_task_log_tail', { upid: upid.replace('pve1', 'gone'), lines: 2 });
    expect(unreadable.isError).toBe(true);
    expect(unreadable.text).not.toContain('line 2');
  });

  it('pages through a log longer than one read', async () => {
    const fake = await started();
    const upid = fake.startTask('pve1', 'x', 'y', { log: Array.from({ length: 12_000 }, (_, i) => `line ${i}`) });
    const res = await (await connect({ fake })).call('pve_get_task_log_tail', { upid, lines: 1 });
    expect(JSON.stringify(res.data)).toContain('"line 11999"');
    expect(JSON.stringify(res.data)).not.toContain('"line 11998"');
  });
});

describe('finding guests and nodes', () => {
  it('finds the node of a guest from its vmid, and caches the answer', async () => {
    const fake = await started({ nodes: ['pve1', 'pve2'], guests: [{ vmid: 100, node: 'pve2', type: 'lxc', name: 'db', status: 'stopped' }] });
    const { call } = await connect({ fake });
    expect((await call('pve_get_lxc_status', { vmid: 100 })).isError).toBe(false);
    expect((await call('pve_get_lxc_config', { vmid: 100 })).isError).toBe(false);
    const reads = fake.find('GET', '/cluster/resources');
    expect(reads).toHaveLength(1);
    expect(reads[0]!.query.type).toBe('vm');
    expect(fake.find('GET', '/nodes/{node}/lxc/{vmid}/status/current')[0]!.pathParams.node).toBe('pve2');
  });

  it('reads again after a write, since the guest may have moved', async () => {
    const fake = await started({ guests: [{ vmid: 100, type: 'qemu', status: 'stopped' }] });
    const { call } = await connect({ fake, env: WRITES });
    await call('pve_get_vm_status', { vmid: 100 });
    await call('pve_start_vm', { vmid: 100, wait: false });
    await call('pve_get_vm_status', { vmid: 100 });
    expect(fake.find('GET', '/cluster/resources')).toHaveLength(2);
  });

  it('looks again before saying that a guest does not exist', async () => {
    const fake = await started();
    const { call } = await connect({ fake });
    await call('pve_get_vm_status', { vmid: 100 });
    fake.addGuest({ vmid: 300 });
    expect((await call('pve_get_vm_status', { vmid: 300 })).isError).toBe(false);
    expect((await call('pve_get_vm_status', { vmid: 999 })).data.error_type).toBe('not_found');
  });

  it('says which tool it is for when the vmid is of the other kind', async () => {
    const fake = await started({ guests: [{ vmid: 101, type: 'lxc' }] });
    const res = await (await connect({ fake })).call('pve_get_vm_status', { vmid: 101 });
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.error).toContain('container');
  });

  it('uses the default node, else the only one, else lists them', async () => {
    const two = await started({ nodes: ['a', 'b'], guests: [] });
    expect((await (await connect({ fake: two, env: { PROXMOX_DEFAULT_NODE: 'b' } })).call('pve_get_node_status')).isError).toBe(false);
    expect(two.find('GET', '/nodes/{node}/status').at(-1)!.pathParams.node).toBe('b');

    const one = await started({ nodes: ['only'], guests: [] });
    expect((await (await connect({ fake: one })).call('pve_get_node_status')).isError).toBe(false);
    expect(one.find('GET', '/nodes/{node}/status')[0]!.pathParams.node).toBe('only');

    const several = await started({ nodes: ['a', 'b'], guests: [] });
    const res = await (await connect({ fake: several })).call('pve_get_node_status');
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.error).toContain('a, b');
  });
});
