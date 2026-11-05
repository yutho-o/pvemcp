import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { renderResult } from '../src/server.js';
import { FAKE_TOKEN, FakePve, pveError } from './fake-pve.js';
import { ALL_GATES, closeAll, connect, WRITES } from './harness.js';

const dir = mkdtempSync(join(tmpdir(), 'pvemcp-server-'));
let fileCounter = 0;
const tempFile = (name: string) => join(dir, `${++fileCounter}-${name}`);

afterEach(closeAll);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function readAudit(path: string, count: number): Promise<Array<Record<string, any>>> {
  return vi.waitFor(() => {
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(count);
    return lines.map((l) => JSON.parse(l) as Record<string, any>);
  });
}

/** Two clusters on one fake, one of them open for writes. */
async function twoInstances(extra: Record<string, unknown> = {}) {
  const fake = new FakePve();
  await fake.start();
  const file = tempFile('instances.json');
  writeFileSync(file, JSON.stringify({ default: 'prod', instances: { prod: { url: fake.url, token: FAKE_TOKEN, ...extra }, lab: { url: fake.url, token: FAKE_TOKEN, allow_writes: true } } }));
  return { fake, env: { PROXMOX_CONFIG: file } };
}

describe('gates', () => {
  it('hides what an instance cannot pass, so that the SDK reports an unknown tool', async () => {
    const { call, fake } = await connect();
    const res = await call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/not found/i);
    expect(fake.writes()).toHaveLength(0);
  });

  it('refuses per instance before any request, when another instance makes the tool visible', async () => {
    const { fake, env } = await twoInstances();
    const { call } = await connect({ fake, env });
    const before = fake.requests.length;
    const res = await call('pve_start_vm', { vmid: 100, node: 'pve1', instance: 'prod' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('write_disabled');
    expect(res.data.hint).toContain('PROXMOX_ALLOW_WRITES');
    expect(fake.requests).toHaveLength(before);

    const ok = await call('pve_start_vm', { vmid: 100, node: 'pve1', instance: 'lab' });
    expect(ok.isError).toBe(false);
    expect(ok.data.exitstatus).toBe('OK');
  });

  it('adds the instance parameter only when there are several, and says which is the default', async () => {
    const { fake, env } = await twoInstances();
    const { client } = await connect({ fake, env });
    const { tools } = await client.listTools();
    const start = tools.find((t) => t.name === 'pve_start_vm')!;
    expect((start.inputSchema.properties as Record<string, any>).instance.description).toContain('prod');

    const single = await connect();
    const list = (await single.client.listTools()).tools.find((t) => t.name === 'pve_list_vms')!;
    expect(list.inputSchema.properties).not.toHaveProperty('instance');
    expect(list.inputSchema.properties).not.toHaveProperty('dry_run');
  });

  it('holds on the generic tools too: elevated, sensitive, guest exec, blocked', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const elevated = await call('pve_api_write', { method: 'POST', path: '/access/users', params: { userid: 'a@pve' } });
    expect(elevated.data.error_type).toBe('elevated_disabled');
    const exec = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/agent/exec', params: { command: ['id'] } });
    expect(exec.data.error_type).toBe('guest_exec_disabled');
    const blocked = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/execute', params: { commands: '[]' } });
    expect(blocked.data.error_type).toBe('blocked_endpoint');
    const sensitive = await call('pve_api_read', { path: '/nodes/pve1/report' });
    expect(sensitive.data.error_type).toBe('sensitive_disabled');
    const unknown = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/made-up' });
    expect(unknown.data.error_type).toBe('elevated_disabled');
    const encoded = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/agent%2Fexec' });
    expect(encoded.data.error_type).toBe('invalid_path');
    expect(fake.writes()).toHaveLength(0);
  });

  it('keeps pve_api_read to reads, even with every gate open', async () => {
    const { call } = await connect({ env: ALL_GATES });
    const exec = await call('pve_api_read', { path: '/nodes/pve1/qemu/100/agent/exec-status', params: { pid: 1 } });
    expect(exec.data.error_type).toBe('not_read_only');
    const blocked = await call('pve_api_read', { path: '/nodes/pve1/vncwebsocket' });
    expect(blocked.data.error_type).toBe('blocked_endpoint');
  });

  it('opens a blocked endpoint only when the operator lists it, then as elevated', async () => {
    const { fake } = await connect({ fake: { permissive: true } });
    fake.on('POST', '/nodes/{node}/execute', () => []);
    const open = await connect({ fake, env: { ...ALL_GATES, PROXMOX_UNBLOCK: 'POST /nodes/{node}/execute' } });
    const res = await open.call('pve_api_write', { method: 'POST', path: '/nodes/pve1/execute', params: { commands: '[]' } });
    expect(res.isError).toBe(false);
    expect(fake.find('POST', '/nodes/{node}/execute')).toHaveLength(1);
  });

  it('refuses a method that takes no token before sending anything', async () => {
    const { call, fake } = await connect({ env: ALL_GATES });
    const res = await call('pve_change_user_password', { userid: 'a@pve', password: 'longenough', 'confirmation-password': 'longenough' });
    expect(res.data.error_type).toBe('forbidden');
    expect(fake.writes()).toHaveLength(0);
  });
});

describe('protected guests', () => {
  const env = { ...ALL_GATES, PROXMOX_PROTECTED_VMIDS: '100,101' };

  it('refuses any change to them, whichever way it names the guest, and allows reads', async () => {
    const { call, fake } = await connect({ env });
    for (const [tool, args] of [
      ['pve_stop_vm', { vmid: 100 }],
      ['pve_update_lxc_config', { vmid: 101, node: 'pve1', description: 'x' }],
      ['pve_create_vm', { vmid: 100, force: true }],
      ['pve_clone_vm', { vmid: 200, node: 'pve1', newid: 100 }],
      ['pve_delete_ha_resource', { sid: 'vm:100' }],
      ['pve_update_ha_resource', { sid: 'ct:101' }],
      ['pve_create_ha_resource', { sid: 'vm:101' }],
      ['pve_run_backup', { vmid: '200,101' }],
      ['pve_api_write', { method: 'POST', path: '/nodes/pve1/lxc/101/status/stop' }],
    ] as const) {
      const res = await call(tool, args);
      expect(res.data.error_type, tool).toBe('protected_guest');
    }
    expect(fake.writes()).toHaveLength(0);

    const read = await call('pve_get_vm_config', { vmid: 100 });
    expect(read.isError).toBe(false);
    const other = await call('pve_start_vm', { vmid: 102, node: 'pve1' });
    expect(other.data.error_type).not.toBe('protected_guest');
  });
});

describe('elicitation', () => {
  it('asks before a destructive tool, and goes ahead on a yes', async () => {
    const asked: string[] = [];
    const { call, fake } = await connect({
      env: WRITES,
      onElicit: (message) => {
        asked.push(message);
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const res = await call('pve_stop_vm', { vmid: 100 });
    expect(res.isError).toBe(false);
    expect(asked).toHaveLength(1);
    expect(asked[0]).toContain('pve_stop_vm');
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/stop')).toHaveLength(1);
  });

  it.each([
    ['decline', { action: 'decline' as const }],
    ['cancel', { action: 'cancel' as const }],
    ['accept without the box ticked', { action: 'accept' as const, content: { confirm: false } }],
  ])('sends nothing on %s', async (_label, answer) => {
    const { call, fake } = await connect({ env: WRITES, onElicit: () => answer });
    const res = await call('pve_stop_vm', { vmid: 100 });
    expect(res.data.error_type).toBe('user_cancelled');
    expect(res.data.hint).toContain('Do not retry');
    expect(fake.writes()).toHaveLength(0);
  });

  it('fails closed when asking itself fails', async () => {
    const { call, fake } = await connect({
      env: WRITES,
      onElicit: () => {
        throw new Error('no human around');
      },
    });
    const res = await call('pve_stop_vm', { vmid: 100 });
    expect(res.data.error_type).toBe('user_cancelled');
    expect(fake.writes()).toHaveLength(0);
  });

  it('does not ask for what is not destructive, nor for what the gate refuses, nor in a dry run', async () => {
    let asked = 0;
    const onElicit = () => {
      asked++;
      return { action: 'decline' as const };
    };
    const { call } = await connect({ env: WRITES, onElicit });
    expect((await call('pve_start_vm', { vmid: 100 })).isError).toBe(false);
    expect((await call('pve_list_vms')).isError).toBe(false);
    expect((await call('pve_stop_vm', { vmid: 100, dry_run: true })).isError).toBe(false);
    expect(asked).toBe(0);

    const { fake, env } = await twoInstances();
    const multi = await connect({ fake, env, onElicit });
    const refused = await multi.call('pve_stop_vm', { vmid: 100, node: 'pve1', instance: 'prod' });
    expect(refused.data.error_type).toBe('write_disabled');
    expect(asked).toBe(0);
  });

  it('asks when the arguments make an ordinary call destructive', async () => {
    let asked = 0;
    const { call } = await connect({
      env: WRITES,
      onElicit: () => {
        asked++;
        return { action: 'decline' };
      },
    });
    expect((await call('pve_create_vm', { vmid: 300 })).isError).toBe(false);
    expect(asked).toBe(0);
    expect((await call('pve_create_vm', { vmid: 300, force: true })).data.error_type).toBe('user_cancelled');
    expect(asked).toBe(1);
  });

  it('can be turned off, and goes ahead for a client that cannot ask', async () => {
    const off = await connect({ env: { ...WRITES, PROXMOX_ELICIT: 'false' }, onElicit: () => ({ action: 'decline' }) });
    expect((await off.call('pve_stop_vm', { vmid: 100 })).isError).toBe(false);
    const unable = await connect({ env: WRITES });
    expect((await unable.call('pve_stop_vm', { vmid: 100 })).isError).toBe(false);
  });

  it('announces destructive tools to clients that decide by themselves', async () => {
    const { client } = await connect({ env: WRITES });
    const { tools } = await client.listTools();
    const hint = (name: string) => tools.find((t) => t.name === name)!.annotations?.destructiveHint;
    expect(hint('pve_stop_vm')).toBe(true);
    expect(hint('pve_delete_vm_snapshot')).toBe(true);
    expect(hint('pve_create_vm')).toBe(true);
    expect(hint('pve_start_vm')).toBe(false);
  });
});

describe('dry run', () => {
  it('sends nothing on dry_run: true, and shows what would go out', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const res = await call('pve_update_lxc_config', { vmid: 101, description: 'hello', net: { 0: 'name=eth0,bridge=vmbr0' }, cipassword: undefined, dry_run: true });
    expect(res.isError).toBe(false);
    expect(res.data.dry_run).toBe(true);
    expect(res.data.would_send).toEqual([{ method: 'PUT', path: '/nodes/pve1/lxc/101/config', params: { description: 'hello', net0: 'name=eth0,bridge=vmbr0' } }]);
    expect(res.data.note).toContain('nothing was sent');
    expect(fake.writes()).toHaveLength(0);
  });

  it('applies to the whole instance, and opens write tools without allowing any write', async () => {
    const { call, fake, toolNames } = await connect({ env: { PROXMOX_DRY_RUN: 'true' } });
    expect(await toolNames()).toContain('pve_start_vm');
    const res = await call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(false);
    expect(res.data.would_send[0]).toMatchObject({ method: 'POST', path: '/nodes/pve1/qemu/100/status/start' });
    expect(res.data.exitstatus).toBe('OK');
    expect(fake.writes()).toHaveLength(0);
    expect(fake.tasks.size).toBe(0);
  });

  it('still needs the elevated gate, and still reads', async () => {
    const { call, fake } = await connect({ env: { PROXMOX_DRY_RUN: 'true' } });
    expect((await call('pve_api_write', { method: 'POST', path: '/access/users', params: { userid: 'a@pve' } })).data.error_type).toBe('elevated_disabled');
    expect((await call('pve_list_vms')).isError).toBe(false);
    expect(fake.requests.length).toBeGreaterThan(0);
  });

  it('redacts secrets from would_send', async () => {
    const { call } = await connect({ env: ALL_GATES });
    const res = await call('pve_create_user', { userid: 'a@pve', password: 'hunter22', dry_run: true });
    expect(res.text).not.toContain('hunter22');
    expect(res.data.would_send[0].params.password).toBe('[REDACTED]');
  });
});

describe('audit log', () => {
  it('records writes and refusals with redacted arguments, not plain reads', async () => {
    const file = tempFile('audit.log');
    const { call } = await connect({ env: { ...ALL_GATES, PROXMOX_AUDIT_LOG: file, PROXMOX_PROTECTED_VMIDS: '100' }, fake: { permissive: true } });
    await call('pve_list_vms');
    await call('pve_create_user', { userid: 'a@pve', password: 'hunter22' });
    await call('pve_stop_vm', { vmid: 100 });
    const lines = await readAudit(file, 2);
    expect(lines.some((l) => l.tool === 'pve_list_vms')).toBe(false);

    const created = lines.find((l) => l.tool === 'pve_create_user')!;
    expect(created).toMatchObject({ instance: 'default', gate: 'elevated', outcome: 'ok' });
    expect(created.args.password).toBe('[REDACTED]');
    expect(created.writes).toEqual([{ method: 'POST', path: '/access/users', params: { userid: 'a@pve', password: '[REDACTED]' }, status: '200' }]);
    expect(typeof created.ts).toBe('string');
    expect(typeof created.duration_ms).toBe('number');
    expect(readFileSync(file, 'utf8')).not.toContain('hunter22');

    const refused = lines.find((l) => l.tool === 'pve_stop_vm')!;
    expect(refused).toMatchObject({ outcome: 'error', error_type: 'protected_guest', writes: [] });
  });

  it('records a refused read, a dry run, and never the content sent to a guest', async () => {
    const file = tempFile('audit.log');
    const { call } = await connect({ env: { PROXMOX_ALLOW_WRITES: 'true', PROXMOX_AUDIT_LOG: file } });
    await call('pve_api_read', { path: '/nodes/pve1/report' });
    await call('pve_start_vm', { vmid: 100, dry_run: true });
    const secret = 'top-secret-file-content';
    await call('pve_api_write', { method: 'PUT', path: '/nodes/pve1/qemu/100/config', params: { description: 'x' }, dry_run: true });
    const lines = await readAudit(file, 3);
    expect(lines.find((l) => l.tool === 'pve_api_read')).toMatchObject({ error_type: 'sensitive_disabled' });
    expect(lines.find((l) => l.tool === 'pve_start_vm')).toMatchObject({ dry_run: true, outcome: 'ok' });
    expect(readFileSync(file, 'utf8')).not.toContain(secret);
  });

  it('stops the server at startup when the log cannot be written', async () => {
    await expect(connect({ env: { PROXMOX_AUDIT_LOG: join(dir, 'no', 'such', 'dir', 'audit.log') } })).rejects.toThrow(/PROXMOX_AUDIT_LOG/);
  });
});

describe('node resolution', () => {
  it('finds the node from the vmid, and only asks the cluster once', async () => {
    const { call, fake } = await connect({ fake: { nodes: ['pve1', 'pve2'], guests: [{ vmid: 200, type: 'qemu', node: 'pve2' }] } });
    expect((await call('pve_get_vm_config', { vmid: 200 })).isError).toBe(false);
    expect((await call('pve_get_vm_status', { vmid: 200 })).isError).toBe(false);
    expect(fake.find('GET', '/nodes/{node}/qemu/{vmid}/config')[0]!.pathParams.node).toBe('pve2');
    expect(fake.find('GET', '/cluster/resources')).toHaveLength(1);
  });

  it('follows a guest after a write', async () => {
    const { call, fake } = await connect({ env: WRITES, fake: { nodes: ['pve1', 'pve2'], guests: [{ vmid: 200, type: 'qemu', node: 'pve1' }] } });
    await call('pve_get_vm_config', { vmid: 200 });
    await call('pve_migrate_vm', { vmid: 200, target: 'pve2' });
    await call('pve_get_vm_config', { vmid: 200 });
    expect(fake.find('GET', '/nodes/{node}/qemu/{vmid}/config').at(-1)!.pathParams.node).toBe('pve2');
  });

  it('respects a node given explicitly', async () => {
    const { call, fake } = await connect({ fake: { nodes: ['pve1', 'pve2'], guests: [{ vmid: 200, type: 'qemu', node: 'pve2' }] } });
    await call('pve_get_vm_config', { vmid: 200, node: 'pve2' });
    expect(fake.find('GET', '/cluster/resources')).toHaveLength(0);
  });

  it('says so when the guest is of the other type, or does not exist', async () => {
    const { call } = await connect();
    const wrong = await call('pve_get_lxc_status', { vmid: 100 });
    expect(wrong.data.error_type).toBe('invalid_input');
    expect(wrong.data.error).toContain('VM');
    const missing = await call('pve_get_vm_status', { vmid: 999 });
    expect(missing.data.error_type).toBe('not_found');
  });

  it('takes the only node, else the default one, else lists them', async () => {
    const one = await connect();
    expect((await one.call('pve_list_vms')).isError).toBe(false);

    const many = await connect({ fake: { nodes: ['pve1', 'pve2'] } });
    const res = await many.call('pve_list_vms');
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.details.nodes).toEqual(['pve1', 'pve2']);

    const withDefault = await connect({ fake: { nodes: ['pve1', 'pve2'] }, env: { PROXMOX_DEFAULT_NODE: 'pve2' } });
    expect((await withDefault.call('pve_list_vms')).isError).toBe(false);
    expect(withDefault.fake.find('GET', '/nodes/{node}/qemu')[0]!.pathParams.node).toBe('pve2');
  });

  it('never guesses the node to take out of a cluster', async () => {
    const { call, fake } = await connect({ env: ALL_GATES, fake: { permissive: true } });
    const res = await call('pve_remove_cluster_node', {});
    expect(res.isError).toBe(true);
    expect(fake.find('DELETE', '/cluster/config/nodes/{node}')).toHaveLength(0);
    await call('pve_remove_cluster_node', { node: 'pve9' });
    expect(fake.find('DELETE', '/cluster/config/nodes/{node}')[0]!.pathParams.node).toBe('pve9');
  });

  it('reports an offline node as such', async () => {
    const { call, fake } = await connect();
    fake.setNodeOnline('pve1', false);
    const res = await call('pve_list_vms', { node: 'pve1' });
    expect(res.data.error_type).toBe('node_unreachable');
    expect(res.data.http_status).toBe(595);
  });
});

describe('tasks', () => {
  it('waits by default, and returns the result with the end of the log', async () => {
    const { call, fake } = await connect({ env: WRITES, fake: { taskPolls: 1 } });
    const res = await call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ node: 'pve1', status: 'stopped', exitstatus: 'OK' });
    expect(res.data.log_tail).toContain('TASK OK');
    expect(fake.guests.get(100)!.status).toBe('running');
    expect(fake.find('GET', '/nodes/{node}/tasks/{upid}/status').length).toBeGreaterThanOrEqual(2);
  });

  it('turns a failed task into an error with the log', async () => {
    const { call, fake } = await connect({ env: WRITES });
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/start', (_r, p) => fake.startTask(p.node!, 'qmstart', p.vmid!, { exitstatus: 'start failed: no space', log: ['oops', 'TASK ERROR: start failed: no space'] }));
    const res = await call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('task_failed');
    expect(res.data.details.log_tail).toContain('oops');
    expect(res.data.details.exitstatus).toBe('start failed: no space');
  });

  it('counts warnings as a success, and says so', async () => {
    const { call, fake } = await connect({ env: WRITES });
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/start', (_r, p) => fake.startTask(p.node!, 'qmstart', p.vmid!, { exitstatus: 'WARNINGS: 2' }));
    const res = await call('pve_start_vm', { vmid: 100 });
    expect(res.isError).toBe(false);
    expect(res.data.warning).toContain('warnings: 2');
  });

  it('hands over a task that outlasts the delay, without calling it a failure', async () => {
    const { call, fake } = await connect({ env: WRITES });
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/start', (_r, p) => fake.startTask(p.node!, 'qmstart', p.vmid!, { polls: 1000 }));
    const res = await call('pve_start_vm', { vmid: 100, wait_seconds: 0 });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ node: 'pve1', still_running: true, next_step: 'pve_wait_task' });
    expect(res.data.task).toMatch(/^UPID:/);
  });

  it('honours PROXMOX_TASK_WAIT_SECONDS', async () => {
    const { call, fake } = await connect({ env: { ...WRITES, PROXMOX_TASK_WAIT_SECONDS: '0' } });
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/start', (_r, p) => fake.startTask(p.node!, 'qmstart', p.vmid!, { polls: 1000 }));
    expect((await call('pve_start_vm', { vmid: 100 })).data.still_running).toBe(true);
  });

  it('returns the task straight away on wait: false', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const res = await call('pve_start_vm', { vmid: 100, wait: false });
    expect(res.data.task).toMatch(/^UPID:pve1:/);
    expect(res.data.next_step).toBe('pve_wait_task');
    expect(fake.find('GET', '/nodes/{node}/tasks/{upid}/status')).toHaveLength(0);
  });

  it('leaves a string that is no task as it is, and waits on the generic tool too', async () => {
    const { call, fake } = await connect({ env: ALL_GATES, fake: { permissive: true } });
    const plain = await call('pve_register_acme_account', { contact: 'a@example.com' });
    expect(plain.data.result).toBe('ok');
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/resume', (_r, p) => fake.startTask(p.node!, 'qmresume', p.vmid!));
    const res = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/status/resume' });
    expect(res.data.exitstatus).toBe('OK');
  });
});

describe('paging and size limits', () => {
  it('pages lists on the client side', async () => {
    const guests = Array.from({ length: 5 }, (_, i) => ({ vmid: 200 + i, type: 'qemu' as const }));
    const { call } = await connect({ fake: { guests } });
    const first = await call('pve_list_vms', { page_limit: 2 });
    expect(first.data).toMatchObject({ total: 5, count: 2, offset: 0, has_more: true, next_offset: 2 });
    expect(first.data.rows.map((r: { vmid: number }) => r.vmid)).toEqual([200, 201]);
    const last = await call('pve_list_vms', { page_limit: 2, page_offset: 4 });
    expect(last.data).toMatchObject({ count: 1, offset: 4, has_more: false });
    expect(last.data.next_offset).toBeUndefined();
    const all = await call('pve_list_vms');
    expect(all.data).toMatchObject({ total: 5, count: 5, has_more: false });
  });

  it('cuts rows to the size limit and says where to go on, and that does work', async () => {
    const guests = Array.from({ length: 300 }, (_, i) => ({ vmid: 1000 + i, type: 'qemu' as const, name: `guest-with-a-rather-long-name-${i}` }));
    const { call } = await connect({ fake: { guests }, env: { PROXMOX_MAX_RESPONSE_CHARS: '2000' } });
    const first = await call('pve_list_vms');
    expect(first.text.length).toBeLessThanOrEqual(2000);
    expect(first.data.has_more).toBe(true);
    expect(first.data.total).toBe(300);
    expect(first.data.truncated).toContain('page_offset');
    const next = await call('pve_list_vms', { page_offset: first.data.next_offset, page_limit: 1 });
    expect(next.data.rows[0].vmid).toBe(1000 + first.data.next_offset);
  });

  it('offers page_offset where a native limit and start exist too, since a cut answer points at it', async () => {
    const { call, fake } = await connect({ env: { PROXMOX_MAX_RESPONSE_CHARS: '2000' } });
    for (let i = 0; i < 100; i++) fake.startTask('pve1', 'qmstart', String(i));
    const first = await call('pve_list_node_tasks', {});
    expect(first.data.has_more).toBe(true);
    const next = await call('pve_list_node_tasks', { page_offset: first.data.next_offset });
    expect(next.isError).toBe(false);
    expect(next.data.offset).toBe(first.data.next_offset);
  });

  it('cuts what has no rows into a preview that is still valid JSON', () => {
    const text = renderResult({ blob: 'x'.repeat(5000) }, 2000);
    const parsed = JSON.parse(text) as Record<string, unknown>;
    expect(parsed.truncated).toBe(true);
    expect(parsed.total_chars).toBeGreaterThan(5000);
    expect(text.length).toBeLessThanOrEqual(2000);
  });
});

describe('what tools send', () => {
  it('spreads indexed params and encodes the odd ones', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const key = 'ssh-ed25519 AAAA+B/C= me@host';
    await call('pve_create_vm', { vmid: 300, net: { 0: 'virtio,bridge=vmbr0', 1: 'e1000,bridge=vmbr1' }, numa_n: { 0: 'cpus=0-1' }, numa: true, sshkeys: key });
    const body = fake.find('POST', '/nodes/{node}/qemu')[0]!.body;
    expect(body).toMatchObject({ vmid: '300', net0: 'virtio,bridge=vmbr0', net1: 'e1000,bridge=vmbr1', numa0: 'cpus=0-1', numa: '1', sshkeys: encodeURIComponent(key) });
    expect(body).not.toHaveProperty('net');
    expect(body).not.toHaveProperty('numa_n');

    await call('pve_create_lxc', { vmid: 301, ostemplate: 'local:vztmpl/x.tar.zst', unprivileged: true, 'ssh-public-keys': key });
    expect(fake.find('POST', '/nodes/{node}/lxc')[0]!.body['ssh-public-keys']).toBe(key);
  });

  it('validates input before anything goes out', async () => {
    const { call, fake } = await connect({ env: WRITES });
    for (const args of [{ vmid: 'abc' }, { vmid: 100, node: '../..' }, { vmid: 100, node: 'a/b' }, {}]) {
      const res = await call('pve_start_vm', args);
      expect(res.isError).toBe(true);
    }
    expect(fake.writes()).toHaveLength(0);
  });

  it('encodes a value holding a slash into one segment', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const res = await call('pve_delete_storage_volume', { storage: 'local', volume: 'local:iso/debian.iso' });
    expect(res.isError).toBe(false);
    expect(fake.find('DELETE', '/nodes/{node}/storage/{storage}/content/{volume}')[0]!.rawUrl).toBe('/api2/json/nodes/pve1/storage/local/content/local:iso%2Fdebian.iso');
  });

  it('refuses to write a redaction placeholder back', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const res = await call('pve_update_vm_config', { vmid: 100, cipassword: '**********' });
    expect(res.data.error_type).toBe('invalid_input');
    expect(fake.writes()).toHaveLength(0);
  });
});

describe('secrets in answers', () => {
  it('hides a new token unless sensitive data is allowed, and the tool warns of it', async () => {
    const env = { ...ALL_GATES, PROXMOX_ALLOW_SENSITIVE: 'false' };
    const closed = await connect({ env });
    const res = await closed.call('pve_create_user_token', { userid: 'a@pve', tokenid: 't' });
    expect(res.data.value).toBe('[REDACTED]');
    expect(res.data['full-tokenid']).toBe('a@pve!t');
    expect(res.data.info.privsep).toBe(1);
    const { tools } = await closed.client.listTools();
    expect(tools.find((t) => t.name === 'pve_create_user_token')!.description).toContain('PROXMOX_ALLOW_SENSITIVE');

    const open = await connect({ env: ALL_GATES });
    const shown = await open.call('pve_create_user_token', { userid: 'a@pve', tokenid: 't' });
    expect(shown.data.value).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
  });

  it('redacts what travels with other data, and keeps what is public', async () => {
    const { call, fake } = await connect();
    fake.guests.get(100)!.config = { cipassword: '**********', sshkeys: 'ssh-ed25519%20AAAA', name: 'web', fingerprint: 'AB:CD' };
    const res = await call('pve_get_vm_config', { vmid: 100 });
    expect(res.data.cipassword).toBe('[REDACTED]');
    expect(res.data.sshkeys).toBe('ssh-ed25519%20AAAA');
    expect(res.data.fingerprint).toBe('AB:CD');
  });

  it('scrubs PEM keys and escape sequences from error text', async () => {
    const { call, fake } = await connect();
    fake.on('GET', '/version', () => pveError(500, 'boom \u001b[31m-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----'));
    const res = await call('pve_get_version');
    expect(res.data.error_type).toBe('upstream_error');
    expect(res.text).not.toContain('BEGIN PRIVATE');
    expect(res.text).not.toContain('\\u001b');
  });
});

describe('errors', () => {
  it('come back as isError JSON, with type, status, hint and field errors', async () => {
    const { call } = await connect({ env: WRITES });
    const res = await call('pve_create_vm', { vmid: 100 });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('upstream_error');
    expect(res.data.error).toContain('already exists');

    const invalid = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/status/start', params: { nonsense: 1 } });
    expect(invalid.data.error_type).toBe('validation_failed');
    expect(invalid.data.http_status).toBe(400);
    expect(invalid.data.details.fields.nonsense).toContain('not defined');
    expect(invalid.data.hint).toContain('pve_api_describe');
  });

  it('name an endpoint the fake does not model as absent on this version', async () => {
    const { call } = await connect();
    const res = await call('pve_list_ha_rules');
    expect(res.data.error_type).toBe('not_supported');
    expect(res.data.hint).toContain('pve_get_version');
  });

  it('survive the API being down', async () => {
    const fake = new FakePve();
    await fake.start();
    const { call } = await connect({ fake });
    await fake.stop();
    const res = await call('pve_get_version');
    expect(res.data.error_type).toBe('unreachable');
    await fake.start();
  });
});

describe('pve_mcp_info', () => {
  it('says what is allowed, and no secret', async () => {
    const { call } = await connect({ env: { ...WRITES, PROXMOX_PROTECTED_VMIDS: '101,100', PROXMOX_DEFAULT_NODE: 'pve1' } });
    const res = await call('pve_mcp_info');
    expect(res.data.server).toBe('pvemcp');
    expect(res.data.default_instance).toBe('default');
    expect(res.data.instances.default).toMatchObject({ auth: 'api token', allow_writes: true, allow_elevated: false, allow_ssh: false, dry_run: false, default_node: 'pve1', protected_vmids: [100, 101], local_transfers: false });
    expect(res.data.api_schema.methods).toBe(680);
    expect(res.data.tools).toBeGreaterThan(300);
    expect(res.data.toolsets).toContain('vm');
    expect(res.data.toolsets_not_loaded).toContain('sdn');
    expect(res.text).not.toContain('11111111-2222');
  });

  it('stays visible whatever the toolsets, and the server instructions start from it', async () => {
    const { toolNames, client } = await connect({ env: { PROXMOX_TOOLSETS: 'sdn' } });
    expect(await toolNames()).toContain('pve_mcp_info');
    expect(client.getInstructions()).toContain('pve_mcp_info');
    expect(client.getInstructions()).toContain('untrusted');
  });
});

describe('generic tools', () => {
  it('pve_api_search finds methods with their tool and gate', async () => {
    const { call } = await connect();
    const res = await call('pve_api_search', { query: 'lxc snapshot rollback' });
    expect(res.data.rows).toContainEqual(expect.objectContaining({ method: 'POST', path: '/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback', tool: 'pve_rollback_lxc_snapshot', gate: 'write', destructive: true }));
    const filtered = await call('pve_api_search', { query: 'qemu config', method: 'PUT' });
    expect(filtered.data.rows.every((r: { method: string }) => r.method === 'PUT')).toBe(true);
    const paged = await call('pve_api_search', { query: 'firewall', page_limit: 3 });
    expect(paged.data.rows).toHaveLength(3);
    expect(paged.data.has_more).toBe(true);
  });

  it('pve_api_search names no tool for what has none, and the curated one for upload', async () => {
    const { call } = await connect();
    const blocked = await call('pve_api_search', { query: 'execute', method: 'POST' });
    expect(blocked.data.rows.find((r: { path: string }) => r.path === '/nodes/{node}/execute').tool).toBeNull();
    const upload = await call('pve_api_describe', { method: 'POST', path: '/nodes/{node}/storage/{storage}/upload' });
    expect(upload.data.tool).toBe('pve_upload_to_storage');
  });

  it('pve_api_describe takes a template or a concrete path, and gives the full parameters', async () => {
    const { call } = await connect();
    const a = await call('pve_api_describe', { method: 'POST', path: '/nodes/{node}/qemu' });
    const b = await call('pve_api_describe', { method: 'POST', path: '/nodes/pve1/qemu' });
    expect(a.data).toEqual(b.data);
    expect(a.data.tool).toBe('pve_create_vm');
    expect(a.data.params['net[n]'].description).toContain('bridge=');
    expect(a.data.permissions).toContain('VM.Allocate');
    const missing = await call('pve_api_describe', { method: 'GET', path: '/nope' });
    expect(missing.data.error_type).toBe('not_found');
  });

  it('pve_api_read reads and pages, with path_params for values holding a slash', async () => {
    const { call, fake } = await connect({ fake: { permissive: true } });
    const list = await call('pve_api_read', { path: '/cluster/resources', params: { type: 'vm' }, page_limit: 1 });
    expect(list.data).toMatchObject({ total: 2, count: 1, has_more: true });
    await call('pve_api_read', { path: '/nodes/pve1/storage/local/content/{volume}', path_params: { volume: 'local:iso/x.iso' } });
    expect(fake.find('GET', '/nodes/{node}/storage/{storage}/content/{volume}')[0]!.pathParams.volume).toBe('local:iso/x.iso');
  });

  it('pve_api_write writes, with confirmation since it can do anything', async () => {
    let asked = 0;
    const { call, fake } = await connect({
      env: WRITES,
      onElicit: () => {
        asked++;
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const res = await call('pve_api_write', { method: 'POST', path: '/nodes/pve1/qemu/100/status/start' });
    expect(res.data.exitstatus).toBe('OK');
    expect(asked).toBe(1);
    expect(fake.writes()).toHaveLength(1);
  });
});

describe('pve_upload_to_storage', () => {
  it('sends a file from the local directory as multipart, and waits for the task', async () => {
    const root = mkdtempSync(join(dir, 'transfers-'));
    writeFileSync(join(root, 'debian.iso'), 'iso-bytes');
    const { call, fake } = await connect({ env: { ...WRITES, PROXMOX_LOCAL_DIR: root } });
    const res = await call('pve_upload_to_storage', { storage: 'local', content: 'iso', local_path: 'debian.iso', checksum: 'abc', 'checksum-algorithm': 'sha256' });
    expect(res.isError).toBe(false);
    expect(res.data.exitstatus).toBe('OK');
    const req = fake.find('POST', '/nodes/{node}/storage/{storage}/upload')[0]!;
    expect(req.body).toMatchObject({ content: 'iso', checksum: 'abc', 'checksum-algorithm': 'sha256' });
    expect(req.file).toMatchObject({ field: 'filename', filename: 'debian.iso', bytes: 9 });
    expect(req.file!.content.toString()).toBe('iso-bytes');
  });

  it('refuses without a local directory, outside it, and in a dry run sends nothing', async () => {
    const root = mkdtempSync(join(dir, 'transfers-'));
    writeFileSync(join(root, 'a.iso'), 'x');
    const none = await connect({ env: WRITES });
    expect((await none.call('pve_upload_to_storage', { storage: 'local', content: 'iso', local_path: 'a.iso' })).data.error_type).toBe('local_path_refused');
    const { call, fake } = await connect({ env: { ...WRITES, PROXMOX_LOCAL_DIR: root } });
    expect((await call('pve_upload_to_storage', { storage: 'local', content: 'iso', local_path: '../../x' })).data.error_type).toBe('local_path_refused');
    const dry = await call('pve_upload_to_storage', { storage: 'local', content: 'iso', local_path: 'a.iso', dry_run: true });
    expect(dry.data.dry_run).toBe(true);
    expect(dry.data.would_send[0].params.filename).toBe('a.iso');
    expect(fake.writes()).toHaveLength(0);
  });
});
