import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { allTools } from '../src/tools/index.js';
import { sshLxcTools } from '../src/tools/ssh-lxc.js';
import { sshNodeTools } from '../src/tools/ssh-node.js';
import { workflowTools } from '../src/tools/workflows.js';
import { FakePve, pveError, Reply } from './fake-pve.js';
import { ALL_GATES, closeAll, connect, WRITES } from './harness.js';

afterEach(closeAll);

const NOW = () => Math.floor(Date.now() / 1000);
const GIB = 1024 ** 3;
const FORBIDDEN = () => pveError(403, 'Permission check failed (/, Sys.Audit)');

const WORKFLOW_NAMES = [
  'pve_overview',
  'pve_find_guest',
  'pve_wait_task',
  'pve_get_task_log_tail',
  'pve_guest_power',
  'pve_snapshot_guest',
  'pve_list_guest_snapshots',
  'pve_provision_lxc',
  'pve_provision_vm_from_template',
  'pve_health_check',
  'pve_security_audit',
  'pve_backup_coverage',
  'pve_capacity_report',
];

/** Rows of /cluster/resources as Proxmox gives them, with the documented fields. */
function resources() {
  return [
    { id: 'node/pve1', type: 'node', node: 'pve1', status: 'online', cpu: 0.25, maxcpu: 8, mem: 8 * GIB, maxmem: 16 * GIB, disk: 10 * GIB, maxdisk: 100 * GIB, uptime: 1000, level: '' },
    { id: 'node/pve2', type: 'node', node: 'pve2', status: 'online', cpu: 0.5, maxcpu: 4, mem: 2 * GIB, maxmem: 8 * GIB, disk: 20 * GIB, maxdisk: 100 * GIB, uptime: 2000, level: '' },
    { id: 'qemu/100', type: 'qemu', vmid: 100, name: 'web', node: 'pve1', status: 'running', maxcpu: 8, maxmem: 16 * GIB, mem: 4 * GIB, cpu: 0.1, disk: 0, maxdisk: 50 * GIB, tags: 'prod;web', template: 0 },
    { id: 'lxc/101', type: 'lxc', vmid: 101, name: 'db', node: 'pve1', status: 'running', maxcpu: 4, maxmem: 8 * GIB, mem: 2 * GIB, cpu: 0.2, disk: 1 * GIB, maxdisk: 20 * GIB, tags: 'production', template: 0, pool: 'core' },
    { id: 'qemu/102', type: 'qemu', vmid: 102, name: 'old-web', node: 'pve2', status: 'stopped', maxcpu: 16, maxmem: 32 * GIB, mem: 0, cpu: 0, disk: 0, maxdisk: 200 * GIB, template: 0 },
    { id: 'qemu/9000', type: 'qemu', vmid: 9000, name: 'tpl', node: 'pve2', status: 'stopped', maxcpu: 64, maxmem: 64 * GIB, mem: 0, cpu: 0, disk: 0, maxdisk: 500 * GIB, template: 1 },
    { id: 'storage/pve1/local', type: 'storage', storage: 'local', node: 'pve1', status: 'available', disk: 10 * GIB, maxdisk: 100 * GIB, shared: 0, plugintype: 'dir', content: 'iso,vztmpl,backup' },
    { id: 'storage/pve2/local', type: 'storage', storage: 'local', node: 'pve2', status: 'available', disk: 30 * GIB, maxdisk: 100 * GIB, shared: 0, plugintype: 'dir', content: 'iso,vztmpl,backup' },
    { id: 'storage/pve1/nas', type: 'storage', storage: 'nas', node: 'pve1', status: 'available', disk: 500 * GIB, maxdisk: 1000 * GIB, shared: 1, plugintype: 'nfs', content: 'backup,images' },
    { id: 'storage/pve2/nas', type: 'storage', storage: 'nas', node: 'pve2', status: 'available', disk: 500 * GIB, maxdisk: 1000 * GIB, shared: 1, plugintype: 'nfs', content: 'backup,images' },
  ];
}

const CLUSTER_STATUS = [
  { type: 'cluster', id: 'cluster', name: 'lab', quorate: 1, nodes: 2, version: 7 },
  { type: 'node', id: 'node/pve1', name: 'pve1', ip: '10.0.0.1', online: 1, local: 1, nodeid: 1, level: '' },
  { type: 'node', id: 'node/pve2', name: 'pve2', ip: '10.0.0.2', online: 1, local: 0, nodeid: 2, level: '' },
];

const NODES = [
  { node: 'pve1', status: 'online', cpu: 0.25, maxcpu: 8, mem: 8 * GIB, maxmem: 16 * GIB, uptime: 1000 },
  { node: 'pve2', status: 'online', cpu: 0.5, maxcpu: 4, mem: 2 * GIB, maxmem: 8 * GIB, uptime: 2000 },
];

const HA_STATUS = [
  { id: 'quorum', type: 'quorum', node: 'pve1', status: 'OK', quorate: true },
  { id: 'master', type: 'master', node: 'pve1', status: 'pve1 (active, Wed Nov  5 20:00:00 2026)' },
  { id: 'lrm:pve1', type: 'lrm', node: 'pve1', status: 'pve1 (active, Wed Nov  5 20:00:00 2026)' },
  { id: 'service:vm:100', type: 'service', sid: 'vm:100', node: 'pve1', status: 'vm:100 (pve1, started)', crm_state: 'started', request_state: 'started', state: 'started' },
];

/** A two-node cluster where everything is fine, in the shapes of the API schema. */
async function healthyCluster(): Promise<FakePve> {
  const fake = new FakePve({
    nodes: ['pve1', 'pve2'],
    guests: [
      { vmid: 100, type: 'qemu', name: 'web', node: 'pve1', ip: '10.0.0.6', config: { net0: 'virtio=AA:BB,bridge=vmbr0,firewall=1' } },
      { vmid: 101, type: 'lxc', name: 'db', node: 'pve1', ip: '10.0.0.5', config: { unprivileged: 1, net0: 'name=eth0,bridge=vmbr0,firewall=1' } },
      { vmid: 102, type: 'qemu', name: 'old-web', node: 'pve2', status: 'stopped', config: {} },
    ],
  });
  fake.on('GET', '/cluster/resources', (req) => {
    const rows = resources();
    const wanted = req.query.type;
    if (wanted === 'vm') return rows.filter((r) => r.type === 'qemu' || r.type === 'lxc');
    if (wanted === 'storage') return rows.filter((r) => r.type === 'storage');
    if (wanted === 'node') return rows.filter((r) => r.type === 'node');
    return rows;
  });
  fake.on('GET', '/cluster/status', () => CLUSTER_STATUS);
  fake.on('GET', '/nodes', () => NODES);
  fake.on('GET', '/cluster/ha/status/current', () => HA_STATUS);
  fake.on('GET', '/cluster/tasks', () => [{ upid: 'UPID:pve1:00000001:00000002:6A000000:qmstart:100:root@pam:', node: 'pve1', type: 'qmstart', id: '100', user: 'root@pam', starttime: NOW() - 60, endtime: NOW() - 50, status: 'OK' }]);
  fake.on('GET', '/cluster/ceph/status', () => ({ health: { status: 'HEALTH_OK', checks: {} } }));
  fake.on('GET', '/nodes/{node}/status', () => ({ cpu: 0.1, memory: { total: 16 * GIB, used: 8 * GIB, free: 8 * GIB }, rootfs: { total: 100 * GIB, used: 10 * GIB, avail: 90 * GIB, free: 90 * GIB }, pveversion: 'pve-manager/9.1.0' }));
  fake.on('GET', '/nodes/{node}/storage', () => [
    { storage: 'local', type: 'dir', content: 'iso,vztmpl,backup', active: 1, enabled: 1, shared: 0, total: 100 * GIB, used: 10 * GIB, avail: 90 * GIB, used_fraction: 0.1 },
    { storage: 'nas', type: 'nfs', content: 'backup,images', active: 1, enabled: 1, shared: 1, total: 1000 * GIB, used: 500 * GIB, avail: 500 * GIB, used_fraction: 0.5 },
  ]);
  fake.on('GET', '/nodes/{node}/services', () => [{ name: 'pveproxy', service: 'pveproxy', desc: 'PVE API Proxy', state: 'running', 'active-state': 'active', 'unit-state': 'enabled' }]);
  fake.on('GET', '/nodes/{node}/replication', () => []);
  fake.on('GET', '/nodes/{node}/subscription', () => ({ status: 'active', level: 'c', productname: 'Proxmox VE Community', key: 'pve4c-secret', nextduedate: '2027-01-01' }));

  fake.on('GET', '/cluster/firewall/options', () => ({ enable: 1, policy_in: 'DROP' }));
  fake.on('GET', '/nodes/{node}/firewall/options', () => ({ enable: 1 }));
  for (const type of ['qemu', 'lxc'] as const) fake.on('GET', `/nodes/{node}/${type}/{vmid}/firewall/options`, () => ({ enable: 1 }));
  fake.on('GET', '/access/users', () => [{ userid: 'root@pam', enable: 1, expire: 0, tokens: [{ tokenid: 'ops', expire: NOW() + 1000, privsep: 1 }] }]);
  fake.on('GET', '/access/tfa/{userid}', () => [{ id: 'totp1', type: 'totp', description: 'phone', created: 1, enable: 1 }]);
  fake.on('GET', '/access/acl', () => [{ path: '/vms', roleid: 'PVEVMUser', type: 'user', ugid: 'ops@pve', propagate: 1 }]);
  fake.on('GET', '/cluster/backup-info/not-backed-up', () => []);
  fake.on('GET', '/cluster/backup', () => [{ id: 'backup-1', enabled: 1, schedule: 'daily', storage: 'nas', all: 1, mode: 'snapshot', 'next-run': NOW() + 3600 }]);
  fake.on('GET', '/nodes/{node}/apt/update', () => []);
  fake.on('GET', '/nodes/{node}/certificates/info', () => [{ filename: 'pve-ssl.pem', notafter: NOW() + 365 * 86400, subject: 'CN=pve', pem: 'x' }]);
  fake.on('GET', '/nodes/{node}/storage/{storage}/content', (_req, p) => (p.storage === 'nas' ? [100, 101, 102].map((vmid) => ({ volid: `nas:backup/vzdump-${vmid}.tar.zst`, content: 'backup', format: 'tar.zst', vmid, ctime: NOW() - 86400, size: GIB })) : []));
  fake.on('GET', '/nodes/{node}/storage/{storage}/rrddata', () => []);
  await fake.start();
  return fake;
}

describe('the workflow tools as a whole', () => {
  it('has every tool of the design, with its own name', () => {
    const names = workflowTools().map((t) => t.name);
    expect(names.sort()).toEqual([...WORKFLOW_NAMES].sort());
    const others = allTools(() => ({}))
      .filter((t) => t.domain !== 'workflows')
      .map((t) => t.name);
    for (const name of names) expect(others).not.toContain(name);
  });

  it('shows only the read tools on a read-only server', async () => {
    const { toolNames } = await connect();
    const names = await toolNames();
    for (const name of WORKFLOW_NAMES.filter((n) => !['pve_guest_power', 'pve_snapshot_guest', 'pve_provision_lxc', 'pve_provision_vm_from_template'].includes(n))) expect(names).toContain(name);
    for (const name of ['pve_guest_power', 'pve_snapshot_guest', 'pve_provision_lxc', 'pve_provision_vm_from_template']) expect(names).not.toContain(name);
  });

  it('announces the right hints', async () => {
    const { client } = await connect({ env: WRITES });
    const { tools } = await client.listTools();
    const hints = (name: string) => tools.find((t) => t.name === name)!.annotations!;
    expect(hints('pve_guest_power').destructiveHint).toBe(true);
    expect(hints('pve_guest_power').readOnlyHint).toBe(false);
    expect(hints('pve_provision_lxc').destructiveHint).toBe(false);
    expect(hints('pve_provision_lxc').readOnlyHint).toBe(false);
    expect(hints('pve_provision_vm_from_template').destructiveHint).toBe(false);
    expect(hints('pve_health_check').readOnlyHint).toBe(true);
    expect(hints('pve_security_audit').readOnlyHint).toBe(true);
    expect(hints('pve_overview').readOnlyHint).toBe(true);
  });

  it('also comes with the toolsets of what it acts on', async () => {
    const { toolNames } = await connect({ env: { ...WRITES, PROXMOX_TOOLSETS: 'lxc' } });
    const names = await toolNames();
    expect(names).toContain('pve_provision_lxc');
    expect(names).toContain('pve_guest_power');
    expect(names).not.toContain('pve_provision_vm_from_template');
    expect(names).not.toContain('pve_health_check');
  });

  it('never points at a tool that does not exist', () => {
    const known = new Set(allTools(() => ({})).map((t) => t.name));
    // The SSH tools named in prompts, while their files are still being filled in.
    if (sshLxcTools().length === 0) for (const n of ['pve_lxc_info', 'pve_lxc_logs', 'pve_lxc_service_status']) known.add(n);
    if (sshNodeTools().length === 0) for (const n of ['pve_ssh_journal', 'pve_ssh_host_diagnostics']) known.add(n);
    for (const file of ['../src/tools/workflows.ts', '../src/prompts.ts']) {
      const text = readFileSync(new URL(file, import.meta.url), 'utf8');
      const mentioned = [...new Set(text.match(/\bpve_[a-z0-9_]+/g) ?? [])].filter((n) => !n.endsWith('_'));
      const missing = mentioned.filter((n) => !known.has(n));
      expect(missing, file).toEqual([]);
    }
  });
});

describe('pve_overview', () => {
  it('sums up the cluster from the fields the API documents', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_overview');
    expect(isError).toBe(false);
    expect(data.version.version).toBe('9.1.0');
    expect(data.quorum).toMatchObject({ state: 'quorate', cluster: 'lab', nodes_total: 2, nodes_online: 2 });
    expect(data.nodes.map((n: any) => n.node)).toEqual(['pve1', 'pve2']);
    expect(data.nodes[0]).toMatchObject({ cores: 8, cpu_percent: 25, memory_percent: 50 });
    expect(data.guests).toEqual({ total: 4, by_type: { qemu: 3, lxc: 1 }, by_status: { running: 2, stopped: 2 }, templates: 1 });
    const nas = data.storage.find((s: any) => s.storage === 'nas');
    expect(nas).toMatchObject({ shared: true, nodes: ['pve1', 'pve2'], used_percent: 50 });
    // Not shared: one per node, and not merged.
    expect(data.storage.filter((s: any) => s.storage === 'local')).toHaveLength(2);
    expect(data.ha).toMatchObject({ services: 1, quorate: true, by_state: { started: 1 }, problem_services: [] });
    expect(data.failed_tasks.count).toBe(0);
    expect(data.complete).toBe(true);
    expect(data.unavailable).toEqual({});
  });

  it('names a section it cannot read, and still answers the rest', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/ha/status/current', FORBIDDEN);
    fake.failNext('GET', '/cluster/status', new Reply(595, 'Connection timed out', { data: null }));
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_overview');
    expect(isError).toBe(false);
    expect(data.complete).toBe(false);
    expect(data.ha).toBeNull();
    expect(data.quorum).toBeNull();
    expect(data.unavailable.ha).toMatch(/forbidden/);
    expect(data.unavailable.quorum).toMatch(/node_unreachable/);
    expect(data.guests.total).toBe(4);
  });

  it('reports a single node as standalone rather than without quorum', async () => {
    const { call, fake } = await connect({ fake: { permissive: true } });
    fake.on('GET', '/cluster/status', () => [{ type: 'node', name: 'pve1', ip: '10.0.0.1', online: 1, local: 1, nodeid: 0 }]);
    const { data } = await call('pve_overview');
    expect(data.quorum.state).toBe('standalone');
  });

  it('counts recent failed tasks and only those', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/tasks', () => [
      { upid: 'u1', node: 'pve1', type: 'vzdump', id: '100', user: 'root@pam', starttime: NOW() - 100, endtime: NOW() - 90, status: 'job errors' },
      { upid: 'u2', node: 'pve1', type: 'vzdump', id: '101', user: 'root@pam', starttime: NOW() - 100, endtime: NOW() - 90, status: 'OK' },
      { upid: 'u3', node: 'pve1', type: 'vzdump', id: '101', user: 'root@pam', starttime: NOW() - 100, endtime: NOW() - 90, status: 'WARNINGS: 2' },
      { upid: 'u4', node: 'pve1', type: 'vzdump', id: '101', user: 'root@pam', starttime: NOW() - 100 },
      { upid: 'u5', node: 'pve1', type: 'vzdump', id: '102', user: 'root@pam', starttime: NOW() - 90 * 86400, endtime: NOW() - 90 * 86400, status: 'old failure' },
    ]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_overview');
    expect(data.failed_tasks.count).toBe(1);
    expect(data.failed_tasks.recent[0].upid).toBe('u1');
  });
});

describe('pve_find_guest', () => {
  it('filters by vmid, name, tag, status, node and type', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const ids = async (args: Record<string, unknown>) => (await call('pve_find_guest', args)).data.rows.map((r: any) => r.vmid);
    expect(await ids({ vmid: 101 })).toEqual([101]);
    expect(await ids({ name: 'WEB' })).toEqual([100, 102]);
    expect(await ids({ tag: 'prod' })).toEqual([100]);
    expect(await ids({ status: 'stopped' })).toEqual([102, 9000]);
    expect(await ids({ node: 'pve2' })).toEqual([102, 9000]);
    expect(await ids({ type: 'lxc' })).toEqual([101]);
    expect(await ids({ name: 'web', status: 'running' })).toEqual([100]);
    expect(await ids({ vmid: 999 })).toEqual([]);
  });

  it('finds a guest by IP, through LXC interfaces and through the agent', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    expect((await call('pve_find_guest', { ip: '10.0.0.5' })).data.rows.map((r: any) => r.vmid)).toEqual([101]);
    const vm = await call('pve_find_guest', { ip: '10.0.0.6' });
    expect(vm.data.rows.map((r: any) => r.vmid)).toEqual([100]);
    expect(vm.data.rows[0].ips).toEqual(['10.0.0.6']);
    expect(fake.find('GET', '/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces').length).toBeGreaterThan(0);
  });

  it('says which guests it could not check for an IP, rather than calling them no match', async () => {
    const fake = await healthyCluster();
    fake.guests.get(100)!.agent = false;
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_find_guest', { ip: '10.0.0.99' });
    expect(isError).toBe(false);
    expect(data.rows).toEqual([]);
    const reasons = Object.fromEntries(data.ip_not_checked.map((e: any) => [e.vmid, e.reason]));
    expect(reasons[100]).toMatch(/agent is not running/);
    expect(reasons[102]).toMatch(/status is stopped/);
    expect(reasons[101]).toBeUndefined();
  });

  it('adds addresses on request', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_find_guest', { vmid: 101, include_ips: true });
    expect(data.rows[0].ips).toEqual(['10.0.0.5']);
  });

  it('pages', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_find_guest', { page_limit: 2 });
    expect(data).toMatchObject({ total: 4, count: 2, has_more: true, next_offset: 2 });
  });

  it('is an error when the guest list itself is refused', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/resources', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_find_guest', { name: 'web' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
  });
});

describe('pve_wait_task and pve_get_task_log_tail', () => {
  it('waits for a task and returns its result', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'qmstart', '100', { polls: 1 });
    const { data, isError } = await call('pve_wait_task', { upid, wait_seconds: 10 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ upid, node: 'pve1', status: 'stopped', exitstatus: 'OK' });
  });

  it('is an error on a failed task, with the log', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'qmstart', '100', { exitstatus: 'start failed', log: ['boom'] });
    const { data, isError } = await call('pve_wait_task', { upid });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('task_failed');
    expect(data.details.log_tail).toEqual(['boom']);
  });

  it('says still_running when it outlasts the wait, and does not cancel it', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'qmstart', '100', { polls: 1000 });
    const { data, isError } = await call('pve_wait_task', { upid, wait_seconds: 0 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ task: upid, node: 'pve1', still_running: true, next_step: 'pve_wait_task' });
    expect(fake.writes()).toEqual([]);
  });

  it('refuses what is not a task id', async () => {
    const { call } = await connect();
    const { data, isError } = await call('pve_wait_task', { upid: 'not-a-upid' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('invalid_input');
  });

  it('is an error when the task cannot be read', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'qmstart', '100');
    fake.failNext('GET', '/nodes/{node}/tasks/{upid}/status', FORBIDDEN());
    const { data, isError } = await call('pve_wait_task', { upid });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
  });

  it('gives the end of a log, and the status', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'vzdump', '100', { log: ['one', 'two', 'three', 'four'] });
    const { data } = await call('pve_get_task_log_tail', { upid, lines: 2 });
    expect(data.log_tail).toEqual(['three', 'four']);
    expect(data.lines_read).toBe(4);
    expect(data.status).toBe('stopped');
    expect(data.node).toBe('pve1');
  });

  it('reads past the first page of a long log', async () => {
    const { call, fake } = await connect();
    const log = Array.from({ length: 12_001 }, (_, i) => `line ${i}`);
    const upid = fake.startTask('pve1', 'vzdump', '100', { log });
    const { data } = await call('pve_get_task_log_tail', { upid, lines: 1 });
    expect(data.log_tail).toEqual(['line 12000']);
    expect(data.lines_read).toBe(12_001);
  });

  it('does not pass off a log it could not read as an empty one', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'vzdump', '100');
    fake.failNext('GET', '/nodes/{node}/tasks/{upid}/log', FORBIDDEN());
    const { data, isError } = await call('pve_get_task_log_tail', { upid });
    expect(isError).toBe(false);
    expect(data.log_tail).toBeNull();
    expect(data.unavailable.log).toMatch(/forbidden/);
    expect(data.status).toBe('stopped');
  });

  it('is an error when neither status nor log can be read', async () => {
    const { call, fake } = await connect();
    const upid = fake.startTask('pve1', 'vzdump', '100');
    fake.failNext('GET', '/nodes/{node}/tasks/{upid}/log', FORBIDDEN());
    fake.failNext('GET', '/nodes/{node}/tasks/{upid}/status', FORBIDDEN());
    const { data, isError } = await call('pve_get_task_log_tail', { upid });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
  });
});

describe('pve_guest_power', () => {
  const fakeWith = async () => {
    const fake = new FakePve({ guests: [{ vmid: 100, type: 'qemu', status: 'stopped' }, { vmid: 101, type: 'lxc', status: 'running' }, { vmid: 103, type: 'qemu', status: 'running' }] });
    await fake.start();
    return fake;
  };

  it('starts a VM on the right path without asking anyone', async () => {
    const fake = await fakeWith();
    let asked = 0;
    const { call } = await connect({
      fake,
      env: WRITES,
      onElicit: () => {
        asked++;
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const { data, isError } = await call('pve_guest_power', { vmid: 100, action: 'start' });
    expect(isError).toBe(false);
    expect(asked).toBe(0);
    expect(data).toMatchObject({ vmid: 100, type: 'qemu', node: 'pve1', action: 'start', changed: true, status_before: 'stopped', status_after: 'running', exitstatus: 'OK' });
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/start')).toHaveLength(1);
  });

  it('stops a container on its own path, once a human agreed', async () => {
    const fake = await fakeWith();
    const messages: string[] = [];
    const { call } = await connect({
      fake,
      env: WRITES,
      onElicit: (message) => {
        messages.push(message);
        return { action: 'accept', content: { confirm: true } };
      },
    });
    const { data } = await call('pve_guest_power', { vmid: 101, action: 'stop' });
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/stop guest 101/);
    expect(data).toMatchObject({ type: 'lxc', status_after: 'stopped' });
    expect(fake.find('POST', '/nodes/{node}/lxc/{vmid}/status/stop')).toHaveLength(1);
  });

  it.each(['stop', 'shutdown', 'reboot'])('sends nothing when a human refuses %s', async (action) => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES, onElicit: () => ({ action: 'decline' }) });
    const { data, isError } = await call('pve_guest_power', { vmid: 103, action });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('user_cancelled');
    expect(fake.writes()).toEqual([]);
  });

  it('passes the shutdown options on', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES });
    await call('pve_guest_power', { vmid: 103, action: 'shutdown', timeout: 20, force_stop: true });
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/shutdown')[0]!.body).toEqual({ timeout: '20', forceStop: '1' });
  });

  it('refuses options that do not go with the action', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES });
    expect((await call('pve_guest_power', { vmid: 103, action: 'stop', force_stop: true })).data.error_type).toBe('invalid_input');
    expect((await call('pve_guest_power', { vmid: 100, action: 'start', timeout: 5 })).data.error_type).toBe('invalid_input');
    expect(fake.writes()).toEqual([]);
  });

  it('leaves alone a guest already in that state', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES });
    const started = await call('pve_guest_power', { vmid: 103, action: 'start' });
    expect(started.data).toMatchObject({ changed: false, status: 'running' });
    const stopped = await call('pve_guest_power', { vmid: 100, action: 'shutdown' });
    expect(stopped.data).toMatchObject({ changed: false, status: 'stopped' });
    expect(fake.writes()).toEqual([]);
  });

  it('refuses to reboot a stopped guest', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_guest_power', { vmid: 100, action: 'reboot' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('guest_not_running');
    expect(fake.writes()).toEqual([]);
  });

  it('goes ahead when it cannot read the status first, and says so', async () => {
    const fake = await fakeWith();
    fake.failNext('GET', '/nodes/{node}/qemu/{vmid}/status/current', FORBIDDEN());
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_guest_power', { vmid: 103, action: 'reboot' });
    expect(data.status_before).toBeNull();
    expect(data.status_before_unavailable).toMatch(/forbidden/);
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/reboot')).toHaveLength(1);
  });

  it('dry run: says what would go out, sends nothing and asks nobody', async () => {
    const fake = await fakeWith();
    let asked = 0;
    const { call } = await connect({
      fake,
      env: WRITES,
      onElicit: () => {
        asked++;
        return { action: 'decline' };
      },
    });
    const { data, isError } = await call('pve_guest_power', { vmid: 103, action: 'stop', dry_run: true });
    expect(isError).toBe(false);
    expect(asked).toBe(0);
    expect(data.dry_run).toBe(true);
    expect(data.would_send).toEqual([{ method: 'POST', path: '/nodes/pve1/qemu/103/status/stop' }]);
    expect(fake.writes()).toEqual([]);
    expect(fake.guests.get(103)!.status).toBe('running');
  });

  it('is refused by the policy for a protected guest', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: { ...WRITES, PROXMOX_PROTECTED_VMIDS: '103' } });
    const { data, isError } = await call('pve_guest_power', { vmid: 103, action: 'stop' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('protected_guest');
    expect(fake.writes()).toEqual([]);
  });

  it('reports a permission refusal from Proxmox', async () => {
    const fake = await fakeWith();
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/status/stop', pveError(403, 'Permission check failed (/vms/103, VM.PowerMgmt)'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_guest_power', { vmid: 103, action: 'stop' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
  });

  it('reports a failed task as an error', async () => {
    const fake = await fakeWith();
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/start', () => fake.startTask('pve1', 'qmstart', '100', { exitstatus: 'start failed: no space' }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_guest_power', { vmid: 100, action: 'start' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('task_failed');
  });

  it('does not claim a final state for a task that is still running', async () => {
    const fake = await fakeWith();
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/status/shutdown', () => fake.startTask('pve1', 'qmshutdown', '103', { polls: 1000 }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_guest_power', { vmid: 103, action: 'shutdown', wait_seconds: 0 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ still_running: true, next_step: 'pve_wait_task' });
    expect(data.changed).toBeUndefined();
    expect(data.status_after).toBeUndefined();
  });

  it('is an error for an unknown guest', async () => {
    const fake = await fakeWith();
    const { call } = await connect({ fake, env: WRITES });
    expect((await call('pve_guest_power', { vmid: 555, action: 'start' })).data.error_type).toBe('not_found');
  });
});

describe('pve_snapshot_guest and pve_list_guest_snapshots', () => {
  it('snapshots a VM and a container on their own paths', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const vm = await call('pve_snapshot_guest', { vmid: 100, snapname: 'before', description: 'why', vmstate: true });
    expect(vm.data).toMatchObject({ vmid: 100, type: 'qemu', snapname: 'before', exitstatus: 'OK' });
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/snapshot')[0]!.body).toEqual({ snapname: 'before', description: 'why', vmstate: '1' });
    const ct = await call('pve_snapshot_guest', { vmid: 101, snapname: 'before' });
    expect(ct.data.type).toBe('lxc');
    expect(fake.guests.get(101)!.snapshots.map((s) => s.name)).toEqual(['before']);
  });

  it('refuses memory on a container, before sending anything', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const { data, isError } = await call('pve_snapshot_guest', { vmid: 101, snapname: 'x1', vmstate: true });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('invalid_input');
    expect(fake.writes()).toEqual([]);
  });

  it('dry run sends nothing', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const { data } = await call('pve_snapshot_guest', { vmid: 100, snapname: 'before', dry_run: true });
    expect(data.would_send).toEqual([{ method: 'POST', path: '/nodes/pve1/qemu/100/snapshot', params: { snapname: 'before' } }]);
    expect(fake.writes()).toEqual([]);
    expect(fake.guests.get(100)!.snapshots).toEqual([]);
  });

  it('reports a refusal and a failure from Proxmox', async () => {
    const { call, fake } = await connect({ env: WRITES });
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/snapshot', pveError(403, 'Permission check failed (/vms/100, VM.Snapshot)'));
    expect((await call('pve_snapshot_guest', { vmid: 100, snapname: 'before' })).data.error_type).toBe('forbidden');
    await call('pve_snapshot_guest', { vmid: 100, snapname: 'twice' });
    expect((await call('pve_snapshot_guest', { vmid: 100, snapname: 'twice' })).isError).toBe(true);
  });

  it('rejects a bad name before it gets anywhere', async () => {
    const { call, fake } = await connect({ env: WRITES });
    const { isError } = await call('pve_snapshot_guest', { vmid: 100, snapname: '../x' });
    expect(isError).toBe(true);
    expect(fake.writes()).toEqual([]);
  });

  it('lists snapshots of either type without the current pseudo-entry', async () => {
    const { call, fake } = await connect();
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/snapshot', () => [
      { name: 'current', description: 'You are here!', parent: 'second' },
      { name: 'second', snaptime: 200, parent: 'first', description: '' },
      { name: 'first', snaptime: 100, description: '' },
    ]);
    const { data } = await call('pve_list_guest_snapshots', { vmid: 101 });
    expect(data.rows.map((r: any) => r.name)).toEqual(['first', 'second']);
    expect(data.current_parent).toBe('second');
    expect(data.type).toBe('lxc');
    const vm = await call('pve_list_guest_snapshots', { vmid: 100 });
    expect(vm.data).toMatchObject({ type: 'qemu', total: 0 });
  });

  it('reports a read refusal', async () => {
    const { call, fake } = await connect();
    fake.failNext('GET', '/nodes/{node}/qemu/{vmid}/snapshot', FORBIDDEN());
    expect((await call('pve_list_guest_snapshots', { vmid: 100 })).data.error_type).toBe('forbidden');
  });
});

function expectWellFormed(findings: any[]): void {
  for (const f of findings) {
    expect(f.severity).toEqual(expect.any(String));
    expect(f.object).toEqual(expect.any(String));
    expect(f.evidence).toBeDefined();
    expect(f.action).toEqual(expect.any(String));
    expect(f.action.length).toBeGreaterThan(10);
  }
}

describe('pve_health_check', () => {
  it('finds nothing on a healthy cluster, and says so without promising anything', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_health_check');
    expect(isError).toBe(false);
    expect(data.findings).toEqual([]);
    expect(data.overall).toBe('no_findings');
    expect(data.complete).toBe(true);
    expect(data.unavailable).toEqual({});
    expect(data.checked).toEqual(expect.arrayContaining(['nodes', 'quorum', 'storage', 'services', 'tasks', 'ha', 'ceph', 'replication', 'subscription', 'node_status']));
    expect(data.thresholds).toEqual({ storage_warn_percent: 85, storage_critical_percent: 95, memory_warn_percent: 90, task_hours: 24 });
    expect(JSON.stringify(data)).not.toContain('pve4c-secret');
  });

  it('reports each kind of problem with severity, object, evidence and action', async () => {
    const fake = await healthyCluster();
    fake.setNodeOnline('pve2', false);
    fake.on('GET', '/nodes', () => [NODES[0], { node: 'pve2', status: 'offline' }]);
    fake.on('GET', '/cluster/status', () => [{ ...CLUSTER_STATUS[0], quorate: 0 }, CLUSTER_STATUS[1], { ...CLUSTER_STATUS[2], online: 0 }]);
    fake.on('GET', '/cluster/tasks', () => [{ upid: 'u1', node: 'pve1', type: 'vzdump', id: '100', user: 'root@pam', starttime: NOW() - 100, endtime: NOW() - 90, status: 'job errors' }]);
    fake.on('GET', '/cluster/ha/status/current', () => [
      { id: 'quorum', type: 'quorum', node: 'pve1', status: 'No quorum', quorate: false },
      { id: 'lrm:pve1', type: 'lrm', node: 'pve1', status: 'old timestamp - dead?' },
      { id: 'service:vm:100', type: 'service', sid: 'vm:100', node: 'pve1', crm_state: 'error', request_state: 'started', state: 'error', status: 'vm:100 (pve1, error)' },
      { id: 'service:ct:101', type: 'service', sid: 'ct:101', node: 'pve1', crm_state: 'freeze', request_state: 'started', state: 'freeze', status: 'ct:101 (pve1, freeze)' },
    ]);
    fake.on('GET', '/cluster/ceph/status', () => ({ health: { status: 'HEALTH_WARN', checks: { OSD_DOWN: {} } } }));
    fake.on('GET', '/nodes/{node}/status', () => ({ rootfs: { total: 100, used: 90 } }));
    fake.on('GET', '/nodes/{node}/storage', () => [
      { storage: 'full', type: 'dir', content: 'images', active: 1, enabled: 1, total: 100, used: 97, used_fraction: 0.97 },
      { storage: 'fairly', type: 'dir', content: 'images', active: 1, enabled: 1, total: 100, used: 88 },
      { storage: 'gone', type: 'nfs', content: 'images', active: 0, enabled: 1 },
      { storage: 'off', type: 'nfs', content: 'images', active: 0, enabled: 0 },
    ]);
    fake.on('GET', '/nodes/{node}/services', () => [
      { name: 'pveproxy', service: 'pveproxy', desc: 'x', state: 'failed', 'active-state': 'failed', 'unit-state': 'enabled' },
      { name: 'postfix', service: 'postfix', desc: 'x', state: 'dead', 'active-state': 'failed', 'unit-state': 'enabled' },
      { name: 'corosync', service: 'corosync', desc: 'x', state: 'dead', 'active-state': 'inactive', 'unit-state': 'enabled' },
    ]);
    fake.on('GET', '/nodes/{node}/replication', () => [{ id: '100-0', guest: 100, target: 'pve2', fail_count: 3, error: 'no route', last_sync: 1000 }]);
    fake.on('GET', '/nodes/{node}/subscription', () => ({ status: 'expired', level: 'c', message: 'expired', key: 'secret-key' }));

    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expectWellFormed(data.findings);
    expect(data.overall).toBe('critical');
    const has = (severity: string, check: string, object: string) => data.findings.some((f: any) => f.severity === severity && f.check === check && f.object === object);
    expect(has('critical', 'nodes', 'node pve2')).toBe(true);
    expect(has('critical', 'quorum', 'cluster lab')).toBe(true);
    expect(has('critical', 'storage', 'storage full')).toBe(true);
    expect(has('warning', 'storage', 'storage fairly')).toBe(true);
    expect(has('critical', 'storage', 'storage gone')).toBe(true);
    expect(data.findings.some((f: any) => f.object === 'storage off')).toBe(false);
    expect(has('critical', 'services', 'service pveproxy on pve1')).toBe(true);
    expect(has('warning', 'services', 'service postfix on pve1')).toBe(true);
    // Enabled and inactive is how corosync looks on a node with no cluster. It has not failed.
    expect(data.findings.some((f: any) => /corosync/.test(f.object))).toBe(false);
    expect(has('warning', 'tasks', 'tasks')).toBe(true);
    expect(has('critical', 'ha', 'ha resource vm:100')).toBe(true);
    expect(has('warning', 'ha', 'ha resource ct:101')).toBe(true);
    expect(has('warning', 'ha', 'ha daemon lrm:pve1')).toBe(true);
    expect(has('critical', 'ha', 'ha quorum')).toBe(true);
    expect(has('warning', 'ceph', 'ceph')).toBe(true);
    expect(has('warning', 'replication', 'replication job 100-0')).toBe(true);
    expect(has('warning', 'subscription', 'node pve1')).toBe(true);
    expect(has('warning', 'node_status', 'node pve1 root disk')).toBe(true);
    // Most severe first.
    expect(data.findings[0].severity).toBe('critical');
    expect(data.counts.critical).toBeGreaterThan(0);
    // The offline node's own checks were not done, and that is not good news.
    for (const section of ['storage', 'services', 'replication', 'subscription', 'node_status']) {
      expect(data.unavailable[`${section}/pve2`]).toMatch(/offline/);
    }
    expect(data.complete).toBe(false);
    expect(JSON.stringify(data)).not.toContain('secret-key');
  });

  it('merges a shared storage into one finding', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage', () => [{ storage: 'nas', type: 'nfs', content: 'images', shared: 1, active: 1, enabled: 1, total: 100, used: 96, used_fraction: 0.96 }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    const hits = data.findings.filter((f: any) => f.object === 'storage nas');
    expect(hits).toHaveLength(1);
    expect(hits[0].evidence.nodes).toEqual(['pve1', 'pve2']);
    expect(hits[0].evidence.threshold_percent).toBe(95);
  });

  it('uses the thresholds it is given, and reports them', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check', { storage_warn_percent: 40, storage_critical_percent: 60, memory_warn_percent: 45 });
    const nas = data.findings.find((f: any) => f.object === 'storage nas');
    expect(nas.severity).toBe('warning');
    expect(nas.evidence.threshold_percent).toBe(40);
    expect(data.findings.find((f: any) => f.object === 'node pve1').evidence.threshold_percent).toBe(45);
    expect(data.thresholds.storage_warn_percent).toBe(40);
  });

  it('a section it cannot read makes the answer incomplete, never healthy', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/replication', FORBIDDEN);
    fake.on('GET', '/cluster/ha/status/current', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_health_check');
    expect(isError).toBe(false);
    expect(data.overall).toBe('incomplete');
    expect(data.complete).toBe(false);
    expect(data.findings).toEqual([]);
    expect(data.unavailable.ha).toMatch(/forbidden/);
    expect(data.unavailable['replication/pve1']).toMatch(/forbidden/);
    expect(data.unavailable['replication/pve2']).toMatch(/forbidden/);
    expect(data.checked).not.toContain('ha');
    expect(data.checked).not.toContain('replication');
    expect(data.checked).toContain('storage');
  });

  it('with no access at all, it reports only what it could not read', async () => {
    const { call, fake } = await connect();
    for (const path of ['/nodes', '/cluster/status', '/cluster/tasks', '/cluster/ha/status/current', '/cluster/ceph/status']) fake.on('GET', path, FORBIDDEN);
    const { data, isError } = await call('pve_health_check');
    expect(isError).toBe(false);
    expect(data.overall).toBe('incomplete');
    expect(data.findings).toEqual([]);
    expect(data.checked).toEqual([]);
    expect(Object.keys(data.unavailable)).toEqual(expect.arrayContaining(['nodes', 'quorum', 'tasks', 'ha', 'ceph', 'storage', 'services', 'replication', 'subscription']));
  });

  it('where Ceph was never set up, it is not applicable rather than unavailable', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/ceph/status', () => pveError(500, "pveceph configuration not initialized - missing '/etc/pve/ceph.conf'"));
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.overall).toBe('no_findings');
    expect(data.complete).toBe(true);
    expect(data.not_applicable.ceph).toMatch(/not initialized/);
    expect(data.checked).not.toContain('ceph');
  });

  it('where Ceph cannot be read, it is unavailable', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/ceph/status', () => pveError(500, 'got timeout'));
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.overall).toBe('incomplete');
    expect(data.unavailable.ceph).toMatch(/got timeout/);
  });

  it('an answer from Ceph without a health status does not count as healthy', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/ceph/status', () => ({}));
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.unavailable.ceph).toMatch(/no health status/);
    expect(data.checked).not.toContain('ceph');
    expect(data.overall).toBe('incomplete');
  });

  it('a standalone node has no quorum to lose', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/status', () => [{ type: 'node', name: 'pve1', ip: '10.0.0.1', online: 1, local: 1, nodeid: 0 }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.findings.filter((f: any) => f.check === 'quorum')).toEqual([]);
  });

  it('falls back on the cluster status for the node list', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes', FORBIDDEN);
    fake.on('GET', '/cluster/status', () => [CLUSTER_STATUS[0], CLUSTER_STATUS[1], { ...CLUSTER_STATUS[2], online: 0 }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.unavailable.nodes).toMatch(/forbidden/);
    expect(data.checked).toContain('services');
    expect(data.unavailable['services/pve2']).toMatch(/offline/);
    expect(data.findings.some((f: any) => f.object === 'node pve2' && f.severity === 'critical')).toBe(true);
  });

  it('a subscription that is merely absent is only for information', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/subscription', () => ({ status: 'notfound', message: 'There is no subscription key' }));
    const { call } = await connect({ fake });
    const { data } = await call('pve_health_check');
    expect(data.overall).toBe('no_findings');
    expect(data.findings.every((f: any) => f.severity === 'info')).toBe(true);
    expect(data.findings).toHaveLength(2);
  });
});

describe('pve_security_audit', () => {
  it('finds nothing on a tidy cluster and makes no claim of compliance', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_security_audit');
    expect(isError).toBe(false);
    expect(data.findings).toEqual([]);
    expect(data.complete).toBe(true);
    expect(data.checked).toEqual(expect.arrayContaining(['cluster_firewall', 'tokens', 'root_tfa', 'acl', 'not_backed_up', 'backup_jobs', 'node_firewall', 'updates', 'certificates', 'guest_config', 'guest_firewall']));
    expect(data.disclaimer).toMatch(/not a certification/);
    expect(data.limits.length).toBeGreaterThan(0);
    for (const key of ['compliant', 'compliance', 'score', 'secure', 'passed', 'certified']) expect(data[key]).toBeUndefined();
  });

  it('reports each kind of finding with its evidence', async () => {
    const fake = await healthyCluster();
    fake.guests.get(101)!.config = { net0: 'name=eth0,bridge=vmbr0', hostname: 'db' };
    fake.guests.get(102)!.config = { net0: 'virtio=AA,bridge=vmbr0' };
    fake.on('GET', '/cluster/firewall/options', () => ({}));
    fake.on('GET', '/nodes/{node}/firewall/options', (_req, p) => (p.node === 'pve2' ? { enable: 0 } : {}));
    fake.on('GET', '/nodes/{node}/qemu/{vmid}/firewall/options', (_req, p) => (p.vmid === '102' ? { enable: 1 } : { enable: 0 }));
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/firewall/options', () => ({}));
    fake.on('GET', '/access/users', () => [
      { userid: 'root@pam', enable: 1, tokens: [{ tokenid: 'god', privsep: 0, expire: 0 }] },
      { userid: 'ops@pve', enable: 1, expire: NOW() + 1000, tokens: [{ tokenid: 'inherits', privsep: 1 }, { tokenid: 'never', privsep: 1, expire: 0 }, { tokenid: 'shared', privsep: 0, expire: NOW() + 100 }] },
    ]);
    fake.on('GET', '/access/tfa/{userid}', () => [{ id: 'r', type: 'recovery', created: 1, description: 'keys' }, { id: 'off', type: 'totp', created: 1, description: 'off', enable: 0 }]);
    fake.on('GET', '/access/acl', () => [
      { path: '/', roleid: 'Administrator', type: 'token', ugid: 'root@pam!god', propagate: 1 },
      { path: '/', roleid: 'PVEVMAdmin', type: 'group', ugid: 'ops' },
      { path: '/', roleid: 'PVEAuditor', type: 'user', ugid: 'audit@pve' },
      { path: '/vms/100', roleid: 'Administrator', type: 'user', ugid: 'owner@pve' },
    ]);
    fake.on('GET', '/cluster/backup-info/not-backed-up', () => [{ vmid: 102, name: 'old-web', type: 'qemu' }]);
    fake.on('GET', '/cluster/backup', () => [{ id: 'backup-1', enabled: 0, schedule: 'daily' }]);
    fake.on('GET', '/nodes/{node}/apt/update', () => [{ Package: 'pve-manager', OldVersion: '9.0', Version: '9.1', Origin: 'Proxmox', Arch: 'all', Description: 'x', Priority: 'o', Section: 'a', Title: 't' }]);
    fake.on('GET', '/nodes/{node}/certificates/info', () => [
      { filename: 'gone.pem', notafter: NOW() - 86400, subject: 'CN=a', pem: '-----BEGIN CERTIFICATE-----' },
      { filename: 'soon.pem', notafter: NOW() + 5 * 86400, subject: 'CN=b' },
      { filename: 'fine.pem', notafter: NOW() + 500 * 86400, subject: 'CN=c' },
    ]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_security_audit');
    expectWellFormed(data.findings);
    const pick = (check: string, object?: string) => data.findings.filter((f: any) => f.check === check && (object === undefined || f.object === object));
    expect(pick('cluster_firewall')[0]).toMatchObject({ severity: 'medium', object: 'datacenter firewall' });
    expect(pick('node_firewall').map((f: any) => f.object)).toEqual(['node pve2']);

    const noExpiry = data.findings.find((f: any) => f.evidence.without_expiry);
    expect(noExpiry.evidence.without_expiry).toEqual(['root@pam!god', 'ops@pve!never']);
    const noPrivsep = data.findings.find((f: any) => f.evidence.without_privilege_separation);
    expect(noPrivsep.severity).toBe('high');
    expect(noPrivsep.evidence.without_privilege_separation).toEqual(['root@pam!god', 'ops@pve!shared']);

    expect(pick('root_tfa')[0]).toMatchObject({ severity: 'high', object: 'root@pam' });
    expect(pick('acl').map((f: any) => [f.severity, f.object])).toEqual(expect.arrayContaining([['high', 'token root@pam!god'], ['medium', 'group ops']]));
    expect(pick('acl')).toHaveLength(2);
    expect(pick('not_backed_up')[0].evidence.guests[0].vmid).toBe(102);
    expect(pick('backup_jobs')[0].evidence.enabled).toBe(0);
    expect(pick('updates')[0].evidence).toMatchObject({ pending: 1, from_proxmox: 1 });
    const certs = pick('certificates');
    expect(certs.find((f: any) => /gone/.test(f.object)).severity).toBe('high');
    expect(certs.find((f: any) => /soon/.test(f.object)).severity).toBe('medium');
    expect(certs.some((f: any) => /fine/.test(f.object))).toBe(false);
    expect(JSON.stringify(data)).not.toContain('BEGIN CERTIFICATE');

    const privileged = pick('guest_config', 'privileged containers')[0];
    expect(privileged.evidence.guests.map((g: any) => g.vmid)).toEqual([101]);
    const off = pick('guest_firewall', 'guests with the firewall off')[0];
    expect(off.evidence.guests.map((g: any) => g.vmid).sort()).toEqual([100, 101]);
    const noNic = pick('guest_firewall', 'guests with the firewall on but on no interface')[0];
    expect(noNic.evidence.guests.map((g: any) => g.vmid)).toEqual([102]);
    expect(data.findings[0].severity).toBe('high');
  });

  it('never counts an unreadable section as compliant', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/access/tfa/{userid}', FORBIDDEN);
    fake.on('GET', '/access/users', FORBIDDEN);
    fake.on('GET', '/cluster/firewall/options', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_security_audit');
    expect(isError).toBe(false);
    expect(data.complete).toBe(false);
    for (const section of ['root_tfa', 'tokens', 'cluster_firewall']) {
      expect(data.unavailable[section]).toMatch(/forbidden/);
      expect(data.checked).not.toContain(section);
      expect(data.findings.filter((f: any) => f.check === section)).toEqual([]);
    }
    expect(data.checked).toContain('acl');
  });

  it('on the unmodelled endpoints, reports them as unavailable with the reason', async () => {
    const { call } = await connect();
    const { data, isError } = await call('pve_security_audit');
    expect(isError).toBe(false);
    expect(data.complete).toBe(false);
    expect(data.unavailable.cluster_firewall).toMatch(/not_supported/);
    expect(data.unavailable['node_firewall/pve1']).toMatch(/not_supported/);
  });

  it('does not read guests when told not to, and says so', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_security_audit', { include_guests: false });
    expect(fake.find('GET', '/nodes/{node}/lxc/{vmid}/config')).toEqual([]);
    expect(fake.find('GET', '/nodes/{node}/lxc/{vmid}/firewall/options')).toEqual([]);
    expect(data.limits.join(' ')).toMatch(/include_guests/);
    expect(data.checked).not.toContain('guest_config');
  });

  it('says it did not check guests on an offline node', async () => {
    const fake = await healthyCluster();
    fake.setNodeOnline('pve2', false);
    fake.on('GET', '/nodes', () => [NODES[0], { node: 'pve2', status: 'offline' }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_security_audit');
    expect(data.unavailable['guest_config/102']).toMatch(/offline/);
    expect(data.unavailable['certificates/pve2']).toMatch(/offline/);
    expect(data.complete).toBe(false);
  });

  it('keeps the list of reasons short when a whole section fails', async () => {
    const guests = Array.from({ length: 30 }, (_, i) => ({ vmid: 200 + i, type: 'lxc' as const, name: `ct${i}` }));
    const fake = new FakePve({ guests });
    await fake.start();
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/config', FORBIDDEN);
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/firewall/options', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data } = await call('pve_security_audit');
    const keys = Object.keys(data.unavailable).filter((k) => k.startsWith('guest_config/'));
    expect(keys).toHaveLength(11);
    expect(data.unavailable['guest_config/...']).toMatch(/20 more/);
  });
});

describe('pve_backup_coverage', () => {
  it('gives the state of each guest, reading a shared storage only once', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage/{storage}/content', (_req, p) => {
      if (p.storage !== 'nas') return [];
      return [
        { volid: 'nas:backup/a', content: 'backup', format: 'tar.zst', vmid: 100, ctime: NOW() - 2 * 86400, verification: { state: 'ok', upid: 'x' } },
        { volid: 'nas:backup/b', content: 'backup', format: 'tar.zst', vmid: 100, ctime: NOW() - 86400 },
        { volid: 'nas:backup/c', content: 'backup', format: 'tar.zst', vmid: 101, ctime: NOW() - 30 * 86400 },
      ];
    });
    fake.on('GET', '/cluster/backup-info/not-backed-up', () => [{ vmid: 102, name: 'old-web', type: 'qemu' }]);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_backup_coverage');
    expect(isError).toBe(false);
    expect(fake.find('GET', '/nodes/{node}/storage/{storage}/content').filter((r) => r.pathParams.storage === 'nas')).toHaveLength(1);
    expect(data.storages_read).toEqual(expect.arrayContaining(['nas@pve1', 'local@pve1', 'local@pve2']));
    const row = (vmid: number) => data.rows.find((r: any) => r.vmid === vmid);
    expect(row(100)).toMatchObject({ in_backup_job: true, volid: 'nas:backup/b', backups_found: 2, storage: 'nas', age_days: 1 });
    expect(row(101)).toMatchObject({ in_backup_job: true, age_days: 30 });
    expect(row(102)).toMatchObject({ in_backup_job: false, last_backup: null, age_days: null });
    expect(row(9000).template).toBe(true);
    expectWellFormed(data.findings);
    const objects = data.findings.map((f: any) => f.object);
    expect(objects).toEqual(expect.arrayContaining(['guests in no backup job', 'guests without any backup found', 'guests whose last backup is old']));
    // A template is listed, not judged.
    const none = data.findings.find((f: any) => f.object === 'guests without any backup found');
    expect(none.evidence.guests.map((g: any) => g.vmid)).toEqual([102]);
    const old = data.findings.find((f: any) => f.object === 'guests whose last backup is old');
    expect(old.evidence.guests.map((g: any) => g.vmid)).toEqual([101]);
    expect(data.jobs[0]).toMatchObject({ id: 'backup-1', enabled: true, storage: 'nas', all: true });
    expect(data.complete).toBe(true);
  });

  it('does not put an age on a backup that has no date', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage/{storage}/content', (_req, p) => (p.storage === 'nas' ? [{ volid: 'nas:backup/a', content: 'backup', format: 'tar.zst', vmid: 100 }] : []));
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage');
    expect(data.rows.find((r: any) => r.vmid === 100)).toMatchObject({ last_backup: null, age_days: null, backups_found: 1 });
    expect(data.findings.find((f: any) => f.object === 'guests whose last backup is old')).toBeUndefined();
    expect(data.findings.find((f: any) => f.object === 'guests without any backup found').evidence.guests.map((g: any) => g.vmid)).toEqual([101, 102]);
  });

  it('uses the age limit it is given', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage', { max_age_days: 0.1 });
    expect(data.thresholds.max_age_days).toBe(0.1);
    const old = data.findings.find((f: any) => f.object === 'guests whose last backup is old');
    expect(old.evidence.guests.map((g: any) => g.vmid)).toEqual([100, 101, 102]);
  });

  it('does not call a guest unprotected when a storage could not be read', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage/{storage}/content', (_req, p) => (p.storage === 'nas' ? FORBIDDEN() : []));
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_backup_coverage');
    expect(isError).toBe(false);
    expect(data.complete).toBe(false);
    expect(data.unavailable['backups/nas@pve1']).toMatch(/forbidden/);
    expect(data.findings.some((f: any) => f.object === 'guests without any backup found')).toBe(false);
    expect(data.not_determined.map((g: any) => g.vmid)).toEqual([100, 101, 102]);
    expect(data.not_determined[0].reason).toMatch(/could not be read/);
  });

  it('nor an inactive storage, nor an offline node', async () => {
    const fake = await healthyCluster();
    fake.setNodeOnline('pve2', false);
    fake.on('GET', '/nodes', () => [NODES[0], { node: 'pve2', status: 'offline' }]);
    fake.on('GET', '/nodes/{node}/storage', () => [{ storage: 'nas', type: 'nfs', content: 'backup', shared: 1, active: 0, enabled: 1 }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage');
    expect(data.unavailable['backups/pve2']).toMatch(/offline/);
    expect(data.unavailable['backups/nas@pve1']).toMatch(/not active/);
    expect(data.not_determined.length).toBeGreaterThan(0);
  });

  it('says it does not know about jobs when that list is refused', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/backup-info/not-backed-up', FORBIDDEN);
    fake.on('GET', '/cluster/backup', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage');
    expect(data.rows[0].in_backup_job).toBeNull();
    expect(data.jobs).toBeNull();
    expect(data.unavailable.not_backed_up).toMatch(/forbidden/);
    expect(data.unavailable.jobs).toMatch(/forbidden/);
    expect(data.findings.some((f: any) => f.object === 'guests in no backup job' || f.object === 'backup jobs')).toBe(false);
  });

  it('flags a cluster with no enabled job', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/backup', () => []);
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage');
    expect(data.findings.find((f: any) => f.object === 'backup jobs').evidence).toEqual({ jobs: 0, enabled: 0 });
  });

  it('pages its rows', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_backup_coverage', { page_limit: 1, page_offset: 1 });
    expect(data).toMatchObject({ total: 4, count: 1, offset: 1, next_offset: 2 });
    expect(data.rows[0].vmid).toBe(101);
  });
});

describe('pve_capacity_report', () => {
  it('gives usage, allocation and overcommit per node, without counting templates', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_capacity_report', { forecast: false });
    expect(isError).toBe(false);
    const pve1 = data.nodes.find((n: any) => n.node === 'pve1');
    expect(pve1).toMatchObject({ cores: 8, cpu_percent: 25, memory_percent: 50, root_disk_percent: 10, guests: 2, guests_running: 2, vcpus_allocated: 12, vcpus_running: 12, memory_allocated_bytes: 24 * GIB, cpu_overcommit_ratio: 1.5, memory_overcommit_ratio: 1.5 });
    const pve2 = data.nodes.find((n: any) => n.node === 'pve2');
    // 102 is stopped, and the template is left out.
    expect(pve2).toMatchObject({ guests: 1, guests_running: 0, vcpus_allocated: 16, vcpus_running: 0, cpu_overcommit_ratio: 4, cpu_overcommit_ratio_running: 0, memory_overcommit_ratio: 4 });
    expect(data.templates_excluded).toBe(1);
    expect(fake.find('GET', '/nodes/{node}/storage/{storage}/rrddata')).toEqual([]);
  });

  it('lists the biggest guests', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake });
    const { data } = await call('pve_capacity_report', { forecast: false, top: 2 });
    expect(data.biggest_guests.by_memory.map((g: any) => g.vmid)).toEqual([102, 100]);
    expect(data.biggest_guests.by_disk.map((g: any) => g.vmid)).toEqual([102, 100]);
    expect(data.biggest_guests.by_vcpus.map((g: any) => g.vmid)).toEqual([102, 100]);
    expect(data.biggest_guests.by_memory[0].maxmem).toBe(32 * GIB);
  });

  it('forecasts a growing storage from its history, and names the method', async () => {
    const fake = await healthyCluster();
    const t0 = NOW() - 10 * 86400;
    fake.on('GET', '/nodes/{node}/storage/{storage}/rrddata', (req, p) => {
      expect(req.query.timeframe).toBe('week');
      if (p.storage === 'nas') return Array.from({ length: 11 }, (_, i) => ({ time: t0 + i * 86400, used: (400 + i * 10) * GIB, total: 1000 * GIB }));
      return Array.from({ length: 11 }, (_, i) => ({ time: t0 + i * 86400, used: (50 - i) * GIB, total: 100 * GIB }));
    });
    const { call } = await connect({ fake });
    const { data } = await call('pve_capacity_report', { forecast_window: 'week' });
    const nas = data.storage.find((s: any) => s.storage === 'nas');
    expect(nas).toMatchObject({ shared: true, nodes: ['pve1', 'pve2'], used_percent: 50 });
    expect(nas.forecast).toMatchObject({ available: true, trend: 'growing', points: 11, days_until_full: 50, growth_bytes_per_day: 10 * GIB });
    expect(nas.forecast.method).toMatch(/least squares.*week/);
    expect(nas.forecast.assumption).toMatch(/not a prediction/);
    const local = data.storage.find((s: any) => s.storage === 'local');
    expect(local.forecast).toMatchObject({ available: true, trend: 'not_growing', days_until_full: null });
    expect(data.complete).toBe(true);
    // The shared one is read once.
    expect(fake.find('GET', '/nodes/{node}/storage/{storage}/rrddata').filter((r) => r.pathParams.storage === 'nas')).toHaveLength(1);
  });

  it('reads a shared storage through a node that can see it', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/resources', () => [
      { id: 'storage/pve1/nas', type: 'storage', storage: 'nas', node: 'pve1', status: 'unknown', shared: 1, plugintype: 'nfs' },
      { id: 'storage/pve2/nas', type: 'storage', storage: 'nas', node: 'pve2', status: 'available', disk: 5, maxdisk: 10, shared: 1, plugintype: 'nfs' },
      { id: 'storage/pve1/gone', type: 'storage', storage: 'gone', node: 'pve1', status: 'unknown', shared: 0, plugintype: 'nfs' },
    ]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_capacity_report');
    expect(fake.find('GET', '/nodes/{node}/storage/{storage}/rrddata').map((r) => r.path)).toEqual(['/nodes/pve2/storage/nas/rrddata']);
    expect(data.storage.find((s: any) => s.storage === 'nas')).toMatchObject({ status: 'available', used_percent: 50, nodes: ['pve1', 'pve2'] });
    expect(data.storage.find((s: any) => s.storage === 'gone').forecast.available).toBe(false);
  });

  it('does not make up a forecast from too little data', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage/{storage}/rrddata', () => [{ time: 1 }, { time: 2, used: 5, total: 10 }]);
    const { call } = await connect({ fake });
    const { data } = await call('pve_capacity_report');
    expect(data.storage[0].forecast.available).toBe(false);
    expect(data.storage[0].forecast.reason).toMatch(/1 data points/);
  });

  it('reports a history it could not read', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/nodes/{node}/storage/{storage}/rrddata', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_capacity_report');
    expect(isError).toBe(false);
    expect(data.complete).toBe(false);
    expect(data.storage[0].forecast.available).toBe(false);
    expect(data.storage[0].forecast.reason).toMatch(/forbidden/);
    expect(data.unavailable['forecast/local@pve1']).toMatch(/forbidden/);
    expect(data.nodes).toHaveLength(2);
  });

  it('says it cannot report when the resources are refused', async () => {
    const fake = await healthyCluster();
    fake.on('GET', '/cluster/resources', FORBIDDEN);
    const { call } = await connect({ fake });
    const { data, isError } = await call('pve_capacity_report');
    expect(isError).toBe(false);
    expect(data).toMatchObject({ complete: false, nodes: null, storage: null, biggest_guests: null });
    expect(data.unavailable.resources).toMatch(/forbidden/);
  });

  it('runs on every gate setting without touching anything', async () => {
    const fake = await healthyCluster();
    const { call } = await connect({ fake, env: ALL_GATES });
    await call('pve_capacity_report');
    await call('pve_health_check');
    await call('pve_security_audit');
    await call('pve_backup_coverage');
    await call('pve_overview');
    await call('pve_find_guest');
    expect(fake.writes()).toEqual([]);
  });
});
