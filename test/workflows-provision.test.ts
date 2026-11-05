import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FakePve, pveError, type RecordedRequest } from './fake-pve.js';
import { closeAll, connect, WRITES } from './harness.js';

afterEach(closeAll);

const SECRET = 'hunter2-do-not-echo';
const PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host';
const LOCAL_TEMPLATE = 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst';
const INDEX = [
  { template: 'debian-12-standard_12.7-1_amd64.tar.zst', section: 'system', package: 'debian-12-standard', os: 'debian-12', version: '12.7-1', type: 'lxc', headline: 'Debian 12' },
  { template: 'debian-13-standard_13.1-1_amd64.tar.zst', section: 'system', package: 'debian-13-standard', os: 'debian-13', version: '13.1-1', type: 'lxc', headline: 'Debian 13' },
  { template: 'alpine-3.22-default_20250617_amd64.tar.xz', section: 'system', package: 'alpine-3.22-default', os: 'alpine-3.22', version: '3.22', type: 'lxc', headline: 'Alpine' },
];

/** A fake where a template is on the storage and the appliance index can be read. */
async function lxcFake(options: { localTemplate?: boolean } = {}): Promise<FakePve> {
  const fake = new FakePve({ guests: [{ vmid: 100, type: 'qemu', name: 'web' }] });
  fake.volumes.set('local', options.localTemplate === false ? [] : [{ volid: LOCAL_TEMPLATE, content: 'vztmpl', format: 'tzst', size: 1000 }]);
  fake.on('GET', '/nodes/{node}/aplinfo', () => INDEX);
  fake.on('POST', '/nodes/{node}/aplinfo', (req, p) => {
    fake.volumes.get(String(req.body.storage))?.push({ volid: `${String(req.body.storage)}:vztmpl/${String(req.body.template)}`, content: 'vztmpl' });
    return fake.startTask(p.node!, 'download', String(req.body.template));
  });
  await fake.start();
  return fake;
}

const TEMPLATE_CONFIG = {
  boot: 'order=scsi0;ide2;net0',
  scsi0: 'local-lvm:base-9000-disk-0,size=2G',
  ide2: 'local-lvm:vm-9000-cloudinit,media=cdrom',
  agent: '1,fstrim_cloned_disks=1',
  net0: 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0',
  name: 'tpl',
};

async function vmFake(config: Record<string, unknown> = TEMPLATE_CONFIG): Promise<FakePve> {
  const fake = new FakePve({ guests: [{ vmid: 9000, type: 'qemu', name: 'tpl', status: 'stopped', template: true, config: { ...config } }, { vmid: 100, type: 'qemu', name: 'web' }, { vmid: 101, type: 'lxc', name: 'db' }] });
  fake.on('PUT', '/nodes/{node}/qemu/{vmid}/resize', (_req, p) => fake.startTask(p.node!, 'qmresize', p.vmid!));
  await fake.start();
  return fake;
}

const paths = (requests: RecordedRequest[]) => requests.map((r) => `${r.method} ${r.path}`);

describe('pve_provision_lxc', () => {
  it('goes through every step, from a template on a storage to an IP address', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_lxc', {
      hostname: 'app1',
      template: LOCAL_TEMPLATE,
      storage: 'local-lvm',
      disk_gb: 8,
      cores: 2,
      memory: 512,
      ssh_public_keys: PUBLIC_KEY,
      password: SECRET,
    });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'complete', vmid: 101, node: 'pve1', hostname: 'app1', ostemplate: LOCAL_TEMPLATE, running: true, ip: '10.0.0.5', ips: ['10.0.0.5'], remaining: [] });
    expect(data.created).toEqual([{ type: 'lxc', vmid: 101, node: 'pve1' }]);
    const steps = Object.fromEntries(data.steps.map((s: any) => [s.step, s.status]));
    expect(steps).toMatchObject({ pick_vmid: 'done', find_template: 'done', create: 'done', start: 'done', find_ip: 'done' });

    const [create] = fake.find('POST', '/nodes/{node}/lxc');
    expect(create!.body).toEqual({
      vmid: '101',
      ostemplate: LOCAL_TEMPLATE,
      hostname: 'app1',
      unprivileged: '1',
      net0: 'name=eth0,bridge=vmbr0,ip=dhcp',
      rootfs: 'local-lvm:8',
      'ssh-public-keys': PUBLIC_KEY,
      password: SECRET,
      cores: '2',
      memory: '512',
    });
    expect(fake.guests.get(101)!.status).toBe('running');
    expect(text).not.toContain(SECRET);
    expect(fake.writes().map((r) => r.method)).toEqual(['POST', 'POST']);
  });

  it('finds a template from the start of its name', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: 'debian-12' });
    expect(data.ostemplate).toBe(LOCAL_TEMPLATE);
    expect(fake.find('GET', '/nodes/{node}/aplinfo')).toEqual([]);
    expect(fake.find('POST', '/nodes/{node}/aplinfo')).toEqual([]);
  });

  it('downloads a template that is only in the appliance index', async () => {
    const fake = await lxcFake({ localTemplate: false });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: 'alpine-3.22' });
    expect(isError).toBe(false);
    expect(fake.find('POST', '/nodes/{node}/aplinfo')[0]!.body).toEqual({ storage: 'local', template: INDEX[2]!.template });
    expect(data.ostemplate).toBe(`local:vztmpl/${INDEX[2]!.template}`);
    expect(fake.find('POST', '/nodes/{node}/lxc')[0]!.body.ostemplate).toBe(data.ostemplate);
    expect(data.created).toEqual([
      { type: 'template', volid: data.ostemplate, node: 'pve1' },
      { type: 'lxc', vmid: 101, node: 'pve1' },
    ]);
  });

  it('does not download when told not to', async () => {
    const fake = await lxcFake({ localTemplate: false });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: 'alpine-3.22', download_template: false });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('invalid_input');
    expect(fake.writes()).toEqual([]);
  });

  it.each([
    ['debian', /several templates/],
    ['windows', /No template/],
  ])('refuses template "%s" before creating anything', async (template, message) => {
    const fake = await lxcFake({ localTemplate: false });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('invalid_input');
    expect(data.error).toMatch(message);
    expect(data.details.created).toEqual([]);
    expect(data.details.cleanup).toMatch(/Nothing was created/);
    expect(fake.writes()).toEqual([]);
  });

  it('refuses a volume that is not on its storage', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: 'local:vztmpl/nope.tar.zst' });
    expect(isError).toBe(true);
    expect(data.error).toMatch(/is not on storage local/);
    expect(fake.writes()).toEqual([]);
  });

  it('does not need the list of storages for a volume that names its own', async () => {
    const fake = await lxcFake();
    fake.on('GET', '/nodes/{node}/storage', () => pveError(403, 'Permission check failed'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE });
    expect(isError).toBe(false);
    expect(data.status).toBe('complete');
  });

  it('stops, having created nothing, when the storages cannot be listed for a template name', async () => {
    const fake = await lxcFake();
    fake.on('GET', '/nodes/{node}/storage', () => pveError(403, 'Permission check failed'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: 'debian-12' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
    expect(data.details.failed_step).toBe('list_template_storages');
    expect(fake.writes()).toEqual([]);
  });

  it('goes on with a volume it could not verify, and says so', async () => {
    const fake = await lxcFake();
    fake.failNext('GET', '/nodes/{node}/storage/{storage}/content', pveError(403, 'Permission check failed (/storage/local, Datastore.Audit)'));
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, ip_wait_seconds: 0 });
    expect(data.status).toBe('complete_with_warnings');
    expect(data.warnings.join(' ')).toMatch(/could not be verified/);
    expect(fake.find('POST', '/nodes/{node}/lxc')).toHaveLength(1);
  });

  it('asks Proxmox whether a vmid that was given is free, and stops if not', async () => {
    const fake = await lxcFake();
    fake.on('GET', '/cluster/nextid', (req) => (req.query.vmid === '100' ? pveError(400, 'Parameter verification failed.', { vmid: 'VM 100 already exists' }) : '105'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, vmid: 100 });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('validation_failed');
    expect(data.details.steps.at(-1)).toMatchObject({ step: 'check_vmid', status: 'failed', field_errors: { vmid: 'VM 100 already exists' } });
    expect(fake.writes()).toEqual([]);
    const free = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, vmid: 200 });
    expect(free.data.vmid).toBe(200);
  });

  it('a permission refusal on create says that nothing was created', async () => {
    const fake = await lxcFake();
    fake.failNext('POST', '/nodes/{node}/lxc', pveError(403, 'Permission check failed (/vms/101, VM.Allocate)'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, password: SECRET });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
    expect(data.error).toMatch(/at step "create"/);
    expect(data.details).toMatchObject({ failed_step: 'create', created: [] });
    expect(data.details.cleanup).toMatch(/Nothing was created/);
    expect(data.details.uncertain).toBeUndefined();
    expect(data.details.remaining.join(' ')).toMatch(/create:.*start:/);
    expect(fake.find('POST', '/nodes/{node}/lxc/{vmid}/status/start')).toEqual([]);
  });

  it('a failed create task says what is not known, and deletes nothing', async () => {
    const fake = await lxcFake();
    fake.on('POST', '/nodes/{node}/lxc', () => fake.startTask('pve1', 'vzcreate', '101', { exitstatus: 'unable to create CT 101', log: ['disk full'] }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('task_failed');
    expect(data.details.steps.at(-1)).toMatchObject({ step: 'create', status: 'failed', log_tail: ['disk full'] });
    expect(data.details.uncertain).toMatch(/Container 101 on pve1 may exist in part/);
    expect(data.details.cleanup).toMatch(/Nothing was deleted automatically.*pve_delete_lxc with vmid 101/);
    expect(fake.writes().filter((r) => r.method === 'DELETE')).toEqual([]);
  });

  it('a failed start leaves the container, and says what was created and what remains', async () => {
    const fake = await lxcFake();
    fake.on('POST', '/nodes/{node}/lxc/{vmid}/status/start', () => pveError(500, 'startup for container failed'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, password: SECRET });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('upstream_error');
    expect(data.details.created).toEqual([{ type: 'lxc', vmid: 101, node: 'pve1' }]);
    expect(data.details.remaining).toEqual(['start: pve_start_lxc with vmid 101']);
    expect(data.details.cleanup).toMatch(/Nothing was deleted automatically.*pve_delete_lxc with vmid 101/);
    expect(fake.guests.has(101)).toBe(true);
    expect(fake.writes().filter((r) => r.method === 'DELETE')).toEqual([]);
    expect(text).not.toContain(SECRET);
  });

  it('never gives back a password that Proxmox quotes in an error', async () => {
    const fake = await lxcFake();
    fake.failNext('POST', '/nodes/{node}/lxc', pveError(400, `bad value ${SECRET}`, { password: `value '${SECRET}' is too weak` }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, text } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, password: SECRET });
    expect(data.error_type).toBe('validation_failed');
    expect(data.details.steps.at(-1).field_errors.password).toContain('[REDACTED]');
    expect(text).not.toContain(SECRET);
  });

  it('a task that outlasts the wait stops the job, and says how to go on', async () => {
    const fake = await lxcFake();
    let upid = '';
    fake.on('POST', '/nodes/{node}/lxc', (_req, p) => {
      upid = fake.startTask(p.node!, 'vzcreate', '101', { polls: 1000 });
      return upid;
    });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, wait_seconds: 0 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'still_running', task: upid, node: 'pve1', next_step: 'pve_wait_task', created: [] });
    expect(data.steps.at(-1)).toMatchObject({ step: 'create', status: 'still_running', task: upid });
    // Not create: it is running, and must not be started a second time.
    expect(data.remaining).toEqual(['start: pve_start_lxc with vmid 101']);
    expect(data.uncertain).toMatch(/still being created/);
    expect(fake.find('POST', '/nodes/{node}/lxc/{vmid}/status/start')).toEqual([]);
  });

  it('leaves a container stopped on request', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, start: false });
    expect(data).toMatchObject({ status: 'complete', running: false, ip: null });
    expect(fake.find('POST', '/nodes/{node}/lxc/{vmid}/status/start')).toEqual([]);
    expect(data.steps.find((s: any) => s.step === 'start').status).toBe('skipped');
  });

  it('is not a failure when no address shows up in time', async () => {
    const fake = await lxcFake();
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/interfaces', () => [{ name: 'lo', inet: '127.0.0.1/8' }, { name: 'eth0', hwaddr: 'x' }]);
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, ip_wait_seconds: 0 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'complete_with_warnings', running: true, ip: null });
    expect(data.warnings[0]).toMatch(/No IP address/);
  });

  it('does not take a link-local address for the address of the container', async () => {
    const fake = await lxcFake();
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/interfaces', () => [{ name: 'eth0', inet6: 'fe80::1/64' }]);
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, ip_wait_seconds: 0 });
    expect(data).toMatchObject({ status: 'complete_with_warnings', ip: null });
  });

  it('waits for the address to come', async () => {
    const fake = await lxcFake();
    let reads = 0;
    fake.on('GET', '/nodes/{node}/lxc/{vmid}/interfaces', () => (++reads < 2 ? [{ name: 'eth0' }] : [{ name: 'eth0', inet: '10.1.1.1/24', inet6: 'fe80::1/64' }]));
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, ip_wait_seconds: 10 });
    expect(data.ip).toBe('10.1.1.1');
    expect(data.ips).toEqual(['10.1.1.1', 'fe80::1']);
    expect(reads).toBe(2);
  });

  it('dry run: tells what would happen, sends nothing, and hides the password', async () => {
    const fake = await lxcFake({ localTemplate: false });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_lxc', { hostname: 'app1', template: 'alpine-3.22', password: SECRET, ssh_public_keys: PUBLIC_KEY, dry_run: true });
    expect(isError).toBe(false);
    expect(fake.writes()).toEqual([]);
    expect(data).toMatchObject({ status: 'dry_run', dry_run: true, vmid: 101, running: false, ip: null, created: [], remaining: [] });
    const steps = Object.fromEntries(data.steps.map((s: any) => [s.step, s.status]));
    expect(steps).toMatchObject({ pick_vmid: 'done', download_template: 'would_run', create: 'would_run', start: 'would_run', find_ip: 'would_run' });
    expect(paths(data.would_send.map((w: any) => ({ method: w.method, path: w.path })) as RecordedRequest[])).toEqual(['POST /nodes/pve1/aplinfo', 'POST /nodes/pve1/lxc', 'POST /nodes/pve1/lxc/101/status/start']);
    expect(data.would_send[1].params['ssh-public-keys']).toBe(PUBLIC_KEY);
    expect(data.would_send[1].params.password).toBe('[REDACTED]');
    expect(text).not.toContain(SECRET);
    expect(fake.guests.has(101)).toBe(false);
  });

  it('dry run works on a read-only server set to dry run', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: { PROXMOX_DRY_RUN: 'true' } });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE });
    expect(isError).toBe(false);
    expect(data.status).toBe('dry_run');
    expect(fake.writes()).toEqual([]);
  });

  it('is refused by the policy for a protected vmid, before anything is created', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: { ...WRITES, PROXMOX_PROTECTED_VMIDS: '150' } });
    const { data, isError } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, vmid: 150 });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('protected_guest');
    expect(fake.writes()).toEqual([]);
  });

  it('does not exist on a read-only server', async () => {
    const fake = await lxcFake();
    const { toolNames } = await connect({ fake });
    expect(await toolNames()).not.toContain('pve_provision_lxc');
  });

  it('refuses a private key where a public one goes', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data, text } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, ssh_public_keys: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----' });
    expect(data.error_type).toBe('invalid_input');
    expect(text).not.toContain('abc');
    expect(fake.writes()).toEqual([]);
  });

  it('wants a storage for a disk size', async () => {
    const fake = await lxcFake();
    const { call } = await connect({ fake, env: WRITES });
    expect((await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, disk_gb: 8 })).data.error_type).toBe('invalid_input');
    expect(fake.writes()).toEqual([]);
  });

  it('wants a node when there are several and no default', async () => {
    const fake = new FakePve({ nodes: ['pve1', 'pve2'] });
    await fake.start();
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE });
    expect(data.error_type).toBe('invalid_input');
    expect(data.error).toMatch(/several nodes/);
  });

  it('keeps the password out of the audit log', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-audit-'));
    try {
      const log = join(dir, 'audit.log');
      const fake = await lxcFake();
      const { call } = await connect({ fake, env: { ...WRITES, PROXMOX_AUDIT_LOG: log } });
      await call('pve_provision_lxc', { hostname: 'app1', template: LOCAL_TEMPLATE, password: SECRET });
      await expect.poll(() => readFileSync(log, 'utf8')).toContain('pve_provision_lxc');
      expect(readFileSync(log, 'utf8')).not.toContain(SECRET);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('pve_provision_vm_from_template', () => {
  const FULL = {
    template_vmid: 9000,
    name: 'app1',
    ciuser: 'ops',
    cipassword: SECRET,
    sshkeys: PUBLIC_KEY,
    ipconfig0: 'ip=dhcp',
    cores: 4,
    disk_size: '+10G',
  };

  it('clones, configures, resizes, starts and waits for the agent', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_vm_from_template', FULL);
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'complete', vmid: 102, node: 'pve1', name: 'app1', template: 9000, running: true, ip: '10.0.0.6', remaining: [] });
    expect(data.created).toEqual([{ type: 'qemu', vmid: 102, node: 'pve1' }]);
    expect(data.steps.map((s: any) => [s.step, s.status])).toEqual([
      ['find_template', 'done'],
      ['read_template_config', 'done'],
      ['pick_vmid', 'done'],
      ['clone', 'done'],
      ['configure', 'done'],
      ['resize', 'done'],
      ['start', 'done'],
      ['wait_agent', 'done'],
    ]);
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/clone')[0]!.body).toEqual({ newid: '102', name: 'app1' });
    const config = fake.find('PUT', '/nodes/{node}/qemu/{vmid}/config')[0]!;
    expect(config.path).toBe('/nodes/pve1/qemu/102/config');
    expect(config.body.ciuser).toBe('ops');
    expect(config.body.cipassword).toBe(SECRET);
    expect(config.body.ipconfig0).toBe('ip=dhcp');
    // qemu-server wants sshkeys encoded once more than the form does.
    expect(config.body.sshkeys).toBe(encodeURIComponent(PUBLIC_KEY));
    // The first disk of the boot order, and not the cloud-init cdrom.
    expect(fake.find('PUT', '/nodes/{node}/qemu/{vmid}/resize')[0]!.body).toEqual({ disk: 'scsi0', size: '+10G' });
    expect(fake.guests.get(102)!.status).toBe('running');
    expect(text).not.toContain(SECRET);
    // In order, each on the new VM.
    expect(paths(fake.writes())).toEqual([
      'POST /nodes/pve1/qemu/9000/clone',
      'PUT /nodes/pve1/qemu/102/config',
      'PUT /nodes/pve1/qemu/102/resize',
      'POST /nodes/pve1/qemu/102/status/start',
      'POST /nodes/pve1/qemu/102/agent/ping',
    ]);
  });

  it('asks for a full copy when a storage is given, since a linked clone cannot move', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', storage: 'fast', start: false });
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/clone')[0]!.body).toEqual({ newid: '102', name: 'app1', full: '1', storage: 'fast' });
  });

  it('works on the target node from then on', async () => {
    const fake = new FakePve({ nodes: ['pve1', 'pve2'], guests: [{ vmid: 9000, type: 'qemu', name: 'tpl', status: 'stopped', template: true, node: 'pve1', config: { ...TEMPLATE_CONFIG } }] });
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/clone', (req, p) => {
      fake.addGuest({ vmid: Number(req.body.newid), type: 'qemu', node: String(req.body.target), name: String(req.body.name), status: 'stopped' });
      return fake.startTask(p.node!, 'qmclone', p.vmid!);
    });
    await fake.start();
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', target_node: 'pve2', ciuser: 'ops', agent_wait_seconds: 0 });
    expect(data.node).toBe('pve2');
    expect(paths(fake.writes())).toEqual(['POST /nodes/pve1/qemu/9000/clone', 'PUT /nodes/pve2/qemu/100/config', 'POST /nodes/pve2/qemu/100/status/start']);
  });

  it('refuses a VM that is not a template, and a container', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    const vm = await call('pve_provision_vm_from_template', { template_vmid: 100, name: 'app1' });
    expect(vm.data.error_type).toBe('invalid_input');
    expect(vm.data.error).toMatch(/not a template/);
    const ct = await call('pve_provision_vm_from_template', { template_vmid: 101, name: 'app1' });
    expect(ct.data.error).toMatch(/container/);
    expect(vm.data.details.cleanup).toMatch(/Nothing was created/);
    expect(fake.writes()).toEqual([]);
  });

  it('refuses to guess which disk to resize, before cloning anything', async () => {
    const fake = await vmFake({ name: 'tpl', ide2: 'local:iso/x.iso,media=cdrom', boot: 'order=ide2;net0' });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', disk_size: '40G' });
    expect(isError).toBe(true);
    expect(data.error_type).toBe('invalid_input');
    expect(data.error).toMatch(/which disk/);
    expect(fake.writes()).toEqual([]);
  });

  it('takes the disk it is told to, and the old bootdisk key', async () => {
    const told = await vmFake();
    const first = await connect({ fake: told, env: WRITES });
    await first.call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', disk: 'virtio1', disk_size: '40G', start: false });
    expect(told.find('PUT', '/nodes/{node}/qemu/{vmid}/resize')[0]!.body).toEqual({ disk: 'virtio1', size: '40G' });

    const legacy = await vmFake({ name: 'tpl', bootdisk: 'virtio0', virtio0: 'local:9000/base.raw,size=2G' });
    const second = await connect({ fake: legacy, env: WRITES });
    await second.call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', disk_size: '40G', start: false });
    expect(legacy.find('PUT', '/nodes/{node}/qemu/{vmid}/resize')[0]!.body.disk).toBe('virtio0');
  });

  it('a permission refusal on the clone says that nothing was created', async () => {
    const fake = await vmFake();
    fake.failNext('POST', '/nodes/{node}/qemu/{vmid}/clone', pveError(403, 'Permission check failed (/vms/9000, VM.Clone)'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_vm_from_template', FULL);
    expect(isError).toBe(true);
    expect(data.error_type).toBe('forbidden');
    expect(data.details.created).toEqual([]);
    expect(data.details.cleanup).toMatch(/Nothing was created/);
    expect(data.details.remaining[0]).toMatch(/^clone:/);
    expect(fake.writes()).toHaveLength(1);
    expect(text).not.toContain(SECRET);
  });

  it('a failed resize leaves the VM, and says what was created and what remains', async () => {
    const fake = await vmFake();
    fake.on('PUT', '/nodes/{node}/qemu/{vmid}/resize', (_req, p) => fake.startTask(p.node!, 'qmresize', p.vmid!, { exitstatus: 'disk resize failed', log: ['no space left'] }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_vm_from_template', FULL);
    expect(isError).toBe(true);
    expect(data.error_type).toBe('task_failed');
    expect(data.error).toMatch(/at step "resize"/);
    expect(data.details.created).toEqual([{ type: 'qemu', vmid: 102, node: 'pve1' }]);
    expect(data.details.remaining).toEqual(['resize: pve_resize_vm_disk with vmid 102, disk scsi0 and size +10G', 'start: pve_start_vm with vmid 102']);
    expect(data.details.steps.at(-1).log_tail).toEqual(['no space left']);
    expect(data.details.cleanup).toMatch(/Nothing was deleted automatically.*pve_delete_vm with vmid 102/);
    expect(fake.guests.has(102)).toBe(true);
    expect(fake.writes().filter((r) => r.method === 'DELETE')).toEqual([]);
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/start')).toEqual([]);
    expect(text).not.toContain(SECRET);
  });

  it('a failed configure stops before start', async () => {
    const fake = await vmFake();
    fake.failNext('PUT', '/nodes/{node}/qemu/{vmid}/config', pveError(400, 'Parameter verification failed.', { ipconfig0: 'bad' }));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_vm_from_template', FULL);
    expect(isError).toBe(true);
    expect(data.details.failed_step).toBe('configure');
    expect(data.details.created).toHaveLength(1);
    expect(data.details.remaining[0]).toMatch(/^configure:/);
    expect(fake.find('POST', '/nodes/{node}/qemu/{vmid}/status/start')).toEqual([]);
  });

  it('a clone that outlasts the wait stops the job, and says how to go on', async () => {
    const fake = await vmFake();
    let upid = '';
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/clone', (_req, p) => {
      upid = fake.startTask(p.node!, 'qmclone', p.vmid!, { polls: 1000 });
      return upid;
    });
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_vm_from_template', { ...FULL, wait_seconds: 0 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'still_running', task: upid, next_step: 'pve_wait_task' });
    expect(data.remaining.map((r: string) => r.split(':')[0])).toEqual(['configure', 'resize', 'start']);
    expect(fake.find('PUT', '/nodes/{node}/qemu/{vmid}/config')).toEqual([]);
  });

  it('an agent that does not answer is a warning: the VM is there and running', async () => {
    const fake = await vmFake();
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/agent/ping', () => pveError(500, 'QEMU guest agent is not running'));
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', agent_wait_seconds: 1 });
    expect(isError).toBe(false);
    expect(data).toMatchObject({ status: 'complete_with_warnings', running: true, ip: null });
    expect(data.warnings[0]).toMatch(/agent is not running/);
    expect(data.steps.at(-1)).toMatchObject({ step: 'wait_agent', status: 'warning' });
  });

  it('tries the agent again until it answers', async () => {
    const fake = await vmFake();
    let pings = 0;
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/agent/ping', () => (++pings < 2 ? pveError(500, 'QEMU guest agent is not running') : {}));
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', agent_wait_seconds: 10 });
    expect(pings).toBe(2);
    expect(data.ip).toBe('10.0.0.6');
  });

  it('stops trying the agent at a refusal, which time will not cure', async () => {
    const fake = await vmFake();
    let pings = 0;
    fake.on('POST', '/nodes/{node}/qemu/{vmid}/agent/ping', () => {
      pings++;
      return pveError(403, 'Permission check failed (/vms/102, VM.GuestAgent.Audit)');
    });
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', agent_wait_seconds: 60 });
    expect(pings).toBe(1);
    expect(data.status).toBe('complete_with_warnings');
    expect(data.warnings[0]).toMatch(/forbidden/);
  });

  it('does not wait for an agent that is not enabled, and sets it when asked', async () => {
    const off = await vmFake({ ...TEMPLATE_CONFIG, agent: '0' });
    const first = await connect({ fake: off, env: WRITES });
    const skipped = await first.call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1' });
    expect(skipped.data.steps.at(-1)).toMatchObject({ step: 'wait_agent', status: 'skipped' });
    expect(off.find('POST', '/nodes/{node}/qemu/{vmid}/agent/ping')).toEqual([]);

    const on = await vmFake({ ...TEMPLATE_CONFIG, agent: 'enabled=0' });
    const second = await connect({ fake: on, env: WRITES });
    const enabled = await second.call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', enable_agent: true });
    expect(on.find('PUT', '/nodes/{node}/qemu/{vmid}/config')[0]!.body.agent).toBe('1');
    expect(enabled.data.ip).toBe('10.0.0.6');
  });

  it('reads the agent switch wherever it is in the property string', async () => {
    const fake = await vmFake({ ...TEMPLATE_CONFIG, agent: 'fstrim_cloned_disks=1,enabled=1' });
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1' });
    expect(data.ip).toBe('10.0.0.6');
  });

  it('warns about cloud-init values on a template with no cloud-init drive', async () => {
    const { ide2: _ide2, ...config } = TEMPLATE_CONFIG;
    const fake = await vmFake(config);
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', ciuser: 'ops', start: false });
    expect(data.status).toBe('complete_with_warnings');
    expect(data.warnings[0]).toMatch(/no cloud-init drive/);
  });

  it('skips the steps with nothing to do', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data } = await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', start: false });
    expect(data).toMatchObject({ status: 'complete', running: false });
    const steps = Object.fromEntries(data.steps.map((s: any) => [s.step, s.status]));
    expect(steps).toMatchObject({ clone: 'done', configure: 'skipped', resize: 'skipped', start: 'skipped' });
    expect(paths(fake.writes())).toEqual(['POST /nodes/pve1/qemu/9000/clone']);
  });

  it('dry run: tells what would happen, on the vmid it would take, without crashing or sending', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    const { data, isError, text } = await call('pve_provision_vm_from_template', { ...FULL, dry_run: true });
    expect(isError).toBe(false);
    expect(fake.writes()).toEqual([]);
    expect(fake.guests.has(102)).toBe(false);
    expect(data).toMatchObject({ status: 'dry_run', dry_run: true, vmid: 102, running: false, ip: null, created: [], remaining: [] });
    const steps = Object.fromEntries(data.steps.map((s: any) => [s.step, s.status]));
    expect(steps).toMatchObject({ find_template: 'done', clone: 'would_run', configure: 'would_run', resize: 'would_run', start: 'would_run', wait_agent: 'would_run' });
    expect(data.would_send.map((w: any) => `${w.method} ${w.path}`)).toEqual(['POST /nodes/pve1/qemu/9000/clone', 'PUT /nodes/pve1/qemu/102/config', 'PUT /nodes/pve1/qemu/102/resize', 'POST /nodes/pve1/qemu/102/status/start']);
    expect(data.would_send[1].params.cipassword).toBe('[REDACTED]');
    expect(data.would_send[1].params.sshkeys).toBe(PUBLIC_KEY);
    expect(text).not.toContain(SECRET);
  });

  it('is refused by the policy for a protected new vmid, and a protected template', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: { ...WRITES, PROXMOX_PROTECTED_VMIDS: '150,9000' } });
    expect((await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', newid: 150 })).data.error_type).toBe('protected_guest');
    expect((await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1' })).data.error_type).toBe('protected_guest');
    expect(fake.writes()).toEqual([]);
  });

  it('does not exist on a read-only server', async () => {
    const fake = await vmFake();
    const { toolNames } = await connect({ fake });
    expect(await toolNames()).not.toContain('pve_provision_vm_from_template');
  });

  it('refuses a private key where a public one goes', async () => {
    const fake = await vmFake();
    const { call } = await connect({ fake, env: WRITES });
    expect((await call('pve_provision_vm_from_template', { template_vmid: 9000, name: 'app1', sshkeys: '-----BEGIN RSA PRIVATE KEY-----' })).data.error_type).toBe('invalid_input');
    expect(fake.writes()).toEqual([]);
  });
});
