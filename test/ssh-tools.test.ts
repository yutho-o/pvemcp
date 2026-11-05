import { readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer, type AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SshSessions } from '../src/ssh/sessions.js';
import { FAKE_SSH_PASSWORD, FakeSsh, generateKey, ShellSandbox } from './fake-ssh.js';
import { closeSsh, connectSsh, POSIX_SHELL, tempDir, type ConnectSshOptions, type SshHarness } from './ssh-harness.js';

/** The SSH tools as an agent meets them: through a real MCP client, on a real SSH connection. */

afterEach(closeSsh);

const IS_WINDOWS = process.platform === 'win32';

const NODE_READ = ['pve_ssh_test', 'pve_ssh_host_diagnostics', 'pve_ssh_journal', 'pve_ssh_list_dir', 'pve_ssh_read_file', 'pve_ssh_pct_list', 'pve_ssh_qm_list'];
const NODE_WRITE = ['pve_ssh_exec', 'pve_ssh_write_file', 'pve_ssh_upload', 'pve_ssh_download', 'pve_ssh_delete_file'];
const LXC_READ = ['pve_lxc_info', 'pve_lxc_processes', 'pve_lxc_ports', 'pve_lxc_disk_usage', 'pve_lxc_logs', 'pve_lxc_list_dir', 'pve_lxc_read_file', 'pve_lxc_service_status', 'pve_lxc_list_packages', 'pve_lxc_list_users', 'pve_lxc_ssh_status', 'pve_lxc_ssh_list_keys'];
const LXC_WRITE = ['pve_lxc_exec', 'pve_lxc_run_script', 'pve_lxc_write_file', 'pve_lxc_push_file', 'pve_lxc_pull_file', 'pve_lxc_delete_file', 'pve_lxc_service', 'pve_lxc_install_packages', 'pve_lxc_remove_packages', 'pve_lxc_update_packages', 'pve_lxc_create_user', 'pve_lxc_delete_user', 'pve_lxc_set_password', 'pve_lxc_fsck', 'pve_lxc_fstrim', 'pve_lxc_mount', 'pve_lxc_unmount', 'pve_lxc_ssh_enable', 'pve_lxc_ssh_disable', 'pve_lxc_ssh_add_key', 'pve_lxc_ssh_remove_key', 'pve_lxc_ssh_configure'];
const GUEST_READ = ['pve_guest_ssh_test'];
const GUEST_WRITE = ['pve_guest_ssh_exec'];
const SESSION = ['pve_ssh_session_open', 'pve_ssh_session_send', 'pve_ssh_session_read', 'pve_ssh_session_close', 'pve_ssh_session_list'];
const READS = [...NODE_READ, ...LXC_READ, ...GUEST_READ];
const WRITES = [...NODE_WRITE, ...LXC_WRITE, ...GUEST_WRITE, ...SESSION];

const SECRET = 'TOP-SECRET-PAYLOAD';
const KEY = generateKey();
/** A call of every write tool on container 101, or on the node. All arguments valid. */
const WRITE_CALLS: Array<[string, Record<string, unknown>]> = [
  ['pve_lxc_exec', { vmid: 101, command: 'id', stdin: SECRET, env: { TOKEN: SECRET } }],
  ['pve_lxc_run_script', { vmid: 101, script: `echo ${SECRET}` }],
  ['pve_lxc_write_file', { vmid: 101, path: '/tmp/x', content: SECRET }],
  ['pve_lxc_push_file', { vmid: 101, local_path: 'local.txt', path: '/tmp/x' }],
  ['pve_lxc_pull_file', { vmid: 101, path: '/tmp/x', local_path: 'pulled.txt' }],
  ['pve_lxc_delete_file', { vmid: 101, path: '/tmp/x' }],
  ['pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'restart' }],
  ['pve_lxc_install_packages', { vmid: 101, packages: ['curl'] }],
  ['pve_lxc_remove_packages', { vmid: 101, packages: ['curl'] }],
  ['pve_lxc_update_packages', { vmid: 101 }],
  ['pve_lxc_create_user', { vmid: 101, name: 'bob' }],
  ['pve_lxc_delete_user', { vmid: 101, name: 'bob' }],
  ['pve_lxc_set_password', { vmid: 101, user: 'alice', password: SECRET }],
  ['pve_lxc_fsck', { vmid: 101 }],
  ['pve_lxc_fstrim', { vmid: 101 }],
  ['pve_lxc_mount', { vmid: 101 }],
  ['pve_lxc_unmount', { vmid: 101 }],
  ['pve_lxc_ssh_enable', { vmid: 101 }],
  ['pve_lxc_ssh_disable', { vmid: 101 }],
  ['pve_lxc_ssh_add_key', { vmid: 101, public_key: KEY.public }],
  ['pve_lxc_ssh_remove_key', { vmid: 101, public_key: KEY.public }],
  ['pve_lxc_ssh_configure', { vmid: 101, port: 2222 }],
];
const NODE_WRITE_CALLS: Array<[string, Record<string, unknown>]> = [
  ['pve_ssh_exec', { node: 'pve1', command: 'id', stdin: SECRET }],
  ['pve_ssh_write_file', { node: 'pve1', path: '/tmp/x', content: SECRET }],
  ['pve_ssh_upload', { node: 'pve1', local_path: 'local.txt', path: '/tmp/x' }],
  ['pve_ssh_download', { node: 'pve1', path: '/tmp/x', local_path: 'pulled.txt' }],
  ['pve_ssh_delete_file', { node: 'pve1', path: '/tmp/x' }],
];

describe('which tools there are, and behind what', () => {
  it('has every SSH tool of the design, with schemas a real client accepts', async () => {
    const { client } = await connectSsh();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const name of [...READS, ...WRITES]) expect(names, name).toContain(name);
    expect(READS.length + WRITES.length).toBe(53);
    for (const tool of tools.filter((t) => READS.includes(t.name))) expect(tool.annotations?.readOnlyHint, tool.name).toBe(true);
    for (const tool of tools.filter((t) => WRITES.includes(t.name))) {
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(false);
      expect(tool.inputSchema.properties, tool.name).toHaveProperty('dry_run');
    }
    for (const name of ['pve_ssh_exec', 'pve_lxc_exec', 'pve_lxc_run_script', 'pve_guest_ssh_exec', 'pve_ssh_session_open']) {
      expect(tools.find((t) => t.name === name)!.annotations, name).toMatchObject({ destructiveHint: true, openWorldHint: true });
    }
  });

  it('keeps the exec tools honest about what they are', async () => {
    const { client } = await connectSsh();
    const { tools } = await client.listTools();
    expect(tools.find((t) => t.name === 'pve_ssh_exec')!.description).toContain('root on the hypervisor');
    expect(tools.find((t) => t.name === 'pve_lxc_exec')!.description).toContain('not a sandbox');
  });

  it('shows none of them with SSH off, and never connects', async () => {
    const { toolNames, call, ssh } = await connectSsh({ env: { PROXMOX_ALLOW_SSH: 'false', PROXMOX_SSH_PASSWORD: '' } });
    const names = await toolNames();
    for (const name of [...READS, ...WRITES]) expect(names, name).not.toContain(name);
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'id' });
    expect(res.isError).toBe(true);
    expect(ssh.connections).toBe(0);
  });

  it('with SSH on and writes off, reads work and writes are refused unconnected', async () => {
    const { call, ssh, toolNames } = await connectSsh({ env: { PROXMOX_ALLOW_WRITES: 'false' } });
    ssh.on(/^hostname;/, { stdout: 'pve1\nroot\nv\n' });
    expect((await call('pve_ssh_test', { node: 'pve1' })).isError).toBe(false);
    const before = ssh.commands.length;
    for (const [name, args] of [...WRITE_CALLS, ...NODE_WRITE_CALLS]) {
      // Not even offered to the client: the gate itself is what test/ssh-gate.test.ts covers.
      expect((await toolNames()), name).not.toContain(name);
      expect((await call(name, args)).isError, name).toBe(true);
    }
    expect(ssh.commands).toHaveLength(before);
  });

  it('refuses to start SSH without any credential, at configuration', async () => {
    await expect(connectSsh({ env: { PROXMOX_SSH_PASSWORD: '' } })).rejects.toThrow(/no SSH credential/);
  });
});

describe('typed failures through a tool', () => {
  it('ssh_auth_failed', async () => {
    const res = await (await connectSsh({ env: { PROXMOX_SSH_PASSWORD: 'wrong-one' } })).call('pve_ssh_test', { node: 'pve1' });
    expect(res.data.error_type).toBe('ssh_auth_failed');
    expect(res.text).not.toContain('wrong-one');
  });

  it('ssh_unreachable', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const { port } = closed.address() as AddressInfo;
    await new Promise((resolve) => closed.close(resolve));
    const res = await (await connectSsh({ env: { PROXMOX_SSH_PORT: String(port) } })).call('pve_ssh_test', { node: 'pve1' });
    expect(res.data.error_type).toBe('ssh_unreachable');
  });

  it('diagnostics give one error when nothing connects, not eight', async () => {
    const res = await (await connectSsh({ env: { PROXMOX_SSH_PASSWORD: 'wrong-one' } })).call('pve_ssh_host_diagnostics', { node: 'pve1' });
    expect(res.data.error_type).toBe('ssh_auth_failed');
  });

  it('a sudo that refuses is an auth failure on the commands of this server', async () => {
    const ssh = new FakeSsh({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    await ssh.start();
    ssh.on(/^sudo /, { stderr: 'sudo: a password is required\n', code: 1 });
    try {
      const h = await connectSsh({ server: ssh, env: { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' } });
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'id' })).data.error_type).toBe('ssh_auth_failed');
    } finally {
      await closeSsh();
      await ssh.stop();
    }
  });

  it('a host that is no Proxmox node says so', async () => {
    const ssh = new FakeSsh();
    await ssh.start();
    ssh.on(/^pct /, { stderr: 'sh: pct: not found\n', code: 127 });
    try {
      const h = await connectSsh({ server: ssh });
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'id' })).data.error_type).toBe('not_supported');
    } finally {
      await closeSsh();
      await ssh.stop();
    }
  });

  it('a container on another node than pct looks on says so', async () => {
    const ssh = new FakeSsh();
    await ssh.start();
    ssh.on(/^pct /, { stderr: `Configuration file 'nodes/pve1/lxc/101.conf' does not exist\n`, code: 2 });
    try {
      const h = await connectSsh({ server: ssh });
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'id' })).data.error_type).toBe('not_found');
    } finally {
      await closeSsh();
      await ssh.stop();
    }
  });
});

describe('untrusted output', () => {
  const PEM = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';

  it('takes private keys and terminal escapes out of everything from a host', async () => {
    const { call, ssh } = await connectSsh();
    ssh.on('leak', { stdout: `before\n${PEM}\n\x1b[31mred\x1b[0m\x07 after\n`, stderr: `\x1b]0;title\x07${PEM}\n` });
    const res = await call('pve_ssh_exec', { node: 'pve1', command: 'leak' });
    expect(res.isError).toBe(false);
    expect(res.text).not.toContain('b3BlbnNzaC1rZXktdjEAAAAA');
    expect(res.text).not.toContain('\\u001b');
    expect(res.data.stdout).toContain('red');
    expect(res.data.stdout).toContain('[REDACTED]');
    expect(res.data.untrusted).toBe(true);
  });

  it('flags what comes from a host, on every tool that returns its output', async () => {
    const { call, ssh } = await connectSsh();
    ssh.on(/.*/, { stdout: 'x\n' });
    for (const [name, args] of [
      ['pve_ssh_test', { node: 'pve1' }],
      ['pve_ssh_journal', { node: 'pve1' }],
      ['pve_ssh_list_dir', { node: 'pve1', path: '/' }],
      ['pve_ssh_pct_list', { node: 'pve1' }],
      ['pve_ssh_qm_list', { node: 'pve1' }],
      ['pve_ssh_host_diagnostics', { node: 'pve1' }],
      ['pve_ssh_exec', { node: 'pve1', command: 'x' }],
      ['pve_lxc_exec', { vmid: 101, command: 'x' }],
      ['pve_lxc_processes', { vmid: 101 }],
    ] as const) {
      expect((await call(name, args)).data.untrusted, name).toBe(true);
    }
  });
});

describe.skipIf(!POSIX_SHELL)('with a real shell on the node', () => {
  const boot = async (opts: ConnectSshOptions = {}) => {
    const sandbox = new ShellSandbox(POSIX_SHELL!);
    const server = new FakeSsh({ sandbox });
    await server.start();
    const h = await connectSsh({ ...opts, server });
    writeFileSync(join(h.localDir, 'local.txt'), SECRET);
    return { ...h, sandbox, server, finish: async () => { await closeSsh(); await server.stop(); sandbox.remove(); } };
  };

  describe('node tools', () => {
    it('test reports host, user, version and the key it verified', async () => {
      const h = await boot();
      const res = await h.call('pve_ssh_test', { node: 'pve1' });
      expect(res.data).toMatchObject({ connected: true, user: expect.any(String), host_key: { fingerprint: h.server.hostKey.fingerprint, type: 'ssh-ed25519' } });
      expect(res.data.pveversion).toContain('pve-manager/9.1.0');
      await h.finish();
    });

    it('diagnostics give each its own status', async () => {
      const h = await boot();
      const { sections } = (await h.call('pve_ssh_host_diagnostics', { node: 'pve1' })).data;
      expect(Object.keys(sections).sort()).toEqual(['cluster', 'disk', 'failed_units', 'journal_errors', 'lvm', 'memory', 'uptime', 'zfs']);
      expect(sections.uptime).toMatchObject({ ok: true, exit_code: 0 });
      expect(sections.zfs.output).toBe('all pools are healthy');
      expect(sections.cluster.output).toBe('Quorate: Yes');
      expect(sections.lvm).toMatchObject({ ok: false, exit_code: 127, not_installed: true });
      expect(sections.journal_errors.output).not.toContain('\x1b');
      await h.finish();
    });

    it('journal passes its filters as arguments', async () => {
      const h = await boot();
      const res = await h.call('pve_ssh_journal', { node: 'pve1', unit: 'pveproxy', lines: 3, since: '2026-01-01 12:00', priority: 'err' });
      expect(res.data.stdout).toContain('ARGS:--no-pager -o short-iso -n 3 -u pveproxy --since=2026-01-01 12:00 -p err');
      await h.finish();
    });

    it('lists qm and pct as rows', async () => {
      const h = await boot();
      expect((await h.call('pve_ssh_qm_list', { node: 'pve1' })).data.rows).toEqual([
        { vmid: 100, name: 'web', status: 'running', memory_mb: 2048, bootdisk_gb: 32, pid: 4242 },
        { vmid: 102, name: 'db', status: 'stopped', memory_mb: 1024, bootdisk_gb: 16 },
      ]);
      await h.finish();
    });

    it('reads, writes, lists and deletes', async () => {
      const h = await boot();
      expect((await h.call('pve_ssh_write_file', { node: 'pve1', path: '/tmp/f', content: 'one', mode: '0600' })).data.bytes).toBe(3);
      expect((await h.call('pve_ssh_read_file', { node: 'pve1', path: '/tmp/f' })).data.content).toBe('one');
      expect((await h.call('pve_ssh_list_dir', { node: 'pve1', path: '/tmp' })).data.rows.map((r: { name: string }) => r.name)).toContain('f');
      expect((await h.call('pve_ssh_delete_file', { node: 'pve1', path: '/tmp/f' })).data.deleted).toBe(true);
      expect((await h.call('pve_ssh_delete_file', { node: 'pve1', path: '/tmp/f' })).data.error_type).toBe('not_found');
      await h.finish();
    });

    it('exec honours cwd, and a bad cwd runs nothing', async () => {
      const h = await boot();
      expect((await h.call('pve_ssh_exec', { node: 'pve1', command: 'pwd', cwd: '/etc' })).data.stdout.trim()).toBe('/etc');
      const bad = await h.call('pve_ssh_exec', { node: 'pve1', command: 'echo ran', cwd: '/etc/none' });
      expect(bad.data.exit_code).toBe(125);
      expect(bad.data.stdout).toBe('');
      await h.finish();
    });

    it('a read tool never takes the write path', async () => {
      const h = await boot({ env: { PROXMOX_ALLOW_WRITES: 'false' } });
      expect((await h.call('pve_ssh_list_dir', { node: 'pve1', path: '/etc' })).isError).toBe(false);
      await h.finish();
    });
  });

  describe('dry runs', () => {
    it.each([...WRITE_CALLS, ...NODE_WRITE_CALLS])('%s connects to nothing, and shows no secret', async (name, args) => {
      const h = await boot();
      const res = await h.call(name, { ...args, dry_run: true });
      expect(res.isError, res.text).toBe(false);
      expect(res.data.dry_run).toBe(true);
      expect(res.data.would_send.length, res.text).toBeGreaterThan(0);
      expect(res.text).not.toContain(SECRET);
      expect(h.server.connections).toBe(0);
      expect(h.sandbox.nodeCalls()).toEqual([]);
      await h.finish();
    });

    it('works with writes off, on a server in dry-run mode', async () => {
      const h = await boot({ env: { PROXMOX_ALLOW_WRITES: 'false', PROXMOX_DRY_RUN: 'true' } });
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'reboot' });
      expect(res.isError, res.text).toBe(false);
      expect(res.data.would_send[0].ssh.command).toContain('reboot');
      await h.finish();
    });

    it('shows the stdin as size and digest only, and the password not at all', async () => {
      const h = await boot();
      const exec = await h.call('pve_lxc_exec', { vmid: 101, command: 'cat', stdin: SECRET, dry_run: true });
      expect(exec.data.would_send[0].ssh.stdin).toEqual({ bytes: SECRET.length, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
      const password = await h.call('pve_lxc_set_password', { vmid: 101, user: 'alice', password: SECRET, dry_run: true });
      expect(password.data.would_send[0].ssh).not.toHaveProperty('stdin');
      expect(password.data.would_send[0].ssh.command).toContain('password of alice on stdin');
      await h.finish();
    });

    it('shows the real script, as it would run', async () => {
      const h = await boot();
      const res = await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['curl'], dry_run: true });
      const { command } = res.data.would_send[0].ssh;
      expect(command).toContain(`pct exec '101' -- sh -c`);
      expect(command).toContain('apk add');
      await h.finish();
    });
  });

  describe('the audit log', () => {
    const auditEntries = (file: string) => readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as Record<string, any>);

    it('has the command and never the secrets, on every tool, for real and on failure', async () => {
      const audit = join(tempDir(), 'audit.log');
      const h = await boot({ env: { PROXMOX_AUDIT_LOG: audit } });
      h.sandbox.write('/tmp/x', 'present');
      for (const [name, args] of [...WRITE_CALLS, ...NODE_WRITE_CALLS]) await h.call(name, args);
      await vi.waitFor(() => expect(auditEntries(audit).length).toBeGreaterThanOrEqual(WRITE_CALLS.length + NODE_WRITE_CALLS.length));
      expect(readFileSync(audit, 'utf8')).not.toContain(SECRET);
      const exec = auditEntries(audit).find((e) => e.tool === 'pve_lxc_exec')!;
      expect(exec.args.stdin).toBe('[REDACTED]');
      expect(exec.args.env).toBe('[REDACTED]');
      expect(exec.args.command).toBe('id');
      expect(exec.writes[0].ssh.command).toBe('pct exec 101 -- (env=TOKEN) id');
      expect(exec.writes[0].ssh.stdin).toEqual({ bytes: SECRET.length, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
      const password = auditEntries(audit).find((e) => e.tool === 'pve_lxc_set_password')!;
      expect(password.args.password).toBe('[REDACTED]');
      expect(password.writes[0].ssh).not.toHaveProperty('stdin');
      await h.finish();
    }, 60_000);

    it('marks a dry run', async () => {
      const audit = join(tempDir(), 'audit.log');
      const h = await boot({ env: { PROXMOX_AUDIT_LOG: audit } });
      await h.call('pve_lxc_exec', { vmid: 101, command: 'id', dry_run: true });
      await vi.waitFor(() => expect(auditEntries(audit)[0]!.dry_run).toBe(true));
      await h.finish();
    });
  });

  describe('protected guests', () => {
    it.each(WRITE_CALLS)('%s is refused', async (name, args) => {
      const h = await boot({ env: { PROXMOX_PROTECTED_VMIDS: '101' } });
      const res = await h.call(name, args);
      expect(res.data.error_type, res.text).toBe('protected_guest');
      expect(h.sandbox.nodeCalls()).toEqual([]);
      await h.finish();
    });

    it('also in a dry run, a guest exec, and a session', async () => {
      const h = await boot({ env: { PROXMOX_PROTECTED_VMIDS: '101' } });
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'id', dry_run: true })).data.error_type).toBe('protected_guest');
      expect((await h.call('pve_guest_ssh_exec', { vmid: 101, command: 'id', host: '127.0.0.1' })).data.error_type).toBe('protected_guest');
      expect((await h.call('pve_ssh_session_open', { vmid: 101 })).data.error_type).toBe('protected_guest');
      await h.finish();
    });

    it('leaves reads, and other guests, alone', async () => {
      const h = await boot({ env: { PROXMOX_PROTECTED_VMIDS: '999,101' } });
      expect((await h.call('pve_lxc_list_users', { vmid: 101 })).isError).toBe(false);
      expect((await h.call('pve_lxc_info', { vmid: 101 })).isError).toBe(false);
      await h.finish();
    });
  });

  describe('secret files', () => {
    const SECRETS = ['/etc/shadow', '/etc/gshadow', '/etc/shadow-', '/root/.ssh/id_rsa', '/root/.ssh/id_ed25519', '/home/alice/.ssh/id_ecdsa', '/etc/pve/priv/authkey.key', '/etc/pve/priv/authorized_keys', '/etc/pve/local/pve-ssl.key', '/etc/pve/nodes/pve1/pve-ssl.key', '/etc/corosync/authkey', '/etc/ssh/ssh_host_ed25519_key', '/var/lib/pve-cluster/config.db', '/proc/1/environ', '/etc/../etc/shadow', '/etc//shadow'];

    it.each(SECRETS)('refuses %s, on node and container, before running anything', async (path) => {
      const h = await boot();
      for (const [name, args] of [
        ['pve_ssh_read_file', { node: 'pve1', path }],
        ['pve_lxc_read_file', { vmid: 101, path }],
        ['pve_ssh_download', { node: 'pve1', path, local_path: 'out.txt' }],
        ['pve_lxc_pull_file', { vmid: 101, path, local_path: 'out.txt' }],
      ] as const) {
        const res = await h.call(name, args);
        expect(res.data.error_type, `${name} ${path}`).toBe('sensitive_disabled');
      }
      expect(h.sandbox.nodeCalls()).toEqual([]);
      expect(h.server.commands).toEqual([]);
      await h.finish();
    });

    it('refuses the same file through a link, on every way out', async () => {
      const h = await boot();
      h.sandbox.write('/root/.ssh/id_rsa', 'PRIVATE');
      symlinkSync(h.sandbox.file('/root/.ssh'), h.sandbox.file('/tmp/innocent'), IS_WINDOWS ? 'junction' : 'dir');
      for (const [name, args] of [
        ['pve_ssh_read_file', { node: 'pve1', path: '/tmp/innocent/id_rsa' }],
        ['pve_lxc_read_file', { vmid: 101, path: '/tmp/innocent/id_rsa' }],
        ['pve_ssh_download', { node: 'pve1', path: '/tmp/innocent/id_rsa', local_path: 'out.txt' }],
        ['pve_lxc_pull_file', { vmid: 101, path: '/tmp/innocent/id_rsa', local_path: 'out.txt' }],
      ] as const) {
        const res = await h.call(name, args);
        expect(res.data.error_type, name).toBe('sensitive_disabled');
        expect(res.text).not.toContain('PRIVATE');
      }
      await h.finish();
    });

    it('allows public keys and ordinary files', async () => {
      const h = await boot();
      h.sandbox.write('/etc/ssh/ssh_host_ed25519_key.pub', 'public\n');
      h.sandbox.write('/root/.ssh/id_rsa.pub', 'public\n');
      h.sandbox.write('/root/.ssh/authorized_keys', 'public\n');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/etc/ssh/ssh_host_ed25519_key.pub' })).data.content).toBe('public\n');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/root/.ssh/id_rsa.pub' })).data.content).toBe('public\n');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/root/.ssh/authorized_keys' })).data.content).toBe('public\n');
      await h.finish();
    });

    it('opens up only with PROXMOX_ALLOW_SENSITIVE', async () => {
      const h = await boot({ env: { PROXMOX_ALLOW_SENSITIVE: 'true' } });
      h.sandbox.write('/etc/shadow', 'hashes\n');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/etc/shadow' })).data.content).toBe('hashes\n');
      expect((await h.call('pve_ssh_download', { node: 'pve1', path: '/etc/shadow', local_path: 'shadow.txt' })).isError).toBe(false);
      expect(readFileSync(join(h.localDir, 'shadow.txt'), 'utf8')).toBe('hashes\n');
      await h.finish();
    });
  });

  describe('asking a human', () => {
    it('shows what will run, and nothing that is secret', async () => {
      const messages: string[] = [];
      const h = await boot({ onElicit: (message) => (messages.push(message), { action: 'accept', content: { confirm: true } }) });
      await h.call('pve_lxc_exec', { vmid: 101, command: 'echo visible', stdin: SECRET, env: { T: SECRET } });
      await h.call('pve_lxc_write_file', { vmid: 101, path: '/tmp/x', content: SECRET });
      await h.call('pve_lxc_set_password', { vmid: 101, user: 'alice', password: SECRET });
      await h.call('pve_ssh_exec', { node: 'pve1', command: 'echo visible2', stdin: SECRET });
      await h.call('pve_ssh_write_file', { node: 'pve1', path: '/tmp/y', content: SECRET });
      expect(messages).toHaveLength(5);
      expect(messages[0]).toContain('echo visible');
      expect(messages[3]).toContain('as root on node pve1');
      expect(messages.join('\n')).not.toContain(SECRET);
      await h.finish();
    });

    it('a no runs nothing', async () => {
      const h = await boot({ onElicit: () => ({ action: 'decline' }) });
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'spy never' });
      expect(res.data.error_type).toBe('user_cancelled');
      expect(h.sandbox.nodeCalls()).toEqual([]);
      await h.finish();
    });

    it('does not ask for what is not destructive', async () => {
      const messages: string[] = [];
      const h = await boot({ onElicit: (message) => (messages.push(message), { action: 'accept', content: { confirm: true } }) });
      await h.call('pve_lxc_list_users', { vmid: 101 });
      await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'start' });
      expect(messages).toEqual([]);
      await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'stop' });
      expect(messages).toHaveLength(1);
      await h.finish();
    });
  });
});

describe('SSH to guests', () => {
  const GUEST_PASSWORD = 'guest-password';

  /** One server for the node, one for the guest, each with its own key. */
  const setup = async (opts: { guest?: ConstructorParameters<typeof FakeSsh>[0]; env?: Record<string, string>; node?: ConstructorParameters<typeof FakeSsh>[0]; ip?: string; agent?: boolean } = {}) => {
    const guest = new FakeSsh(opts.guest ?? { users: { root: { password: GUEST_PASSWORD }, deploy: { password: GUEST_PASSWORD } } });
    await guest.start();
    const node = new FakeSsh(opts.node);
    await node.start();
    node.on(/ssh_host_\*_key\.pub/, { stdout: `${guest.hostKey.public}\n` });
    guest.on(/^id -un/, { stdout: 'root\nLinux 6.1 x86_64\n' });
    const h = await connectSsh({
      server: node,
      env: { PROXMOX_GUEST_SSH_PASSWORD: GUEST_PASSWORD, ...opts.env },
      fake: { guests: [{ vmid: 100, type: 'qemu', name: 'web', ...(opts.ip ? { ip: opts.ip } : {}), ...(opts.agent === false ? { agent: false } : {}) }, { vmid: 101, type: 'lxc', name: 'db', ...(opts.ip ? { ip: opts.ip } : {}) }] },
    });
    const finish = async () => {
      await closeSsh();
      await node.stop();
      await guest.stop();
    };
    return { h, guest, node, finish, at: { host: '127.0.0.1', port: guest.port } };
  };

  it('checks a container against the keys read through pct, and logs in with guest credentials only', async () => {
    const { h, guest, node, finish, at } = await setup();
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    expect(res.data).toMatchObject({ connected: true, user: 'root', system: 'Linux 6.1 x86_64', host: '127.0.0.1', host_key: { fingerprint: guest.hostKey.fingerprint } });
    expect(node.commands.some((c) => c.command === `pct exec '101' -- sh -c 'cat /etc/ssh/ssh_host_*_key.pub'`)).toBe(true);
    expect(guest.authAttempts.every((a) => a.user === 'root' && a.password !== FAKE_SSH_PASSWORD)).toBe(true);
    expect(guest.authAttempts.some((a) => a.password === GUEST_PASSWORD)).toBe(true);
    expect(node.authAttempts.some((a) => a.password === GUEST_PASSWORD)).toBe(false);
    await finish();
  });

  it('refuses a container presenting a key other than the one pct shows, with no credential sent', async () => {
    const { h, guest, node, finish, at } = await setup();
    node.options.refuseChannels = false;
    const other = generateKey();
    (node as unknown as { scripted: unknown[] }).scripted.length = 0;
    node.on(/ssh_host_\*_key\.pub/, { stdout: `${other.public}\n` });
    const res = await h.call('pve_guest_ssh_exec', { vmid: 101, command: 'id', ...at });
    expect(res.data.error_type).toBe('host_key_mismatch');
    expect(res.data.details).toMatchObject({ presented: guest.hostKey.fingerprint, expected: [other.fingerprint] });
    expect(guest.authAttempts).toEqual([]);
    expect(guest.commands).toEqual([]);
    await finish();
  });

  it('refuses a container with no host keys to compare with', async () => {
    const { h, node, guest, finish, at } = await setup();
    (node as unknown as { scripted: unknown[] }).scripted.length = 0;
    node.on(/ssh_host_\*_key\.pub/, { stderr: 'cat: no such file\n', code: 1 });
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    expect(res.data.error_type).toBe('host_key_unknown');
    expect(res.data.hint).toContain('pve_lxc_ssh_enable');
    expect(guest.connections).toBe(0);
    await finish();
  });

  it('says so for a stopped container', async () => {
    const { h, node, finish, at } = await setup();
    (node as unknown as { scripted: unknown[] }).scripted.length = 0;
    node.on(/ssh_host_\*_key\.pub/, { stderr: 'CT 101 not running\n', code: 255 });
    expect((await h.call('pve_guest_ssh_test', { vmid: 101, ...at })).data.error_type).toBe('guest_not_running');
    await finish();
  });

  it('refuses a VM that nothing vouches for, however the policy reads', async () => {
    const { h, guest, finish, at } = await setup();
    const res = await h.call('pve_guest_ssh_test', { vmid: 100, ...at });
    expect(res.data.error_type).toBe('host_key_unknown');
    expect(res.data.details.fingerprint).toBe(guest.hostKey.fingerprint);
    expect(guest.authAttempts).toEqual([]);
    await finish();
  });

  it('takes a VM with a fingerprint given on the call, and refuses a wrong one', async () => {
    const { h, guest, finish, at } = await setup();
    expect((await h.call('pve_guest_ssh_test', { vmid: 100, ...at, fingerprint: guest.hostKey.fingerprint })).data.connected).toBe(true);
    const wrong = await h.call('pve_guest_ssh_test', { vmid: 100, ...at, fingerprint: generateKey().fingerprint });
    expect(wrong.data.error_type).toBe('host_key_mismatch');
    await finish();
  });

  it('takes a VM listed in known_hosts', async () => {
    const { h, guest, finish, at } = await setup();
    writeFileSync(h.knownHosts, `${h.ssh.knownHostsLine()}\n${guest.knownHostsLine()}\n`);
    expect((await h.call('pve_guest_ssh_test', { vmid: 100, ...at })).data.connected).toBe(true);
    await finish();
  });

  it('finds the address of a container from the node, skipping loopback', async () => {
    const { h, guest, finish } = await setup({ ip: '127.0.0.1' });
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, port: guest.port });
    expect(res.data).toMatchObject({ connected: true, host: '127.0.0.1' });
    await finish();
  });

  it('finds the address of a VM from its guest agent', async () => {
    const { h, guest, finish } = await setup({ ip: '127.0.0.1' });
    const res = await h.call('pve_guest_ssh_test', { vmid: 100, port: guest.port, fingerprint: guest.hostKey.fingerprint });
    expect(res.data).toMatchObject({ connected: true, host: '127.0.0.1' });
    await finish();
  });

  it('says what to do when a VM has no agent to ask', async () => {
    const { h, guest, finish } = await setup({ agent: false });
    const res = await h.call('pve_guest_ssh_test', { vmid: 100, port: guest.port });
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.hint).toContain('Pass host');
    expect(guest.connections).toBe(0);
    await finish();
  });

  it('goes through the node with via_node: real forwarding, key still checked, node password not sent', async () => {
    const { h, guest, node, finish, at } = await setup();
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, ...at, via_node: true });
    expect(res.data).toMatchObject({ connected: true, host_key: { fingerprint: guest.hostKey.fingerprint } });
    expect(node.forwards).toEqual([{ host: '127.0.0.1', port: guest.port }]);
    expect(guest.authAttempts.some((a) => a.password === FAKE_SSH_PASSWORD)).toBe(false);
    await finish();
  });

  it('refuses a key that differs through the jump too', async () => {
    const { h, node, guest, finish, at } = await setup();
    (node as unknown as { scripted: unknown[] }).scripted.length = 0;
    node.on(/ssh_host_\*_key\.pub/, { stdout: `${generateKey().public}\n` });
    expect((await h.call('pve_guest_ssh_test', { vmid: 101, ...at, via_node: true })).data.error_type).toBe('host_key_mismatch');
    expect(guest.authAttempts).toEqual([]);
    await finish();
  });

  it('says so when the node does not forward', async () => {
    const { h, finish, at } = await setup({ node: { allowForwarding: false } });
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, ...at, via_node: true });
    expect(res.data.error_type).toBe('ssh_unreachable');
    expect(res.data.hint).toContain('AllowTcpForwarding');
    await finish();
  });

  it('wants a credential of its own, and never falls back on that of the node', async () => {
    const { h, guest, finish, at } = await setup({ env: { PROXMOX_GUEST_SSH_PASSWORD: '' } });
    const res = await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    expect(res.data.error_type).toBe('config_error');
    expect(guest.connections).toBe(0);
    await finish();
  });

  it('logs in with a key for guests', async () => {
    const key = generateKey();
    const file = join(tempDir(), 'guest_key');
    writeFileSync(file, key.private);
    const { h, guest, finish, at } = await setup({ guest: { users: { root: { keys: [key.public] } } }, env: { PROXMOX_GUEST_SSH_PASSWORD: '', PROXMOX_GUEST_SSH_KEY_FILE: file } });
    expect((await h.call('pve_guest_ssh_test', { vmid: 101, ...at })).data.connected).toBe(true);
    expect(guest.authAttempts.at(-1)).toMatchObject({ method: 'publickey' });
    await finish();
  });

  it('gives ssh_auth_failed for refused guest credentials', async () => {
    const { h, finish, at } = await setup({ env: { PROXMOX_GUEST_SSH_PASSWORD: 'wrong' } });
    expect((await h.call('pve_guest_ssh_test', { vmid: 101, ...at })).data.error_type).toBe('ssh_auth_failed');
    await finish();
  });

  it('uses the user asked for, then the configured one', async () => {
    const { h, guest, finish, at } = await setup({ env: { PROXMOX_GUEST_SSH_USER: 'deploy' } });
    await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    expect(guest.authAttempts.at(-1)!.user).toBe('deploy');
    await h.call('pve_guest_ssh_test', { vmid: 101, ...at, user: 'root' });
    expect(guest.authAttempts.at(-1)!.user).toBe('root');
    await finish();
  });

  it('runs commands, with stdin, cwd and the exit code', async () => {
    const { h, guest, finish, at } = await setup();
    guest.on(/run-it/, (req) => ({ stdout: req.stdin, code: 4 }));
    const res = await h.call('pve_guest_ssh_exec', { vmid: 101, ...at, command: 'run-it', stdin: 'piped', cwd: '/srv/a b' });
    expect(res.data).toMatchObject({ stdout: 'piped', exit_code: 4, untrusted: true, vmid: 101 });
    expect(guest.commands.at(-1)!.command).toBe(`cd -- '/srv/a b' || exit '125'\nrun-it`);
    await finish();
  });

  it('does not use sudo of the node on a guest', async () => {
    const ssh = new FakeSsh({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    await ssh.start();
    const guest = new FakeSsh({ users: { root: { password: GUEST_PASSWORD } } });
    await guest.start();
    ssh.on(/ssh_host_\*_key\.pub/, { stdout: `${guest.hostKey.public}\n` });
    guest.on('id -un; uname -srm', { stdout: 'root\nx\n' });
    const h = await connectSsh({ server: ssh, env: { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true', PROXMOX_GUEST_SSH_PASSWORD: GUEST_PASSWORD } });
    await h.call('pve_guest_ssh_test', { vmid: 101, host: '127.0.0.1', port: guest.port });
    expect(guest.commands[0]!.command).toBe('id -un; uname -srm');
    await closeSsh();
    await ssh.stop();
    await guest.stop();
  });

  it('a dry run connects to nothing, and says who it is about', async () => {
    const { h, guest, node, finish, at } = await setup();
    const res = await h.call('pve_guest_ssh_exec', { vmid: 101, ...at, command: 'reboot', stdin: SECRET, dry_run: true });
    expect(res.isError, res.text).toBe(false);
    expect(res.text).not.toContain(SECRET);
    expect(res.data.would_send.at(-1).ssh.command).toBe('[guest 101 root@127.0.0.1] reboot');
    expect(guest.connections).toBe(0);
    expect(node.connections).toBe(0);
    await finish();
  });

  it('a connection per call: none stays open on the guest', async () => {
    const { h, guest, finish, at } = await setup();
    await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    await h.call('pve_guest_ssh_test', { vmid: 101, ...at });
    expect(guest.connections).toBe(2);
    await vi.waitFor(() => expect((guest as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
    await finish();
  });
});

describe('PTY sessions', () => {
  const open = async (h: SshHarness, args: Record<string, unknown> = { node: 'pve1' }) => {
    const res = await h.call('pve_ssh_session_open', args);
    expect(res.isError, res.text).toBe(false);
    return res.data.session as string;
  };
  const readUntil = async (h: SshHarness, session: string, text: string): Promise<string> => {
    let seen = '';
    await vi.waitFor(async () => {
      seen += (await h.call('pve_ssh_session_read', { session, wait_ms: 100 })).data.output ?? '';
      expect(seen).toContain(text);
    });
    return seen;
  };

  it('opens, types, reads, lists and closes', async () => {
    const h = await connectSsh();
    const res = await h.call('pve_ssh_session_open', { node: 'pve1', cols: 100, rows: 30 });
    expect(res.data).toMatchObject({ node: 'pve1', untrusted: true, next_step: 'pve_ssh_session_send' });
    expect(res.data.output).toContain('fake#');
    const { session } = res.data;
    expect(h.ssh.ptys[0]).toMatchObject({ cols: 100, rows: 30, term: 'xterm' });

    expect((await h.call('pve_ssh_session_send', { session, input: 'uname\n' })).data).toMatchObject({ sent_bytes: 6, next_step: 'pve_ssh_session_read' });
    expect(await readUntil(h, session, 'ran: uname')).toContain('uname');
    expect(h.ssh.typed).toEqual(['uname']);

    const listed = (await h.call('pve_ssh_session_list')).data.rows;
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ session, node: 'pve1', command: '(login shell)', closed: false });

    expect((await h.call('pve_ssh_session_close', { session })).data).toMatchObject({ session, closed: true });
    expect((await h.call('pve_ssh_session_list')).data.rows).toEqual([]);
    expect((await h.call('pve_ssh_session_read', { session })).data.error_type).toBe('not_found');
    await vi.waitFor(() => expect((h.ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
  });

  it('enters a container with pct enter', async () => {
    const h = await connectSsh();
    const session = await open(h, { vmid: 101 });
    expect(h.ssh.ptys[0]!.command).toBe(`pct enter '101'`);
    expect((await h.call('pve_ssh_session_list')).data.rows[0]).toMatchObject({ session, vmid: 101, command: `pct enter '101'` });
  });

  it('gives guest_not_running for a stopped container, and keeps no session', async () => {
    const h = await connectSsh({ sshOptions: { ptyStoppedGuests: [101] } });
    const res = await h.call('pve_ssh_session_open', { vmid: 101 });
    expect(res.data.error_type).toBe('guest_not_running');
    expect((await h.call('pve_ssh_session_list')).data.rows).toEqual([]);
  });

  it('a VM has no pct enter', async () => {
    const h = await connectSsh();
    expect((await h.call('pve_ssh_session_open', { vmid: 100 })).data.error_type).toBe('invalid_input');
    expect(h.ssh.ptys).toEqual([]);
  });

  it('presses control keys', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'sleep 100', keys: ['ctrl-c'] });
    await readUntil(h, session, '^C');
    expect(h.ssh.typed).toEqual(['^C']);
  });

  it('refuses a key it does not know', async () => {
    const h = await connectSsh();
    const session = await open(h);
    expect((await h.call('pve_ssh_session_send', { session, keys: ['ctrl-q'] })).isError).toBe(true);
  });

  it('resizes the terminal', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, cols: 200, rows: 50 });
    await vi.waitFor(() => expect(h.ssh.windowChanges).toEqual([{ cols: 200, rows: 50 }]));
  });

  it('takes escapes out of what it returns', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'color\n' });
    const seen = await readUntil(h, session, 'red');
    expect(seen).not.toContain('\x1b');
    expect(seen).not.toContain('[31m');
  });

  it('reports the end of the program, once, and then forgets it', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'exit\n' });
    await vi.waitFor(async () => {
      const res = await h.call('pve_ssh_session_read', { session, wait_ms: 50 });
      expect(res.data).toMatchObject({ closed: true, exit_code: 0 });
    });
    expect((await h.call('pve_ssh_session_read', { session })).data.error_type).toBe('not_found');
  });

  it('refuses typing into a program that ended', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'exit\n' });
    await vi.waitFor(async () => expect((await h.call('pve_ssh_session_list')).data.rows[0].closed).toBe(true));
    const res = await h.call('pve_ssh_session_send', { session, input: 'x\n' });
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.hint).toContain('pve_ssh_session_open');
  });

  it('allows 8 at a time, each on its own connection', async () => {
    const h = await connectSsh();
    const sessions: string[] = [];
    for (let i = 0; i < 8; i++) sessions.push(await open(h));
    expect(h.ssh.connections).toBe(8);
    const ninth = await h.call('pve_ssh_session_open', { node: 'pve1' });
    expect(ninth.data.error_type).toBe('invalid_input');
    expect(ninth.data.hint).toContain('pve_ssh_session_close');
    expect(h.ssh.connections).toBe(8);
    await h.call('pve_ssh_session_close', { session: sessions[0] });
    await open(h);
  });

  it('closes a session left idle', async () => {
    const h = await connectSsh();
    h.runtime.state('ssh-sessions', () => new SshSessions({ idleMs: 60 }));
    const session = await open(h);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect((await h.call('pve_ssh_session_read', { session })).data.error_type).toBe('not_found');
    await vi.waitFor(() => expect((h.ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
  });

  it('a program printing on its own does not count as use', async () => {
    const sessions = new SshSessions({ idleMs: 80 });
    const h = await connectSsh();
    h.runtime.state('ssh-sessions', () => sessions);
    await open(h);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(sessions.list('default')).toEqual([]);
  });

  it('drops the oldest output past the ring size, and says how much', async () => {
    const h = await connectSsh();
    h.runtime.state('ssh-sessions', () => new SshSessions({ bufferBytes: 1024 }));
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'flood 5000\n' });
    await vi.waitFor(async () => {
      expect((await h.call('pve_ssh_session_list')).data.rows[0].unread_bytes).toBe(1024);
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    const res = await h.call('pve_ssh_session_read', { session });
    expect(res.data.dropped_bytes).toBeGreaterThan(3900);
    expect(res.data.output.length).toBeLessThanOrEqual(1024);
    expect(res.data.output).toContain('fake#');
  });

  it('keeps a character cut across two reads whole', async () => {
    const h = await connectSsh();
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: 'é☃\n' });
    expect(await readUntil(h, session, 'ran: é☃')).not.toContain('�');
  });

  it('closes at shutdown', async () => {
    const h = await connectSsh();
    await open(h);
    await open(h);
    await h.runtime.shutdown();
    await vi.waitFor(() => expect((h.ssh as unknown as { clients: Set<unknown> }).clients.size).toBe(0));
  });

  it('a dry run opens nothing and types nothing', async () => {
    const h = await connectSsh();
    const refused = await h.call('pve_ssh_session_open', { node: 'pve1', dry_run: true });
    expect(refused.data.error_type).toBe('invalid_input');
    expect(h.ssh.connections).toBe(0);
    const session = await open(h);
    const res = await h.call('pve_ssh_session_send', { session, input: `${SECRET}\n`, dry_run: true });
    expect(res.data).toMatchObject({ dry_run: true, sent_bytes: 0 });
    expect(res.text).not.toContain(SECRET);
    expect(h.ssh.typed).toEqual([]);
    expect((await h.call('pve_ssh_session_close', { session, dry_run: true })).data.dry_run).toBe(true);
    expect((await h.call('pve_ssh_session_list')).data.rows).toHaveLength(1);
  });

  it('keeps what is typed out of the audit log, and asks a human only for the opening', async () => {
    const audit = join(tempDir(), 'audit.log');
    const messages: string[] = [];
    const h = await connectSsh({ env: { PROXMOX_AUDIT_LOG: audit }, onElicit: (message) => (messages.push(message), { action: 'accept', content: { confirm: true } }) });
    const session = await open(h);
    await h.call('pve_ssh_session_send', { session, input: `${SECRET}\n` });
    await readUntil(h, session, SECRET);
    await h.call('pve_ssh_session_close', { session });
    expect(messages).toHaveLength(1);
    await vi.waitFor(() => {
      const lines = readFileSync(audit, 'utf8').trim().split('\n');
      expect(lines.length).toBeGreaterThanOrEqual(3);
      const send = lines.map((l) => JSON.parse(l)).find((e) => e.tool === 'pve_ssh_session_send');
      expect(send.args.input).toBe('[REDACTED]');
      expect(send.writes[0].ssh.bytes).toBe(SECRET.length + 1);
    });
    expect(readFileSync(audit, 'utf8')).not.toContain(SECRET);
  });

  it('refuses a malformed session id before looking', async () => {
    const h = await connectSsh();
    expect((await h.call('pve_ssh_session_read', { session: '../../etc' })).isError).toBe(true);
  });

  it('goes through sudo for a user who needs it', async () => {
    const ssh = new FakeSsh({ users: { admin: { password: FAKE_SSH_PASSWORD } } });
    await ssh.start();
    const h = await connectSsh({ server: ssh, env: { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' } });
    await open(h);
    await open(h, { vmid: 101 });
    expect(ssh.ptys.map((p) => p.command)).toEqual(['sudo -n -i', `sudo -n pct enter '101'`]);
    await closeSsh();
    await ssh.stop();
  });
});
