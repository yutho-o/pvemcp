import { mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FakeSsh, generateKey, ShellSandbox, type Distro } from './fake-ssh.js';
import { closeSsh, connectSsh, POSIX_SHELL, type SshHarness } from './ssh-harness.js';

/**
 * The container tools run for real: real SSH, a real strict shell, pct running what it is given,
 * and for each distribution the commands it has, recording how they were called. What is not
 * real is what the package managers and init systems do once called.
 */

const IS_WINDOWS = process.platform === 'win32';

describe.skipIf(!POSIX_SHELL)('container tools', () => {
  let sandbox: ShellSandbox;
  let server: FakeSsh;
  let h: SshHarness;

  beforeEach(async () => {
    sandbox = new ShellSandbox(POSIX_SHELL!);
    server = new FakeSsh({ sandbox });
    await server.start();
    h = await connectSsh({ server });
  });
  afterEach(async () => {
    await closeSsh();
    await server.stop();
    sandbox.remove();
  });

  const argvOf = (name: string) => sandbox.ctCalls(name).map((c) => c.argv.slice(1));
  const on = (distro: Distro) => sandbox.useDistro(distro);

  describe('packages, per distribution', () => {
    const MATRIX: Array<[Distro, string, { install: string[][]; installNoRefresh: string[][]; remove: string[][]; purge: string[][]; update: string[][]; command: string }]> = [
      [
        'debian',
        'apt',
        {
          command: 'apt-get',
          install: [['update', '-q'], ['install', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', '--', 'curl', 'g++']],
          installNoRefresh: [['install', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', '--', 'curl', 'g++']],
          remove: [['remove', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', '--', 'curl']],
          purge: [['purge', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', '--', 'curl']],
          update: [['update', '-q'], ['upgrade', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold']],
        },
      ],
      [
        'alpine',
        'apk',
        {
          command: 'apk',
          install: [['update', '-q'], ['add', '--no-progress', 'curl', 'g++']],
          installNoRefresh: [['add', '--no-progress', 'curl', 'g++']],
          remove: [['del', '--no-progress', 'curl']],
          purge: [['del', '--no-progress', 'curl']],
          update: [['update', '-q'], ['upgrade', '--no-progress']],
        },
      ],
      [
        'rhel',
        'dnf',
        {
          command: 'dnf',
          install: [['install', '-y', 'curl', 'g++']],
          installNoRefresh: [['install', '-y', 'curl', 'g++']],
          remove: [['remove', '-y', 'curl']],
          purge: [['remove', '-y', 'curl']],
          update: [['upgrade', '-y']],
        },
      ],
      [
        'arch',
        'pacman',
        {
          command: 'pacman',
          install: [['-Syu', '--noconfirm', '--needed', 'curl', 'g++']],
          installNoRefresh: [['-S', '--noconfirm', '--needed', 'curl', 'g++']],
          remove: [['-R', '--noconfirm', 'curl']],
          purge: [['-Rns', '--noconfirm', 'curl']],
          update: [['-Syu', '--noconfirm']],
        },
      ],
    ];

    describe.each(MATRIX)('%s', (distro, manager, want) => {
      beforeEach(() => on(distro));

      it('installs, refreshing first', async () => {
        const res = await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['curl', 'g++'] });
        expect(res.isError).toBe(false);
        expect(res.data.manager).toBe(manager);
        expect(argvOf(want.command)).toEqual(want.install);
      });

      it('installs without a refresh when told', async () => {
        await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['curl', 'g++'], refresh: false });
        expect(argvOf(want.command)).toEqual(want.installNoRefresh);
      });

      it('removes, and purges', async () => {
        await h.call('pve_lxc_remove_packages', { vmid: 101, packages: ['curl'] });
        expect(argvOf(want.command)).toEqual(want.remove);
        sandbox.clearLogs();
        await h.call('pve_lxc_remove_packages', { vmid: 101, packages: ['curl'], purge: true });
        expect(argvOf(want.command)).toEqual(want.purge);
      });

      it('upgrades', async () => {
        const res = await h.call('pve_lxc_update_packages', { vmid: 101 });
        expect(res.data.manager).toBe(manager);
        expect(argvOf(want.command)).toEqual(want.update);
      });
    });

    it('never lets debconf ask anything', async () => {
      on('debian');
      const script = await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['curl'], dry_run: true });
      expect(JSON.stringify(script.data.would_send)).toContain('DEBIAN_FRONTEND=noninteractive');
    });

    it('falls back to yum on an older RHEL', async () => {
      on('rhel');
      rmSync(join(sandbox.root, 'distro-rhel', 'dnf'));
      const res = await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['curl'] });
      expect(res.data.manager).toBe('yum');
      expect(argvOf('yum')).toEqual([['install', '-y', 'curl']]);
    });

    it('uses dist-upgrade only with full', async () => {
      on('debian');
      await h.call('pve_lxc_update_packages', { vmid: 101, full: true });
      expect(argvOf('apt-get')[1]![0]).toBe('dist-upgrade');
    });

    it('says when the container has no package manager', async () => {
      on('bare');
      for (const [tool, args] of [
        ['pve_lxc_install_packages', { vmid: 101, packages: ['curl'] }],
        ['pve_lxc_remove_packages', { vmid: 101, packages: ['curl'] }],
        ['pve_lxc_update_packages', { vmid: 101 }],
        ['pve_lxc_list_packages', { vmid: 101 }],
      ] as const) {
        const res = await h.call(tool, args);
        expect(res.data.error_type, tool).toBe('not_supported');
        expect(res.data.error).toContain('apt-get, apk, dnf, yum or pacman');
      }
    });

    it('gives a failing install as an error, with its output', async () => {
      on('alpine');
      writeFileSync(join(sandbox.root, 'distro-alpine', 'apk'), `#!${POSIX_SHELL!.name}\necho 'ERROR: unable to select packages' >&2\nexit 3\n`);
      const res = await h.call('pve_lxc_install_packages', { vmid: 101, packages: ['nope'], refresh: false });
      expect(res.data.error_type).toBe('upstream_error');
      expect(res.data.error).toContain('unable to select packages');
      expect(res.data.details.exit_code).toBe(3);
    });

    it.each<[Distro, string, Array<Record<string, unknown>>]>([
      ['debian', 'dpkg', [{ name: 'curl', version: '8.5.0-1' }, { name: 'bash', version: '5.2' }]],
      ['alpine', 'apk', [{ name: 'curl', version: '8.5.0-r0' }, { name: 'musl', version: '1.2.4-r2' }, { name: 'busybox', version: '1.36.1-r15' }]],
      ['rhel', 'rpm', [{ name: 'curl', version: '8.5.0-1.el9', arch: 'x86_64' }]],
      ['arch', 'pacman', [{ name: 'curl', version: '8.5.0-1' }, { name: 'glibc', version: '2.39-1' }]],
    ])('lists packages on %s, leaving out what is only left as configuration', async (distro, manager, rows) => {
      on(distro);
      const res = await h.call('pve_lxc_list_packages', { vmid: 101 });
      expect(res.isError).toBe(false);
      expect(res.data.manager).toBe(manager);
      expect(res.data.rows).toEqual(rows);
      expect(res.data.untrusted).toBe(true);
    });

    it('filters and pages the list', async () => {
      on('alpine');
      expect((await h.call('pve_lxc_list_packages', { vmid: 101, filter: 'cur' })).data.rows).toEqual([{ name: 'curl', version: '8.5.0-r0' }]);
      const page = await h.call('pve_lxc_list_packages', { vmid: 101, page_limit: 1, page_offset: 1 });
      expect(page.data.rows).toEqual([{ name: 'musl', version: '1.2.4-r2' }]);
    });
  });

  describe('services, per init system', () => {
    it.each<[Distro, string]>([['debian', 'systemd'], ['ubuntu', 'systemd'], ['rhel', 'systemd'], ['arch', 'systemd']])('uses systemctl on %s', async (distro, init) => {
      on(distro);
      const res = await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'restart' });
      expect(res.isError).toBe(false);
      expect(res.data.init).toBe(init);
      expect(argvOf('systemctl')).toEqual([['restart', '--', 'nginx']]);
    });

    it.each<[string, string[]]>([
      ['start', ['start']],
      ['stop', ['stop']],
      ['restart', ['restart']],
      ['reload', ['reload']],
    ])('uses rc-service on alpine to %s', async (action, want) => {
      on('alpine');
      const res = await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action });
      expect(res.data.init).toBe('openrc');
      expect(argvOf('rc-service')).toEqual([['nginx', ...want]]);
    });

    it('enables and disables through rc-update on alpine', async () => {
      on('alpine');
      await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'enable' });
      await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'disable' });
      expect(argvOf('rc-update')).toEqual([['add', 'nginx', 'default'], ['del', 'nginx', 'default']]);
    });

    it('reads the state of one service under systemd', async () => {
      on('debian');
      const res = await h.call('pve_lxc_service_status', { vmid: 101, unit: 'nginx' });
      expect(res.data).toMatchObject({ init: 'systemd', active: 'active', enabled: 'enabled', untrusted: true });
    });

    it('reads the state of one service under OpenRC, where there is no is-active', async () => {
      on('alpine');
      sandbox.flag('sshd-running');
      const res = await h.call('pve_lxc_service_status', { vmid: 101, unit: 'sshd' });
      expect(res.data).toMatchObject({ init: 'openrc', active: 'active', enabled: 'enabled' });
      expect(argvOf('rc-update')).toEqual([['show', 'default']]);
    });

    it('lists all services', async () => {
      on('debian');
      expect((await h.call('pve_lxc_service_status', { vmid: 101 })).data.output).toContain('cron.service');
      on('alpine');
      expect((await h.call('pve_lxc_service_status', { vmid: 101 })).data.output).toContain('Runlevel');
    });

    it('says when there is no service manager', async () => {
      on('bare');
      const res = await h.call('pve_lxc_service', { vmid: 101, unit: 'nginx', action: 'start' });
      expect(res.data.error_type).toBe('not_supported');
      expect((await h.call('pve_lxc_service_status', { vmid: 101 })).data.init).toBe('none');
    });
  });

  describe('users, per distribution', () => {
    it('uses useradd where shadow is installed, with every option', async () => {
      on('debian');
      const res = await h.call('pve_lxc_create_user', { vmid: 101, name: 'bob', uid: 1500, shell: '/bin/sh', home: '/home/bob', comment: 'Bob Smith', groups: ['wheel', 'adm'] });
      expect(res.data).toMatchObject({ user: 'bob', created: true });
      expect(argvOf('useradd')).toEqual([['-m', '-u', '1500', '-s', '/bin/sh', '-d', '/home/bob', '-c', 'Bob Smith', '-G', 'wheel,adm', 'bob']]);
    });

    it('uses the adduser of BusyBox on alpine, whose options differ', async () => {
      on('alpine');
      await h.call('pve_lxc_create_user', { vmid: 101, name: 'bob', uid: 1500, shell: '/bin/sh', home: '/home/bob', comment: 'Bob Smith', groups: ['wheel', 'adm'] });
      expect(argvOf('adduser')).toEqual([['-D', '-u', '1500', '-s', '/bin/sh', '-h', '/home/bob', '-g', 'Bob Smith', 'bob']]);
      expect(argvOf('addgroup')).toEqual([['bob', 'wheel'], ['bob', 'adm']]);
    });

    it('makes a system account in both', async () => {
      on('rhel');
      await h.call('pve_lxc_create_user', { vmid: 101, name: 'svc1', system: true });
      expect(argvOf('useradd')).toEqual([['-m', '-r', 'svc1']]);
      on('alpine');
      await h.call('pve_lxc_create_user', { vmid: 101, name: 'svc2', system: true });
      expect(argvOf('adduser')).toEqual([['-D', '-S', 'svc2']]);
    });

    it('deletes with userdel or deluser, with and without the home', async () => {
      on('arch');
      await h.call('pve_lxc_delete_user', { vmid: 101, name: 'bob', remove_home: true });
      await h.call('pve_lxc_delete_user', { vmid: 101, name: 'bob' });
      expect(argvOf('userdel')).toEqual([['-r', 'bob'], ['bob']]);
      on('alpine');
      await h.call('pve_lxc_delete_user', { vmid: 101, name: 'bob', remove_home: true });
      await h.call('pve_lxc_delete_user', { vmid: 101, name: 'bob' });
      expect(argvOf('deluser')).toEqual([['--remove-home', 'bob'], ['bob']]);
    });

    it('refuses to delete root', async () => {
      const res = await h.call('pve_lxc_delete_user', { vmid: 101, name: 'root' });
      expect(res.data.error_type).toBe('invalid_input');
      expect(sandbox.nodeCalls()).toEqual([]);
    });

    it('says when neither tool is there', async () => {
      on('bare');
      expect((await h.call('pve_lxc_create_user', { vmid: 101, name: 'bob' })).data.error_type).toBe('not_supported');
      expect((await h.call('pve_lxc_delete_user', { vmid: 101, name: 'bob' })).data.error_type).toBe('not_supported');
    });

    it.each<Distro>(['debian', 'alpine', 'rhel', 'arch'])('sets a password through chpasswd on stdin, on %s, and only there', async (distro) => {
      on(distro);
      const res = await h.call('pve_lxc_set_password', { vmid: 101, user: 'alice', password: `s3cret'$(touch pwned)` });
      expect(res.data).toMatchObject({ user: 'alice', changed: true });
      expect(readFileSync(sandbox.file('state/chpasswd.in'), 'utf8')).toBe(`alice:s3cret'$(touch pwned)\n`);
      expect(server.commands.at(-1)!.command).not.toContain('s3cret');
      expect(JSON.stringify(sandbox.nodeCalls())).not.toContain('s3cret');
      expect(sandbox.exists('ct/pwned')).toBe(false);
    });

    it('lists users from /etc/passwd, and leaves system accounts out on request', async () => {
      const all = await h.call('pve_lxc_list_users', { vmid: 101 });
      expect(all.data.rows.map((r: { name: string }) => r.name)).toEqual(['root', 'nobody', 'alice', 'svc']);
      expect(all.data.rows[2]).toEqual({ name: 'alice', uid: 1000, gid: 1000, comment: 'Alice', home: '/home/alice', shell: '/bin/sh' });
      const humans = await h.call('pve_lxc_list_users', { vmid: 101, include_system: false });
      expect(humans.data.rows.map((r: { name: string }) => r.name)).toEqual(['root', 'alice']);
    });
  });

  describe('read tools', () => {
    it('info gives os-release, kernel, addresses and mounts', async () => {
      const res = await h.call('pve_lxc_info', { vmid: 101 });
      expect(res.isError).toBe(false);
      expect(res.data.os).toMatchObject({ id: 'debian', version_id: '12' });
      expect(res.data.uptime_seconds).toBe(12345.67);
      expect(res.data.ips).toContainEqual({ interface: 'eth0', family: 'inet', address: '10.0.0.5/24' });
      expect(res.data.mounts[0]).toEqual({ device: '/dev/rbd0', mountpoint: '/', type: 'ext4', options: 'rw,relatime' });
    });

    it('info works with nothing but the base system', async () => {
      on('bare');
      const res = await h.call('pve_lxc_info', { vmid: 101 });
      expect(res.isError).toBe(false);
      expect(res.data.ips).toEqual([]);
    });

    it('ports use ss, then netstat, then the kernel tables', async () => {
      on('debian');
      expect((await h.call('pve_lxc_ports', { vmid: 101 })).data.output).toContain('sshd');
      expect(argvOf('ss')).toEqual([['-tulnp']]);
      on('alpine');
      expect((await h.call('pve_lxc_ports', { vmid: 101 })).data.output).toContain('LISTEN');
      expect(argvOf('netstat')).toEqual([['-tuln']]);
      on('bare');
      expect((await h.call('pve_lxc_ports', { vmid: 101 })).data.output).toContain('Neither ss nor netstat');
    });

    it('logs come from the journal under systemd', async () => {
      on('debian');
      const res = await h.call('pve_lxc_logs', { vmid: 101, unit: 'nginx', lines: 5, since: '-1h' });
      expect(res.data.source).toBe('journal');
      expect(argvOf('journalctl')).toEqual([['--no-pager', '-o', 'short-iso', '-n', '5', '-u', 'nginx', '--since=-1h']]);
    });

    it('logs come from /var/log without a journal, where BusyBox syslog puts them', async () => {
      on('alpine');
      sandbox.write('/var/log/messages', 'a nginx line\nanother line\nnginx again\n');
      const all = await h.call('pve_lxc_logs', { vmid: 101, lines: 2 });
      expect(all.data).toMatchObject({ source: '/var/log/messages', output: 'another line\nnginx again\n' });
      const one = await h.call('pve_lxc_logs', { vmid: 101, unit: 'nginx' });
      expect(one.data.output).toBe('a nginx line\nnginx again\n');
    });

    it('logs prefer the own file of a service', async () => {
      on('alpine');
      sandbox.write('/var/log/nginx/nginx.log', 'own file\n');
      sandbox.write('/var/log/messages', 'syslog\n');
      expect((await h.call('pve_lxc_logs', { vmid: 101, unit: 'nginx' })).data).toMatchObject({ source: '/var/log/nginx/nginx.log', output: 'own file\n' });
    });

    it('says when there are no logs at all', async () => {
      on('bare');
      expect((await h.call('pve_lxc_logs', { vmid: 101 })).data.error_type).toBe('not_found');
    });

    it('disk usage parses df and gives one directory', async () => {
      const res = await h.call('pve_lxc_disk_usage', { vmid: 101, path: '/etc' });
      expect(res.isError).toBe(false);
      expect(res.data.filesystems.length).toBeGreaterThan(0);
      expect(res.data.directory).toContain('/etc');
      expect(argvOf('df')).toEqual([['-hP']]);
      expect(argvOf('du')).toEqual([['-xsh', '--', '/etc']]);
    });

    it('lists a directory as rows', async () => {
      sandbox.write('/etc/app/one.conf', 'x');
      const res = await h.call('pve_lxc_list_dir', { vmid: 101, path: '/etc/app' });
      expect(res.isError).toBe(false);
      expect(res.data.rows.map((r: { name: string }) => r.name)).toEqual(['one.conf']);
      expect(res.data.rows[0].size).toBe(1);
    });

    it('reads a file, and says so when it is not a file', async () => {
      sandbox.write('/etc/app.conf', 'key=value\n');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/etc/app.conf' })).data).toMatchObject({ content: 'key=value\n', size: 10, truncated: false, untrusted: true });
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/etc' })).data.error_type).toBe('invalid_input');
      expect((await h.call('pve_lxc_read_file', { vmid: 101, path: '/etc/none' })).data.error_type).toBe('not_found');
    });

    it('refuses a file over the cap, as a typed error, unless the start of it is wanted', async () => {
      sandbox.write('/tmp/big.log', 'x'.repeat(5000));
      const refused = await h.call('pve_lxc_read_file', { vmid: 101, path: '/tmp/big.log', max_bytes: 1024 });
      expect(refused.data.error_type).toBe('ssh_output_too_large');
      expect(refused.data.details).toEqual({ size: 5000, limit: 1024 });
      const partial = await h.call('pve_lxc_read_file', { vmid: 101, path: '/tmp/big.log', max_bytes: 1024, allow_partial: true });
      expect(partial.data).toMatchObject({ truncated: true, size: 5000 });
      expect(partial.data.content).toHaveLength(1024);
      expect(argvOf('head')).toContainEqual(['-c', '1024', '--', '/tmp/big.log']);
    });

    it('marks a binary file instead of passing it off as text', async () => {
      sandbox.write('/tmp/bin', Buffer.from([0xff, 0xfe, 0x41]));
      const res = await h.call('pve_lxc_read_file', { vmid: 101, path: '/tmp/bin' });
      expect(res.data.binary).toBe(true);
      expect(res.data.hint).toContain('pull_file');
    });
  });

  describe('a container that is not running', () => {
    beforeEach(() => sandbox.stopGuest(101));

    it.each<[string, Record<string, unknown>]>([
      ['pve_lxc_exec', { vmid: 101, command: 'id' }],
      ['pve_lxc_run_script', { vmid: 101, script: 'id' }],
      ['pve_lxc_read_file', { vmid: 101, path: '/etc/hostname' }],
      ['pve_lxc_write_file', { vmid: 101, path: '/tmp/x', content: 'y' }],
      ['pve_lxc_delete_file', { vmid: 101, path: '/tmp/x' }],
      ['pve_lxc_info', { vmid: 101 }],
      ['pve_lxc_processes', { vmid: 101 }],
      ['pve_lxc_ports', { vmid: 101 }],
      ['pve_lxc_disk_usage', { vmid: 101 }],
      ['pve_lxc_logs', { vmid: 101 }],
      ['pve_lxc_list_dir', { vmid: 101, path: '/' }],
      ['pve_lxc_service_status', { vmid: 101 }],
      ['pve_lxc_service', { vmid: 101, unit: 'x', action: 'start' }],
      ['pve_lxc_list_packages', { vmid: 101 }],
      ['pve_lxc_install_packages', { vmid: 101, packages: ['x'] }],
      ['pve_lxc_remove_packages', { vmid: 101, packages: ['x'] }],
      ['pve_lxc_update_packages', { vmid: 101 }],
      ['pve_lxc_list_users', { vmid: 101 }],
      ['pve_lxc_create_user', { vmid: 101, name: 'x' }],
      ['pve_lxc_delete_user', { vmid: 101, name: 'x' }],
      ['pve_lxc_set_password', { vmid: 101, user: 'x', password: 'y' }],
      ['pve_lxc_fstrim', { vmid: 101 }],
      ['pve_lxc_ssh_status', { vmid: 101 }],
      ['pve_lxc_ssh_list_keys', { vmid: 101 }],
      ['pve_lxc_ssh_enable', { vmid: 101 }],
      ['pve_lxc_ssh_disable', { vmid: 101 }],
      ['pve_lxc_ssh_add_key', { vmid: 101, public_key: generateKey().public }],
      ['pve_lxc_ssh_remove_key', { vmid: 101, public_key: generateKey().public }],
      ['pve_lxc_ssh_configure', { vmid: 101, port: 2222 }],
    ])('%s gives guest_not_running', async (tool, args) => {
      const res = await h.call(tool, args);
      expect(res.isError).toBe(true);
      expect(res.data.error_type).toBe('guest_not_running');
      expect(res.data.hint).toContain('starts it');
    });

    it('pct push and pull say the same, in their own words, and the temp file still goes', async () => {
      writeFileSync(join(h.localDir, 'f.txt'), 'x');
      sandbox.startGuest(101);
      sandbox.write('/etc/f', 'x');
      sandbox.stopGuest(101);
      expect((await h.call('pve_lxc_push_file', { vmid: 101, local_path: 'f.txt', path: '/tmp/x' })).data.error_type).toBe('guest_not_running');
      expect(readdirSync(sandbox.file('/tmp')).filter((n) => n.startsWith('pvemcp-'))).toEqual([]);
    });

    it('fsck works on it, and only on it', async () => {
      const res = await h.call('pve_lxc_fsck', { vmid: 101 });
      expect(res.isError).toBe(false);
      expect(res.data.stdout).toContain('rootfs: clean');
      sandbox.startGuest(101);
      const running = await h.call('pve_lxc_fsck', { vmid: 101 });
      expect(running.data.error_type).toBe('invalid_input');
      expect(running.data.error).toContain('needs it stopped');
    });
  });

  it('a locked container gives guest_locked', async () => {
    sandbox.flag('locked-101');
    const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'id' });
    expect(res.data.error_type).toBe('guest_locked');
    expect(res.data.error).toContain('backup');
  });

  it('a command printing what pct prints does not read as pct', async () => {
    const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'echo CT 101 not running; exit 0' });
    expect(res.isError).toBe(false);
    expect(res.data.exit_code).toBe(0);
  });

  it('a VM is not something pct reaches', async () => {
    const res = await h.call('pve_lxc_exec', { vmid: 100, command: 'id' });
    expect(res.data.error_type).toBe('invalid_input');
    expect(res.data.hint).toContain('pve_guest_ssh_exec');
    expect(sandbox.nodeCalls()).toEqual([]);
  });

  it('a wrong node is refused before anything runs', async () => {
    const res = await h.call('pve_lxc_exec', { vmid: 101, node: 'pve2', command: 'id' });
    expect(res.data.error_type).toBe('invalid_input');
    expect(sandbox.nodeCalls()).toEqual([]);
  });

  describe('exec', () => {
    it('reports a non-zero exit as an answer, not as an error', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'echo out; echo err >&2; exit 7' });
      expect(res.isError).toBe(false);
      expect(res.data).toMatchObject({ stdout: 'out\n', stderr: 'err\n', exit_code: 7, truncated: false, timed_out: false, untrusted: true, vmid: 101, node: 'pve1' });
    });

    it('runs in the directory asked for', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'pwd', cwd: '/etc/ssh' });
      expect(res.data.stdout.trim()).toBe('/etc/ssh');
    });

    it('feeds stdin', async () => {
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'cat', stdin: 'piped' })).data.stdout).toBe('piped');
    });

    it('sees the end of stdin at once when there is none', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'cat', timeout_seconds: 20 });
      expect(res.data).toMatchObject({ stdout: '', exit_code: 0, timed_out: false });
    });

    it('runs scripts through a real interpreter, on stdin, with argv', async () => {
      const res = await h.call('pve_lxc_run_script', { vmid: 101, script: 'echo "$# $1 $2"\nexit 3\n', args: ['a b', '-c'] });
      expect(res.data).toMatchObject({ stdout: '2 a b -c\n', exit_code: 3 });
      const pct = sandbox.nodeCalls().find((c) => c.argv[0] === 'pct')!;
      expect(pct.argv).toEqual(['pct', 'exec', '101', '--', 'sh', '-s', '--', 'a b', '-c']);
    });

    it('stops at the timeout, as a typed error with what came before', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'echo before; sleep 2', timeout_seconds: 1 });
      expect(res.data.error_type).toBe('ssh_timeout');
      expect(res.data.details.stdout).toContain('before');
      expect(server.signals).toContain('TERM');
    }, 20_000);

    it('keeps the start of too much output, flagged', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: `i=0; while [ $i -lt 2000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done`, max_output_bytes: 1024 });
      expect(res.isError).toBe(false);
      expect(res.data.truncated).toBe(true);
      expect(res.data.stdout).toHaveLength(1024);
      expect(res.data.exit_code).toBe(0);
    });
  });

  describe('files', () => {
    it('writes a new file whole, with 644 by default, and leaves no temp file', async () => {
      const res = await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/app.conf', content: 'a=1\n' });
      expect(res.data).toMatchObject({ path: '/etc/app.conf', bytes: 4 });
      expect(sandbox.read('/etc/app.conf')).toBe('a=1\n');
      expect(argvOf('chmod')[0]![0]).toBe('644');
      expect(readdirSync(sandbox.file('/etc')).filter((n) => n.includes('pvemcp'))).toEqual([]);
    });

    it('keeps the mode and owner of an existing file', async () => {
      sandbox.write('/etc/app.conf', 'old');
      await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/app.conf', content: 'new' });
      expect(sandbox.read('/etc/app.conf')).toBe('new');
      expect(argvOf('stat')).toEqual([['-c', '%a', '/etc/app.conf'], ['-c', '%u:%g', '/etc/app.conf']]);
      expect(argvOf('chmod').length).toBe(1);
      expect(argvOf('chown').length).toBe(1);
    });

    it('sets the mode and owner it is told to, and keeps a backup', async () => {
      sandbox.write('/etc/app.conf', 'old');
      const res = await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/app.conf', content: 'new', mode: '0600', owner: 'alice:alice', backup: true });
      expect(res.data.backup).toMatch(/^\/etc\/app\.conf\.bak\.\d{14}$/);
      expect(sandbox.read(res.data.backup)).toBe('old');
      expect(argvOf('chmod').at(-1)![0]).toBe('0600');
      expect(argvOf('chown').at(-1)![0]).toBe('alice:alice');
    });

    it('writes base64 as bytes', async () => {
      await h.call('pve_lxc_write_file', { vmid: 101, path: '/tmp/b', content: Buffer.from([0, 1, 254, 255]).toString('base64'), encoding: 'base64' });
      expect(readFileSync(sandbox.file('/tmp/b')).equals(Buffer.from([0, 1, 254, 255]))).toBe(true);
    });

    it('wants the directory to exist, unless told to create it', async () => {
      const res = await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/new/deep/f', content: 'x' });
      expect(res.data.error_type).toBe('not_found');
      expect(res.data.hint).toContain('create_parents');
      expect((await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/new/deep/f', content: 'x', create_parents: true })).isError).toBe(false);
      expect(sandbox.read('/etc/new/deep/f')).toBe('x');
    });

    it('refuses to write over a directory', async () => {
      expect((await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc', content: 'x' })).isError).toBe(true);
    });

    it('keeps the content out of the command, and removes the temp file when the write fails', async () => {
      writeFileSync(join(sandbox.root, 'core', 'mv'), `#!${POSIX_SHELL!.name}\nexit 1\n`);
      const res = await h.call('pve_lxc_write_file', { vmid: 101, path: '/etc/app.conf', content: 'TOP-SECRET-CONTENT' });
      expect(res.isError).toBe(true);
      expect(res.data.error).not.toContain('TOP-SECRET-CONTENT');
      expect(server.commands.at(-1)!.command).not.toContain('TOP-SECRET-CONTENT');
      expect(readdirSync(sandbox.file('/etc')).filter((n) => n.includes('pvemcp'))).toEqual([]);
      expect(sandbox.exists('/etc/app.conf')).toBe(false);
    });

    it('deletes one file, and says when it was not there', async () => {
      sandbox.write('/tmp/d', 'x');
      expect((await h.call('pve_lxc_delete_file', { vmid: 101, path: '/tmp/d' })).data.deleted).toBe(true);
      expect(sandbox.exists('/tmp/d')).toBe(false);
      expect((await h.call('pve_lxc_delete_file', { vmid: 101, path: '/tmp/d' })).data.error_type).toBe('not_found');
      expect((await h.call('pve_lxc_delete_file', { vmid: 101, path: '/tmp/d', missing_ok: true })).data.deleted).toBe(true);
    });

    it('never deletes a directory', async () => {
      const res = await h.call('pve_lxc_delete_file', { vmid: 101, path: '/etc/ssh' });
      expect(res.isError).toBe(true);
      expect(sandbox.exists('/etc/ssh')).toBe(true);
    });
  });

  describe('pct syntax of the node commands', () => {
    const pct = () => sandbox.nodeCalls().filter((c) => c.argv[0] === 'pct').map((c) => c.argv.slice(1));
    const temps = () => readdirSync(sandbox.file('/tmp')).filter((n) => n.startsWith('pvemcp-'));

    it('push: vmid, file, target, then options', async () => {
      writeFileSync(join(h.localDir, 'f.txt'), 'pushed');
      const res = await h.call('pve_lxc_push_file', { vmid: 101, local_path: 'f.txt', path: '/etc/f.txt', mode: '0640', user: 'alice', group: 'adm' });
      expect(res.data).toMatchObject({ path: '/etc/f.txt', bytes: 6 });
      const [call] = pct();
      expect(call!.slice(0, 2)).toEqual(['push', '101']);
      expect(call![2]).toMatch(/^\/tmp\/pvemcp-[0-9a-f-]{36}$/);
      expect(call!.slice(3)).toEqual(['/etc/f.txt', '--perms', '0640', '--user', 'alice', '--group', 'adm']);
      expect(sandbox.read('/etc/f.txt')).toBe('pushed');
    });

    it('push: the file on the node is private, and always goes', async () => {
      writeFileSync(join(h.localDir, 'f.txt'), 'pushed');
      await h.call('pve_lxc_push_file', { vmid: 101, local_path: 'f.txt', path: '/etc/f.txt' });
      const opened = server.sftpOps.find((o) => o.op === 'open' || o.op === 'fsetstat');
      expect(opened).toBeDefined();
      expect(server.sftpOps.filter((o) => o.mode !== undefined).every((o) => (o.mode! & 0o777) === 0o600)).toBe(true);
      expect(temps()).toEqual([]);
    });

    it('push: the temp file goes when pct fails too', async () => {
      writeFileSync(join(h.localDir, 'f.txt'), 'x');
      const res = await h.call('pve_lxc_push_file', { vmid: 101, local_path: 'f.txt', path: '/nonexistent-top/deep/f' });
      expect(res.isError).toBe(true);
      expect(temps()).toEqual([]);
      expect(server.commands.some((c) => /^rm -f -- '\/tmp\/pvemcp-/.test(c.command))).toBe(true);
    });

    it('pull: vmid, path, destination, private on the node, and gone afterwards', async () => {
      sandbox.write('/etc/out.txt', 'pulled');
      const res = await h.call('pve_lxc_pull_file', { vmid: 101, path: '/etc/out.txt', local_path: 'out.txt' });
      expect(res.isError).toBe(false);
      expect(res.data.bytes).toBe(6);
      expect(readFileSync(join(h.localDir, 'out.txt'), 'utf8')).toBe('pulled');
      const call = pct().find((c) => c[0] === 'pull')!;
      expect(call.slice(0, 3)).toEqual(['pull', '101', '/etc/out.txt']);
      expect(call[3]).toMatch(/^\/tmp\/pvemcp-/);
      expect(call.slice(4)).toEqual(['--perms', '0600']);
      expect(temps()).toEqual([]);
    });

    it('pull: refuses to replace a local file unless told', async () => {
      sandbox.write('/etc/out.txt', 'pulled');
      writeFileSync(join(h.localDir, 'out.txt'), 'mine');
      expect((await h.call('pve_lxc_pull_file', { vmid: 101, path: '/etc/out.txt', local_path: 'out.txt' })).data.error_type).toBe('local_path_refused');
      expect(readFileSync(join(h.localDir, 'out.txt'), 'utf8')).toBe('mine');
      expect((await h.call('pve_lxc_pull_file', { vmid: 101, path: '/etc/out.txt', local_path: 'out.txt', overwrite: true })).isError).toBe(false);
      expect(readFileSync(join(h.localDir, 'out.txt'), 'utf8')).toBe('pulled');
    });

    it('fsck, with device and force', async () => {
      sandbox.stopGuest(101);
      await h.call('pve_lxc_fsck', { vmid: 101 });
      await h.call('pve_lxc_fsck', { vmid: 101, device: 'mp0', force: true });
      expect(pct()).toEqual([['fsck', '101'], ['fsck', '101', '--device', 'mp0', '--force', '1']]);
    });

    it('fstrim, with and without mount points', async () => {
      await h.call('pve_lxc_fstrim', { vmid: 101 });
      await h.call('pve_lxc_fstrim', { vmid: 101, ignore_mountpoints: true });
      expect(pct()).toEqual([['fstrim', '101'], ['fstrim', '101', '--ignore-mountpoints', '1']]);
    });

    it('mount and unmount', async () => {
      const mounted = await h.call('pve_lxc_mount', { vmid: 101 });
      expect(mounted.data).toMatchObject({ mounted_at: '/var/lib/lxc/101/rootfs', next_step: 'pve_lxc_unmount' });
      await h.call('pve_lxc_unmount', { vmid: 101 });
      expect(pct()).toEqual([['mount', '101'], ['unmount', '101']]);
    });

    it('list reads the lock column, which the API list does not have', async () => {
      const res = await h.call('pve_ssh_pct_list', { node: 'pve1' });
      expect(res.data.rows).toEqual([{ vmid: 101, status: 'running', name: 'db' }, { vmid: 103, status: 'stopped', lock: 'backup', name: 'old' }]);
    });
  });

  describe('sshd', () => {
    const SSHD_MAIN = 'Port 22\n#PermitRootLogin yes\nPasswordAuthentication yes\nSubsystem sftp internal-sftp\n';
    const SSHD_INCLUDE = `Include /etc/ssh/sshd_config.d/*.conf\n${SSHD_MAIN}`;

    describe('enable', () => {
      it.each<[Distro, string, string[][]]>([
        ['debian', 'apt-get', [['update', '-q'], ['install', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', '--', 'openssh-server']]],
        ['alpine', 'apk', [['update', '-q'], ['add', '--no-progress', 'openssh']]],
        ['rhel', 'dnf', [['install', '-y', 'openssh-server']]],
        ['arch', 'pacman', [['-Syu', '--noconfirm', '--needed', 'openssh']]],
      ])('installs on %s when it is missing', async (distro, manager, calls) => {
        on(distro);
        const res = await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(res.isError).toBe(false);
        expect(res.data).toMatchObject({ enabled: true, installed_now: true });
        expect(argvOf(manager)).toEqual(calls);
      });

      it('does not install when it is there, and is safe to repeat', async () => {
        on('debian');
        sandbox.installSshd();
        const res = await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(res.data.installed_now).toBe(false);
        expect(argvOf('apt-get')).toEqual([]);
        expect((await h.call('pve_lxc_ssh_enable', { vmid: 101 })).isError).toBe(false);
      });

      it('creates missing host keys', async () => {
        on('debian');
        sandbox.installSshd();
        await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(argvOf('ssh-keygen')).toEqual([['-A']]);
      });

      it.each<[Distro, string[]]>([['debian', ['enable', '--now', 'ssh']], ['rhel', ['enable', '--now', 'sshd']], ['arch', ['enable', '--now', 'sshd']]])('names the unit right on %s', async (distro, want) => {
        on(distro);
        sandbox.installSshd();
        await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(argvOf('systemctl')).toContainEqual(want);
      });

      it('starts the socket on an Ubuntu that uses one, leaving the service alone', async () => {
        on('ubuntu');
        sandbox.installSshd();
        await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(argvOf('systemctl')).toContainEqual(['start', 'ssh.socket']);
        expect(argvOf('systemctl').filter((a) => a[0] === 'enable')).toEqual([]);
      });

      it('uses rc-update and rc-service on alpine', async () => {
        on('alpine');
        sandbox.installSshd();
        const res = await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(res.data.init).toBe('openrc');
        expect(argvOf('rc-update')).toEqual([['add', 'sshd', 'default']]);
        expect(argvOf('rc-service')).toEqual([['sshd', 'start']]);
      });

      it('starts the daemon itself with no service manager', async () => {
        on('bare');
        sandbox.installSshd();
        const res = await h.call('pve_lxc_ssh_enable', { vmid: 101 });
        expect(res.data.init).toBe('none');
        expect(sandbox.exists('state/sshd-running')).toBe(true);
      });

      it('says when it cannot install', async () => {
        on('bare');
        expect((await h.call('pve_lxc_ssh_enable', { vmid: 101 })).data.error_type).toBe('not_supported');
      });
    });

    describe('disable', () => {
      it('stops and disables under systemd', async () => {
        on('debian');
        expect((await h.call('pve_lxc_ssh_disable', { vmid: 101 })).data).toMatchObject({ disabled: true, init: 'systemd' });
        expect(argvOf('systemctl')).toContainEqual(['disable', '--now', 'ssh']);
      });

      it('takes the socket with it on Ubuntu', async () => {
        on('ubuntu');
        await h.call('pve_lxc_ssh_disable', { vmid: 101 });
        expect(argvOf('systemctl')).toContainEqual(['disable', '--now', 'ssh.socket']);
        expect(argvOf('systemctl')).toContainEqual(['disable', '--now', 'ssh']);
      });

      it('stops and removes from the runlevel under OpenRC', async () => {
        on('alpine');
        await h.call('pve_lxc_ssh_disable', { vmid: 101 });
        expect(argvOf('rc-service')).toEqual([['sshd', 'stop']]);
        expect(argvOf('rc-update')).toEqual([['del', 'sshd', 'default']]);
      });

      it('says when it cannot', async () => {
        on('bare');
        expect((await h.call('pve_lxc_ssh_disable', { vmid: 101 })).data.error_type).toBe('not_supported');
      });
    });

    describe('status', () => {
      it('shows what is installed, running and in force', async () => {
        on('debian');
        sandbox.installSshd();
        sandbox.flag('sshd-running');
        sandbox.write('/etc/ssh/sshd_config', 'Port 22\nPort 2222\nPermitRootLogin no\n');
        const res = await h.call('pve_lxc_ssh_status', { vmid: 101 });
        expect(res.data).toMatchObject({ installed: true, running: true, init: 'systemd', ports: [22, 2222], untrusted: true });
        expect(res.data.effective.permitrootlogin).toBe('no');
      });

      it('shows when it is not installed', async () => {
        on('alpine');
        expect((await h.call('pve_lxc_ssh_status', { vmid: 101 })).data).toMatchObject({ installed: false, running: false, ports: [], init: 'openrc' });
      });

      it('says a socket counts as running', async () => {
        on('ubuntu');
        sandbox.installSshd();
        expect((await h.call('pve_lxc_ssh_status', { vmid: 101 })).data).toMatchObject({ running: true, socket_activated: true });
      });
    });

    describe('configure', () => {
      beforeEach(() => {
        on('debian');
        sandbox.installSshd();
      });

      it('uses a drop-in where sshd_config includes one', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_INCLUDE);
        sandbox.write('/etc/ssh/sshd_config.d/50-other.conf', '# nothing set here\n');
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no', password_authentication: false });
        expect(res.isError).toBe(false);
        expect(res.data).toMatchObject({ layout: 'dropin', effective: ['permitrootlogin no', 'passwordauthentication no'] });
        expect(sandbox.read('/etc/ssh/sshd_config.d/00-pvemcp.conf')).toBe('PermitRootLogin no\nPasswordAuthentication no\n');
        expect(sandbox.read('/etc/ssh/sshd_config')).toBe(SSHD_INCLUDE);
      });

      it('changes a setting again without piling up', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_INCLUDE);
        sandbox.write('/etc/ssh/sshd_config.d/placeholder', '');
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no', pubkey_authentication: true });
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'prohibit-password' });
        expect(sandbox.read('/etc/ssh/sshd_config.d/00-pvemcp.conf')).toBe('PubkeyAuthentication yes\nPermitRootLogin prohibit-password\n');
      });

      it('uses a block at the top of a sshd_config with no Include', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        expect(res.isError).toBe(false);
        expect(res.data.layout).toBe('main');
        expect(sandbox.read('/etc/ssh/sshd_config')).toBe(`# BEGIN pvemcp\nPermitRootLogin no\n# END pvemcp\n${SSHD_MAIN}`);
      });

      it('replaces its own block the next time, leaving the rest', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'yes', password_authentication: false });
        expect(sandbox.read('/etc/ssh/sshd_config')).toBe(`# BEGIN pvemcp\nPermitRootLogin yes\nPasswordAuthentication no\n# END pvemcp\n${SSHD_MAIN}`);
      });

      it('takes out other Port lines, since those add up', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, port: 2222 });
        expect(res.isError).toBe(false);
        expect(res.data.effective).toEqual(['port 2222']);
        expect(sandbox.read('/etc/ssh/sshd_config')).not.toContain('Port 22\n');
      });

      it('puts the old file back when sshd -t refuses, drop-in layout', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_INCLUDE);
        sandbox.write('/etc/ssh/sshd_config.d/00-pvemcp.conf', 'PubkeyAuthentication yes\n');
        sandbox.flag('sshd-t-fails');
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        expect(res.data.error_type).toBe('invalid_input');
        expect(res.data.error).toContain('Bad configuration option');
        expect(res.data.hint).toContain('back in place');
        expect(sandbox.read('/etc/ssh/sshd_config.d/00-pvemcp.conf')).toBe('PubkeyAuthentication yes\n');
      });

      it('removes a new drop-in when sshd -t refuses', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_INCLUDE);
        sandbox.write('/etc/ssh/sshd_config.d/placeholder', '');
        sandbox.flag('sshd-t-fails');
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        expect(sandbox.exists('/etc/ssh/sshd_config.d/00-pvemcp.conf')).toBe(false);
      });

      it('puts the old file back when sshd -t refuses, main layout', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        sandbox.flag('sshd-t-fails');
        expect((await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' })).isError).toBe(true);
        expect(sandbox.read('/etc/ssh/sshd_config')).toBe(SSHD_MAIN);
      });

      it('puts the old file back when another file wins, and says which setting', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_INCLUDE);
        // Reads first by name, and sshd keeps the first value: 00- is not the first if 00-a is there.
        sandbox.write('/etc/ssh/sshd_config.d/00-a.conf', 'PermitRootLogin yes\n');
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        expect(res.data.error_type).toBe('upstream_error');
        expect(res.data.error).toContain('PermitRootLogin');
        expect(res.data.hint).toContain('back in place');
        expect(sandbox.exists('/etc/ssh/sshd_config.d/00-pvemcp.conf')).toBe(false);
      });

      it('puts the old file back when the reload fails, and reloads that', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        sandbox.flag('reload-fails');
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        expect(res.data.error_type).toBe('upstream_error');
        expect(res.data.error).toContain('could not reload');
        expect(sandbox.read('/etc/ssh/sshd_config')).toBe(SSHD_MAIN);
      });

      it('leaves no temp files, whatever happens', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'no' });
        sandbox.flag('sshd-t-fails');
        await h.call('pve_lxc_ssh_configure', { vmid: 101, permit_root_login: 'yes' });
        expect(readdirSync(sandbox.file('/tmp')).filter((n) => n.includes('pvemcp'))).toEqual([]);
      });

      it('reports whether anything had to reload, per init system', async () => {
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        const debian = await h.call('pve_lxc_ssh_configure', { vmid: 101, port: 2222 });
        // The stub of systemctl answers active for the unit of this distribution.
        expect(debian.data.reloaded).toBe(true);
        expect(argvOf('systemctl')).toContainEqual(['reload-or-restart', 'ssh']);
        sandbox.clearLogs();
        on('alpine');
        sandbox.installSshd();
        const stopped = await h.call('pve_lxc_ssh_configure', { vmid: 101, port: 2223 });
        expect(stopped.data.reloaded).toBe(false);
        sandbox.flag('sshd-running');
        const running = await h.call('pve_lxc_ssh_configure', { vmid: 101, port: 2224 });
        expect(running.data.reloaded).toBe(true);
        expect(argvOf('rc-service')).toContainEqual(['sshd', 'reload']);
      });

      it('wants at least one setting', async () => {
        expect((await h.call('pve_lxc_ssh_configure', { vmid: 101 })).data.error_type).toBe('invalid_input');
      });

      it('says so when sshd is not there', async () => {
        on('alpine');
        sandbox.write('/etc/ssh/sshd_config', SSHD_MAIN);
        const res = await h.call('pve_lxc_ssh_configure', { vmid: 101, port: 2222 });
        expect(res.data.error_type).toBe('not_found');
      });
    });

    describe('authorized keys', () => {
      const key = generateKey('ed25519', { comment: 'me@laptop' });
      const other = generateKey('ed25519', { comment: 'other' });

      it('adds a key, with the modes and owner sshd insists on', async () => {
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public, user: 'alice' });
        expect(res.data).toMatchObject({ user: 'alice', added: true, fingerprint: key.fingerprint });
        expect(sandbox.read('/home/alice/.ssh/authorized_keys')).toBe(`${key.public}\n`);
        const chmods = argvOf('chmod');
        expect(chmods).toContainEqual(['700', '/home/alice/.ssh']);
        expect(chmods).toContainEqual(['600', '/home/alice/.ssh/authorized_keys']);
        expect(argvOf('chown')).toEqual([['-h', '1000:1000', '/home/alice/.ssh', '/home/alice/.ssh/authorized_keys']]);
      });

      it('adding the same key again changes nothing', async () => {
        await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public });
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public });
        expect(res.data.added).toBe(false);
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe(`${key.public}\n`);
      });

      it('is the same key under another comment', async () => {
        await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public });
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: `${key.public.split(' ').slice(0, 2).join(' ')} different comment` });
        expect(res.data.added).toBe(false);
      });

      it('keeps what is there, even without a last newline', async () => {
        sandbox.write('/root/.ssh/authorized_keys', other.public);
        await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public });
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe(`${other.public}\n${key.public}\n`);
      });

      it('lists keys with fingerprints, and counts what it cannot read', async () => {
        sandbox.write('/root/.ssh/authorized_keys', `# a comment\nfrom="10.0.0.1" ${key.public}\nnot a key\n`);
        const res = await h.call('pve_lxc_ssh_list_keys', { vmid: 101 });
        expect(res.data.unparsed).toBe(1);
        expect(res.data.keys).toHaveLength(1);
        expect(res.data.keys[0]).toMatchObject({ type: 'ssh-ed25519', fingerprint: key.fingerprint, comment: 'me@laptop', options: 'from="10.0.0.1"' });
      });

      it('lists nothing when there is no file', async () => {
        expect((await h.call('pve_lxc_ssh_list_keys', { vmid: 101, user: 'alice' })).data).toMatchObject({ keys: [], unparsed: 0 });
      });

      it('says so for an unknown user', async () => {
        expect((await h.call('pve_lxc_ssh_list_keys', { vmid: 101, user: 'ghost' })).data.error_type).toBe('not_found');
        expect((await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public, user: 'ghost' })).data.error_type).toBe('not_found');
      });

      it('finds a user by exact name: a regex in the name finds nobody', async () => {
        expect((await h.call('pve_lxc_ssh_list_keys', { vmid: 101, user: 'r.ot' })).data.error_type).toBe('not_found');
      });

      it('removes by public key, keeping the others', async () => {
        sandbox.write('/root/.ssh/authorized_keys', `${other.public}\n${key.public}\n`);
        const res = await h.call('pve_lxc_ssh_remove_key', { vmid: 101, public_key: key.public });
        expect(res.data.removed).toBe(1);
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe(`${other.public}\n`);
      });

      it('removes by fingerprint', async () => {
        sandbox.write('/root/.ssh/authorized_keys', `${other.public}\n${key.public}\n`);
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, fingerprint: key.fingerprint })).data.removed).toBe(1);
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe(`${other.public}\n`);
      });

      it('removes the last key, leaving an empty file', async () => {
        sandbox.write('/root/.ssh/authorized_keys', `${key.public}\n`);
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, public_key: key.public })).data.removed).toBe(1);
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe('');
      });

      it('removes nothing when it is not there', async () => {
        sandbox.write('/root/.ssh/authorized_keys', `${other.public}\n`);
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, public_key: key.public })).data.removed).toBe(0);
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, fingerprint: key.fingerprint })).data.removed).toBe(0);
        expect(sandbox.read('/root/.ssh/authorized_keys')).toBe(`${other.public}\n`);
      });

      it('wants exactly one way of naming the key', async () => {
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101 })).data.error_type).toBe('invalid_input');
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, public_key: key.public, fingerprint: key.fingerprint })).data.error_type).toBe('invalid_input');
      });

      it.each([
        ['a private key', generateKey().private],
        ['several lines', `${key.public}\n${other.public}`],
        ['an options prefix', `command="reboot" ${key.public}`],
        ['a wrong type', `ssh-rsa ${key.blob.toString('base64')}`],
        ['no key data', 'ssh-ed25519'],
        ['a shell payload', `ssh-ed25519 $(reboot)`],
      ])('refuses %s, before anything runs', async (_name, public_key) => {
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key });
        expect(res.data.error_type).toBe('invalid_input');
        expect(sandbox.nodeCalls()).toEqual([]);
      });

      it('never echoes a private key it was handed', async () => {
        const secret = generateKey();
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: secret.private });
        expect(res.text).not.toContain(secret.private.split('\n')[1]);
      });

      /** A directory link needs no privilege on Windows, and root follows any kind. */
      const plant = (target: string, path: string) => symlinkSync(sandbox.file(target), sandbox.file(path), IS_WINDOWS ? 'junction' : 'dir');

      it('refuses a link at ~/.ssh, and leaves its target alone', async () => {
        sandbox.write('/etc/victim/keep', 'x');
        plant('/etc/victim', '/home/alice/.ssh');
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public, user: 'alice' });
        expect(res.data.error_type).toBe('invalid_input');
        expect(res.data.hint).toContain('link');
        expect(sandbox.exists('/etc/victim/authorized_keys')).toBe(false);
        expect(argvOf('chmod')).toEqual([]);
        sandbox.write('/etc/victim/authorized_keys', `${key.public}
`);
        expect((await h.call('pve_lxc_ssh_remove_key', { vmid: 101, public_key: key.public, user: 'alice' })).data.error_type).toBe('invalid_input');
        expect(sandbox.read('/etc/victim/authorized_keys')).toBe(`${key.public}
`);
      });

      it('refuses a link at authorized_keys, and leaves its target alone', async () => {
        sandbox.write('/etc/victim/keep', 'x');
        mkdirSync(sandbox.file('/home/alice/.ssh'), { recursive: true });
        plant('/etc/victim', '/home/alice/.ssh/authorized_keys');
        const res = await h.call('pve_lxc_ssh_add_key', { vmid: 101, public_key: key.public, user: 'alice' });
        expect(res.data.error_type).toBe('invalid_input');
        expect(argvOf('chmod')).toEqual([]);
        expect(readdirSync(sandbox.file('/etc/victim'))).toEqual(['keep']);
      });
    });
  });

  describe('options BusyBox really has', () => {
    /**
     * No BusyBox can run here, so this is a table. It is what BusyBox 1.36 applets take, read from
     * their usage, for the applets the scripts use on Alpine. A flag not here would fail only there.
     */
    const BUSYBOX: Record<string, { flags: string; long?: string[] }> = {
      cat: { flags: '' },
      head: { flags: 'cn' },
      tail: { flags: 'cn' },
      wc: { flags: 'clw' },
      tr: { flags: 'd' },
      ls: { flags: 'la' },
      rm: { flags: 'f' },
      mv: { flags: 'f' },
      cp: { flags: 'p' },
      mkdir: { flags: 'p' },
      mktemp: { flags: '' },
      readlink: { flags: 'f' },
      stat: { flags: 'c' },
      date: { flags: '' },
      df: { flags: 'hP' },
      du: { flags: 'xsh' },
      ps: { flags: 'eo' },
      uname: { flags: 'srm' },
      hostname: { flags: '' },
      id: { flags: 'un' },
      grep: { flags: 'qixcFEvwe' },
      sed: { flags: 'ne' },
      chmod: { flags: '' },
      chown: { flags: 'h' },
      su: { flags: 'sc' },
      adduser: { flags: 'DSushg' },
      deluser: { flags: '', long: ['--remove-home'] },
      addgroup: { flags: '' },
      chpasswd: { flags: '' },
      netstat: { flags: 'tuln' },
      ip: { flags: 'o' },
      pgrep: { flags: 'x' },
      'ssh-keygen': { flags: 'A' },
      sshd: { flags: 'tT' },
      // Not BusyBox, but what Alpine has: apk and OpenRC take these.
      apk: { flags: 'qv', long: ['--no-progress'] },
      'rc-service': { flags: '' },
      'rc-update': { flags: '' },
      'rc-status': { flags: '', long: ['--all'] },
      spy: { flags: '' },
    };

    it('every call made on Alpine, by every tool that runs there, has only those', async () => {
      on('alpine');
      sandbox.installSshd();
      sandbox.write('/etc/ssh/sshd_config', 'Port 22\n');
      sandbox.write('/etc/app.conf', 'x\n');
      sandbox.write('/var/log/messages', 'nginx line\n');
      sandbox.write('/root/.ssh/authorized_keys', `${generateKey().public}\n`);
      sandbox.flag('sshd-running');
      const key = generateKey();
      const calls: Array<[string, Record<string, unknown>]> = [
        ['pve_lxc_info', {}],
        ['pve_lxc_processes', {}],
        ['pve_lxc_ports', {}],
        ['pve_lxc_disk_usage', { path: '/etc' }],
        ['pve_lxc_logs', {}],
        ['pve_lxc_logs', { unit: 'nginx', since: '-1h' }],
        ['pve_lxc_list_dir', { path: '/etc' }],
        ['pve_lxc_read_file', { path: '/etc/app.conf' }],
        ['pve_lxc_read_file', { path: '/etc/app.conf', max_bytes: 1, allow_partial: true }],
        ['pve_lxc_service_status', {}],
        ['pve_lxc_service_status', { unit: 'sshd' }],
        ['pve_lxc_list_packages', {}],
        ['pve_lxc_list_users', {}],
        ['pve_lxc_write_file', { path: '/etc/new', content: 'x', mode: '0644', owner: 'root', backup: true, create_parents: true }],
        ['pve_lxc_write_file', { path: '/etc/app.conf', content: 'y', backup: true }],
        ['pve_lxc_delete_file', { path: '/etc/new' }],
        ['pve_lxc_delete_file', { path: '/etc/gone', missing_ok: true }],
        ['pve_lxc_service', { unit: 'nginx', action: 'restart' }],
        ['pve_lxc_service', { unit: 'nginx', action: 'enable' }],
        ['pve_lxc_install_packages', { packages: ['curl'] }],
        ['pve_lxc_remove_packages', { packages: ['curl'] }],
        ['pve_lxc_update_packages', {}],
        ['pve_lxc_create_user', { name: 'bob', uid: 1500, shell: '/bin/sh', home: '/home/bob', comment: 'Bob', groups: ['wheel'] }],
        ['pve_lxc_create_user', { name: 'svc2', system: true }],
        ['pve_lxc_delete_user', { name: 'bob', remove_home: true }],
        ['pve_lxc_set_password', { user: 'alice', password: 'x' }],
        ['pve_lxc_ssh_status', {}],
        ['pve_lxc_ssh_enable', {}],
        ['pve_lxc_ssh_configure', { permit_root_login: 'no', password_authentication: false, port: 2222 }],
        ['pve_lxc_ssh_list_keys', {}],
        ['pve_lxc_ssh_add_key', { public_key: key.public }],
        ['pve_lxc_ssh_remove_key', { public_key: key.public }],
        ['pve_lxc_ssh_disable', {}],
        ['pve_lxc_exec', { command: 'spy', as_user: 'alice' }],
      ];
      for (const [tool, args] of calls) {
        const res = await h.call(tool, { vmid: 101, ...args });
        expect(res.isError, `${tool} ${JSON.stringify(args)}: ${res.text}`).toBe(false);
      }
      const seen = new Set<string>();
      const offending: string[] = [];
      for (const { argv } of sandbox.ctCalls()) {
        const name = argv[0]!;
        seen.add(name);
        const allowed = BUSYBOX[name];
        if (!allowed) {
          offending.push(`${name}: not in the table`);
          continue;
        }
        const end = argv.indexOf('--');
        for (const arg of end >= 0 ? argv.slice(1, end) : argv.slice(1)) {
          if (!/^-./.test(arg)) continue;
          if (arg.startsWith('--')) {
            if (!allowed.long?.includes(arg)) offending.push(`${name} ${arg}`);
          } else if ([...arg.slice(1)].some((flag) => !allowed.flags.includes(flag))) {
            offending.push(`${name} ${arg}`);
          }
        }
      }
      expect(offending).toEqual([]);
      // That the run really covered the applets it is about.
      for (const name of ['head', 'stat', 'readlink', 'grep', 'sed', 'mktemp', 'adduser', 'deluser', 'addgroup', 'rc-service', 'apk', 'su']) expect(seen, name).toContain(name);
    }, 60_000);

    it('no script, on any distribution, needs bash to be there', async () => {
      on('alpine');
      expect((await h.call('pve_lxc_exec', { vmid: 101, command: 'command -v bash || echo none' })).data.stdout).toBe('none\n');
    });
  });
});
