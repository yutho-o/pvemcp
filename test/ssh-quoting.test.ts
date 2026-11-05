import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sh } from '../src/ssh/index.js';
import { pctExec, sampleScripts } from '../src/ssh/scripts.js';
import { FAKE_SSH_PASSWORD, FakeSsh, ShellSandbox } from './fake-ssh.js';
import { closeSsh, connectSsh, POSIX_SHELL, type SshHarness } from './ssh-harness.js';

/**
 * Input from an agent goes through the shell of the node, then through pct, then through a
 * shell in the container. These tests run all of that for real, with a real SSH connection and
 * a real POSIX shell (dash where available), with a pct stub that executes what it is given. The
 * container commands record the arguments they get. Everything stays in a temp directory.
 */

/** Each one tries to break out by another route. If any ran, the marker file appears. */
const HOSTILE: Array<[string, string]> = [
  ['single quote', `it's`],
  ['closing the quote and running', `'; touch pwned; '`],
  ['command substitution', '$(touch pwned)'],
  ['backticks', '`touch pwned`'],
  ['variable', '$HOME ${PATH}'],
  ['newline', 'one\ntouch pwned\ntwo'],
  ['carriage return', 'one\rtwo'],
  ['semicolon', 'a; touch pwned'],
  ['ampersand', 'a && touch pwned & b'],
  ['pipe', 'a | touch pwned'],
  ['redirection', 'a > pwned < b'],
  ['leading dash', '-rf'],
  ['leading double dash', '--help'],
  ['glob', '* ? [a-z]'],
  ['backslash', 'a\\b\\\\c\\'],
  ['double quotes', 'a"b"c'],
  ['hash', '# touch pwned'],
  ['tilde', '~root'],
  ['spaces', '  two  spaces  '],
  ['tab', 'a\tb'],
  ['unicode', 'héllo wörld ☃ 日本語 🎉'],
  ['empty', ''],
  ['mixed', `'"\`$(touch pwned)\n;touch pwned #`],
];

describe.skipIf(!POSIX_SHELL)('hostile input through the node shell, pct and the container shell', () => {
  let sandbox: ShellSandbox;
  let server: FakeSsh;
  let h: SshHarness;

  beforeAll(async () => {
    sandbox = new ShellSandbox(POSIX_SHELL!);
    server = new FakeSsh({ sandbox });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
    sandbox.remove();
  });
  beforeEach(async () => {
    sandbox.clearLogs();
    h = await connectSsh({ server });
  });
  afterEach(async () => {
    await closeSsh();
    // Whatever was tried in the test, it did not run in any of the places where a shell would have run it.
    expect(sandbox.exists('ct/pwned')).toBe(false);
    expect(sandbox.exists('pwned')).toBe(false);
  });

  it('runs a plain command through the whole chain', async () => {
    const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'echo hello from "$IN_CT"' });
    expect(res.isError).toBe(false);
    expect(res.data).toMatchObject({ stdout: 'hello from 1\n', exit_code: 0, untrusted: true, node: 'pve1' });
    const pct = sandbox.nodeCalls().find((c) => c.argv[0] === 'pct')!;
    expect(pct.argv.slice(0, 5)).toEqual(['pct', 'exec', '101', '--', 'sh']);
  });

  it('expands in the container, and not on the node', async () => {
    const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'spy "$IN_CT" "$(printf inner)"' });
    expect(res.isError).toBe(false);
    // IN_CT is only set past pct: on the node it would have been empty.
    expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', '1', 'inner']);
  });

  describe.each(HOSTILE)('%s', (_name, payload) => {
    it('arrives intact as an environment value', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'spy "$X"', env: { X: payload } });
      expect(res.isError).toBe(false);
      expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', payload]);
    });

    it('arrives intact through su', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'spy "$X" "$AS_USER"', env: { X: payload }, as_user: 'alice' });
      expect(res.isError).toBe(false);
      expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', payload, '1']);
      expect(sandbox.ctCalls('su')[0]!.argv.slice(0, 5)).toEqual(['su', '-s', '/bin/sh', 'alice', '-c']);
    });

    it('arrives intact as a script argument, one argument', async () => {
      const res = await h.call('pve_lxc_run_script', { vmid: 101, script: 'spy "$#" "$1"\n', args: [payload] });
      expect(res.isError).toBe(false);
      expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', '1', payload]);
    });

    it('arrives intact in the command itself, as text and not as code, when properly quoted by the caller', async () => {
      const command = sh`spy ${payload}`;
      const res = await h.call('pve_lxc_exec', { vmid: 101, command });
      expect(res.isError).toBe(false);
      expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', payload]);
    });

    it('is on stdin byte for byte, and never read as shell text', async () => {
      const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'cat', stdin: payload });
      expect(res.isError).toBe(false);
      // scrubText drops bare control characters from output, as it does for everything from a guest. Tabs and \r stay.
      expect(res.data.stdout).toBe(payload);
    });

    if (payload !== '') {
      const path = `/tmp/x${payload}y`;

      it('reaches rm as one path on a delete in a container', async () => {
        await h.call('pve_lxc_delete_file', { vmid: 101, path, missing_ok: true });
        const rm = sandbox.ctCalls('rm')[0]!.argv;
        expect(rm.slice(0, 3)).toEqual(['rm', '-f', '--']);
        expect(rm.slice(3)).toEqual([path]);
      });

      it('reaches ls as one path on a listing in a container', async () => {
        await h.call('pve_lxc_list_dir', { vmid: 101, path });
        expect(sandbox.ctCalls('ls')[0]!.argv).toEqual(['ls', '-la', '--', path]);
      });

      it('does not run from a read in a container', async () => {
        const res = await h.call('pve_lxc_read_file', { vmid: 101, path });
        expect(res.data.error_type).toBe('not_found');
      });

      it('does not run from a directory to change to', async () => {
        const res = await h.call('pve_lxc_exec', { vmid: 101, command: 'spy ran', cwd: path });
        expect(res.data.exit_code).toBe(125);
        expect(sandbox.ctCalls('spy')).toEqual([]);
      });

      it('reaches pct push and pull as one argument', async () => {
        writeFileSync(join(h.localDir, 'f.txt'), 'data');
        await h.call('pve_lxc_push_file', { vmid: 101, local_path: 'f.txt', path });
        const push = sandbox.nodeCalls().find((c) => c.argv[1] === 'push')!;
        expect(push.argv.slice(0, 3)).toEqual(['pct', 'push', '101']);
        expect(push.argv.at(-1)).toBe(path);
      });

      it('does not run from a node path', async () => {
        const res = await h.call('pve_ssh_delete_file', { node: 'pve1', path, missing_ok: true });
        expect(res.isError).toBe(false);
        const listed = await h.call('pve_ssh_list_dir', { node: 'pve1', path });
        expect(listed.isError).toBe(true);
      });

      it('does not run from a node working directory', async () => {
        const res = await h.call('pve_ssh_exec', { node: 'pve1', command: 'echo ran', cwd: path });
        expect(res.data.exit_code).toBe(125);
        expect(res.data.stdout).toBe('');
      });
    }

    it('does not run from a write in a container, with the content kept out of the command', async () => {
      if (payload === '' || /[\\]/.test(payload)) return;
      const path = `/tmp/w${payload.replace(/\//g, '_')}`;
      const res = await h.call('pve_lxc_write_file', { vmid: 101, path, content: `content of ${payload}` });
      // Windows may refuse some of these names, which is not what this test is about. Nothing must run either way.
      if (res.isError) return;
      const back = await h.call('pve_lxc_read_file', { vmid: 101, path });
      expect(back.data.content).toBe(`content of ${payload}`);
    });
  });

  it('refuses a name that could be an option, before anything runs', async () => {
    for (const [tool, args] of [
      ['pve_lxc_service', { vmid: 101, unit: '-rf', action: 'stop' }],
      ['pve_lxc_service', { vmid: 101, unit: '--now', action: 'stop' }],
      ['pve_lxc_service', { vmid: 101, unit: 'a;reboot', action: 'stop' }],
      ['pve_lxc_service_status', { vmid: 101, unit: '$(reboot)' }],
      ['pve_lxc_logs', { vmid: 101, unit: '`reboot`' }],
      ['pve_ssh_journal', { node: 'pve1', unit: "x'; reboot #" }],
      ['pve_ssh_journal', { node: 'pve1', since: '$(reboot)' }],
      ['pve_lxc_logs', { vmid: 101, since: '; reboot' }],
      ['pve_lxc_install_packages', { vmid: 101, packages: ['-o'] }],
      ['pve_lxc_install_packages', { vmid: 101, packages: ['curl', '--allow-unauthenticated'] }],
      ['pve_lxc_install_packages', { vmid: 101, packages: ['curl;reboot'] }],
      ['pve_lxc_install_packages', { vmid: 101, packages: ['a b'] }],
      ['pve_lxc_remove_packages', { vmid: 101, packages: ['$(reboot)'] }],
      ['pve_lxc_create_user', { vmid: 101, name: '-o' }],
      ['pve_lxc_create_user', { vmid: 101, name: 'a b' }],
      ['pve_lxc_create_user', { vmid: 101, name: "x'y" }],
      ['pve_lxc_create_user', { vmid: 101, name: 'ok', comment: 'a:b' }],
      ['pve_lxc_create_user', { vmid: 101, name: 'ok', groups: ['-g'] }],
      ['pve_lxc_delete_user', { vmid: 101, name: '--remove-home' }],
      ['pve_lxc_set_password', { vmid: 101, user: '-e', password: 'x' }],
      ['pve_lxc_set_password', { vmid: 101, user: 'root', password: 'a\nb:c' }],
      ['pve_lxc_exec', { vmid: 101, command: 'x', as_user: '-c' }],
      ['pve_lxc_exec', { vmid: 101, command: 'x', env: { 'A;reboot': '1' } }],
      ['pve_lxc_exec', { vmid: 101, command: 'x', env: { 'A B': '1' } }],
      ['pve_lxc_delete_file', { vmid: 101, path: '-rf' }],
      ['pve_lxc_delete_file', { vmid: 101, path: 'relative/path' }],
      ['pve_lxc_read_file', { vmid: 101, path: '../etc/passwd' }],
      ['pve_lxc_write_file', { vmid: 101, path: '/tmp/x', content: 'y', mode: '777;reboot' }],
      ['pve_lxc_write_file', { vmid: 101, path: '/tmp/x', content: 'y', owner: '-R' }],
      ['pve_lxc_push_file', { vmid: 101, local_path: 'x', path: '/tmp/x', user: '--help' }],
      ['pve_lxc_fsck', { vmid: 101, device: '--force' }],
      ['pve_ssh_exec', { node: '-oProxyCommand=x', command: 'x' }],
      ['pve_ssh_exec', { node: 'pve1', command: 'x', cwd: 'rel' }],
      ['pve_guest_ssh_test', { vmid: 101, user: '-l' }],
      ['pve_guest_ssh_test', { vmid: 101, host: '-oProxyCommand=x' }],
    ] as const) {
      const res = await h.call(tool, args as Record<string, unknown>);
      expect(res.isError, `${tool} ${JSON.stringify(args)}`).toBe(true);
    }
    expect(sandbox.nodeCalls()).toEqual([]);
    expect(sandbox.ctCalls()).toEqual([]);
  });

  it('refuses NUL everywhere it can get in', async () => {
    for (const [tool, args] of [
      ['pve_lxc_exec', { vmid: 101, command: 'spy "$X"', env: { X: 'a\0b' } }],
      ['pve_lxc_exec', { vmid: 101, command: 'a\0b' }],
      ['pve_lxc_read_file', { vmid: 101, path: '/tmp/a\0b' }],
      ['pve_lxc_delete_file', { vmid: 101, path: '/tmp/a\0b' }],
      ['pve_ssh_exec', { node: 'pve1', command: 'a\0b' }],
      ['pve_lxc_run_script', { vmid: 101, script: 'x', args: ['a\0b'] }],
    ] as const) {
      const res = await h.call(tool, args as Record<string, unknown>);
      expect(res.isError, `${tool}`).toBe(true);
    }
    expect(sandbox.nodeCalls()).toEqual([]);
  });

  it('goes through sudo as one argument too, for a user who needs it', async () => {
    const asAdmin = new FakeSsh({ sandbox, users: { admin: { password: FAKE_SSH_PASSWORD } } });
    await asAdmin.start();
    try {
      const admin = await connectSsh({ server: asAdmin, env: { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' } });
      const payload = `'; touch pwned; '$(touch pwned)`;
      const res = await admin.call('pve_lxc_exec', { vmid: 101, command: 'spy "$X"', env: { X: payload } });
      expect(res.isError).toBe(false);
      const sudo = sandbox.nodeCalls().find((c) => c.argv[0] === 'sudo')!;
      expect(sudo.argv.slice(0, 4)).toEqual(['sudo', '-n', 'sh', '-c']);
      expect(sudo.argv).toHaveLength(5);
      expect(sandbox.ctCalls('spy')[0]!.argv).toEqual(['spy', payload]);
    } finally {
      await closeSsh();
      await asAdmin.stop();
    }
  });

  it('reports a sudo that refuses as an auth failure, with nothing run', async () => {
    const asAdmin = new FakeSsh({ sandbox, users: { admin: { password: FAKE_SSH_PASSWORD } } });
    await asAdmin.start();
    sandbox.flag('sudo-refused');
    try {
      const admin = await connectSsh({ server: asAdmin, env: { PROXMOX_SSH_USER: 'admin', PROXMOX_SSH_SUDO: 'true' } });
      const res = await admin.call('pve_ssh_exec', { node: 'pve1', command: 'spy never' });
      expect(res.data.error_type).toBe('ssh_auth_failed');
      expect(res.data.details.stderr).toContain('password is required');
      expect(sandbox.ctCalls('spy')).toEqual([]);
    } finally {
      sandbox.flag('sudo-refused', false);
      await closeSsh();
      await asAdmin.stop();
    }
  });
});

describe.skipIf(!POSIX_SHELL)('every generated script', () => {
  const scripts = Object.entries(sampleScripts());

  it.each(scripts)('%s parses in a strict POSIX shell', (_name, script) => {
    const res = spawnSync(POSIX_SHELL!.path, ['-n'], { input: script, encoding: 'utf8' });
    expect(res.stderr).toBe('');
    expect(res.status).toBe(0);
  });

  it.each(scripts)('%s also parses once carried by pct exec', (_name, script) => {
    const res = spawnSync(POSIX_SHELL!.path, ['-n'], { input: pctExec(101, script), encoding: 'utf8' });
    expect(res.stderr).toBe('');
    expect(res.status).toBe(0);
  });
});

describe('bash syntax', () => {
  /** Dash already rejects most of it. These would slip through a parse, or are options dash does not check. */
  const BASHISMS: Array<[string, RegExp]> = [
    ['[[ ]]', /\[\[ /],
    ['function keyword', /\bfunction\s+\w+/],
    ['here string', /<<</],
    ['ANSI-C quoting', /(?:^|\s)\$'/m],
    ['process substitution', /[<>]\(/],
    ['&> redirect', /&>/],
    ['pipefail', /pipefail/],
    ['source', /^\s*source\s/m],
    ['echo with options', /\becho -[neE]\b/],
    ['local', /^\s*local\s/m],
    ['arrays', /\$\{\w+\[/],
    ['pattern substitution', /\$\{\w+\/\//],
    ['== in test', /\[ [^\]]*== /],
    ['hard-coded bash', /\bbash\b/],
  ];

  it.each(Object.entries(sampleScripts()))('%s has none', (_name, script) => {
    for (const [what, pattern] of BASHISMS) expect(pattern.test(script), what).toBe(false);
  });
});

describe('pct syntax', () => {
  it('builds pct exec the way the man page has it: vmid, then -- and the command', () => {
    expect(pctExec(100, 'id')).toBe(`pct exec '100' -- sh -c 'id'`);
  });

  it('holds exactly one level of quoting around the script', () => {
    expect(pctExec(100, `cat 'a b'`)).toBe(`pct exec '100' -- sh -c 'cat '\\''a b'\\'''`);
  });
});
