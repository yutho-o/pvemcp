import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type AddressInfo } from 'node:net';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { closeAll, connect, type Env, type Harness } from './harness.js';

/**
 * Against the real thing: the OpenSSH server and key tools that come with Git for Windows, or
 * with the system elsewhere, on a local port, with every file in a temp directory, and the server
 * binary in front through a real MCP client. This is what the fake server built on ssh2 cannot
 * show: that both sides really speak the same SSH, and that what ssh-keygen writes is read
 * correctly. The commands run in the login shell of this user, which is what sshd does on a node too.
 */

function findOpenSsh(): { sshd: string; keygen: string; sftpServer: string[] } | undefined {
  const dirs = process.platform === 'win32' ? [join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'usr', 'bin')] : ['/usr/sbin', '/usr/bin'];
  const exe = process.platform === 'win32' ? '.exe' : '';
  const sshd = dirs.map((d) => join(d, `sshd${exe}`)).find((p) => existsSync(p));
  const keygen = dirs.map((d) => join(d, `ssh-keygen${exe}`)).find((p) => existsSync(p));
  if (!sshd || !keygen) return undefined;
  return { sshd, keygen, sftpServer: ['/usr/lib/ssh/sftp-server', '/usr/lib/openssh/sftp-server', '/usr/libexec/openssh/sftp-server'] };
}

const OPENSSH = findOpenSsh();
if (!OPENSSH) console.warn('[test] SKIPPING the tests against a real OpenSSH server: sshd or ssh-keygen not found.');

/** With LogLevel DEBUG1, needed to see what sshd got, this sshd also tells the client. */
const stderrOf = (text: string) => text.replace(/^debug1:.*\r?\n/gm, '');

/** How the MSYS programs of Git want a path. */
const forConfig = (path: string) => (process.platform === 'win32' ? path.replace(/^([A-Za-z]):\\/, (_m, drive: string) => `/${drive.toLowerCase()}/`).replaceAll('\\', '/') : path);

/** What a careful caller does to put a value in a command: the quoting of sh! in the server. */
const shQuote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;

function keygen(...args: string[]): string {
  const res = spawnSync(OPENSSH!.keygen, args, { encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`ssh-keygen ${args.join(' ')}: ${res.stderr}`);
  return res.stdout;
}

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

describe.skipIf(!OPENSSH)('a real OpenSSH server', () => {
  let dir: string;
  let localDir: string;
  let daemon: ChildProcess | undefined;
  let log = '';
  let port = 0;
  let hostPublic = '';
  let clientKey = '';
  let usable = false;
  const user = userInfo().username;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'pvemcp-openssh-'));
    localDir = join(dir, 'local');
    mkdirSync(localDir);
    keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'host_key'));
    keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'client_key'));
    hostPublic = readFileSync(join(dir, 'host_key.pub'), 'utf8').trim();
    clientKey = join(dir, 'client_key');
    writeFileSync(join(dir, 'authorized_keys'), readFileSync(`${clientKey}.pub`));
    port = await freePort();
    const sftp = OPENSSH!.sftpServer.find((p) => existsSync(process.platform === 'win32' ? join(dirname(OPENSSH!.sshd), '..', '..', `${p}.exe`) : p)) ?? OPENSSH!.sftpServer[0];
    writeFileSync(
      join(dir, 'sshd_config'),
      [`Port ${port}`, 'ListenAddress 127.0.0.1', `HostKey ${forConfig(join(dir, 'host_key'))}`, `AuthorizedKeysFile ${forConfig(join(dir, 'authorized_keys'))}`, `PidFile ${forConfig(join(dir, 'sshd.pid'))}`, 'PasswordAuthentication no', 'StrictModes no', 'AllowTcpForwarding yes', 'LogLevel DEBUG1', `Subsystem sftp ${sftp}`, ''].join('\n'),
    );
    daemon = spawn(OPENSSH!.sshd, ['-D', '-e', '-f', forConfig(join(dir, 'sshd_config'))], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      // MSYS sshd passes its own PATH on to sessions, and from here that has no Unix tools on it.
      env: { ...process.env, PATH: `${dirname(OPENSSH!.sshd)}${delimiter}${process.env.PATH ?? ''}` },
    });
    daemon.stdout!.on('data', (chunk: Buffer) => (log += chunk.toString()));
    daemon.stderr!.on('data', (chunk: Buffer) => (log += chunk.toString()));
    daemon.on('error', () => undefined);
    const started = Date.now();
    while (!log.includes('Server listening') && daemon.exitCode === null && Date.now() - started < 10_000) await new Promise((resolve) => setTimeout(resolve, 50));
    usable = log.includes('Server listening');
    if (!usable) console.warn(`[test] SKIPPING the tests against a real OpenSSH server: sshd did not start. ${log}`);
  }, 30_000);

  afterEach(closeAll);

  afterAll(async () => {
    daemon?.kill();
    if (daemon && daemon.exitCode === null) await new Promise((resolve) => daemon!.once('exit', resolve));
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  });

  /** known_hosts text for this server. */
  const knownLine = () => `[127.0.0.1]:${port} ${hostPublic}\n`;

  function env(extra: Env = {}): Env {
    return {
      PROXMOX_ALLOW_SSH: 'true',
      PROXMOX_ALLOW_WRITES: 'true',
      PROXMOX_SSH_USER: user,
      PROXMOX_SSH_KEY_FILE: clientKey,
      PROXMOX_SSH_PORT: String(port),
      PROXMOX_SSH_NODES: 'pve1=127.0.0.1',
      PROXMOX_SSH_KNOWN_HOSTS: join(dir, 'known_hosts'),
      PROXMOX_LOCAL_DIR: localDir,
      ...extra,
    };
  }

  /** A server process for these settings. Its transport connects on the first call, after known_hosts is written. */
  async function server(extra: Env = {}, known = knownLine(), killGraceMs = 100): Promise<Harness> {
    writeFileSync(join(dir, 'known_hosts'), known);
    return connect({ env: env({ PVEMCP_TEST_SSH_TRANSPORT: JSON.stringify({ killGraceMs }), ...extra }) });
  }

  const run = (h: Harness, command: string, extra: Record<string, unknown> = {}) => h.call('pve_ssh_exec', { node: 'pve1', command, ...extra });

  const typeOf = async (h: Harness, command = 'true') => {
    const res = await run(h, command);
    return res.isError ? res.data.error_type : 'no error';
  };

  const accepted = () => (log.match(/Accepted publickey/g) ?? []).length;

  /** Tests are declared before beforeAll ran: this is where a server that did not start shows. */
  const ready = (ctx: { skip: () => void }) => {
    if (!usable) ctx.skip();
  };

  describe('the handshake and the host key', () => {
    it('connects, logs in with a key made by ssh-keygen, runs a command', async (ctx) => {
      ready(ctx);
      const res = await run(await server(), 'echo hello; exit 3');
      expect(res.isError, res.text).toBe(false);
      expect(res.data).toMatchObject({ stdout: 'hello\n', exit_code: 3, truncated: false });
      expect(log).toContain('Accepted publickey');
    });

    it('computes the fingerprint ssh-keygen -l gives', async (ctx) => {
      ready(ctx);
      const res = await (await server()).call('pve_ssh_test', { node: 'pve1' });
      const printed = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1];
      expect(res.data.host_key).toEqual({ type: 'ssh-ed25519', fingerprint: printed });
    });

    it('reads a known_hosts file hashed by ssh-keygen -H, and connects by it', async (ctx) => {
      ready(ctx);
      const file = join(dir, 'to_hash');
      writeFileSync(file, knownLine());
      keygen('-H', '-f', file);
      const hashed = readFileSync(file, 'utf8');
      expect(hashed.startsWith('|1|')).toBe(true);
      rmSync(`${file}.old`, { force: true });
      expect((await run(await server({}, hashed), 'echo ok')).data.stdout).toBe('ok\n');
    });

    it('agrees with ssh-keygen -F on what a hashed file holds', async (ctx) => {
      ready(ctx);
      const file = join(dir, 'to_find');
      writeFileSync(file, knownLine());
      keygen('-H', '-f', file);
      rmSync(`${file}.old`, { force: true });
      expect(keygen('-F', `[127.0.0.1]:${port}`, '-f', file)).toContain('|1|');
    });

    it('refuses an unknown host before logging in', async (ctx) => {
      ready(ctx);
      const before = accepted();
      expect(await typeOf(await server({}, ''))).toBe('host_key_unknown');
      expect(accepted()).toBe(before);
    });

    it('refuses a changed key before logging in', async (ctx) => {
      ready(ctx);
      const before = accepted();
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'other_key'));
      const other = readFileSync(join(dir, 'other_key.pub'), 'utf8').trim();
      expect(await typeOf(await server({}, `[127.0.0.1]:${port} ${other}\n`))).toBe('host_key_mismatch');
      expect(accepted()).toBe(before);
    });

    it('takes a pin from ssh-keygen -l', async (ctx) => {
      ready(ctx);
      const pin = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1]!;
      expect((await run(await server({ PROXMOX_SSH_FINGERPRINTS: `pve1=${pin}` }, ''), 'echo ok')).data.stdout).toBe('ok\n');
    });

    it('records with accept-new a line that ssh-keygen then finds', async (ctx) => {
      ready(ctx);
      expect(await typeOf(await server({ PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' }, ''))).toBe('no error');
      expect(keygen('-F', `[127.0.0.1]:${port}`, '-f', join(dir, 'known_hosts'))).toContain(hostPublic.split(' ')[1]);
    });

    it('checks a real server offering several key types', async (ctx) => {
      ready(ctx);
      // sshd has only the ed25519 key, and a known RSA entry must not make it unknown by another name.
      keygen('-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', join(dir, 'rsa_key'));
      const rsa = readFileSync(join(dir, 'rsa_key.pub'), 'utf8').trim();
      expect(await typeOf(await server({}, `[127.0.0.1]:${port} ${rsa}\n`))).toBe('host_key_unknown');
    });
  });

  describe('logging in', () => {
    it('refuses a key sshd does not know', async (ctx) => {
      ready(ctx);
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'stranger'));
      expect(await typeOf(await server({ PROXMOX_SSH_KEY_FILE: join(dir, 'stranger') }))).toBe('ssh_auth_failed');
    });

    it('opens an encrypted key made by ssh-keygen, with its passphrase, and only with it', async (ctx) => {
      ready(ctx);
      keygen('-q', '-t', 'ed25519', '-N', 'sesame', '-f', join(dir, 'locked'));
      const pub = readFileSync(`${join(dir, 'locked')}.pub`, 'utf8');
      const authorized = readFileSync(join(dir, 'authorized_keys'), 'utf8');
      writeFileSync(join(dir, 'authorized_keys'), `${authorized}${pub}`);
      expect((await run(await server({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked'), PROXMOX_SSH_KEY_PASSPHRASE: 'sesame' }), 'echo ok')).data.stdout).toBe('ok\n');
      expect(await typeOf(await server({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked') }))).toBe('ssh_auth_failed');
      expect(await typeOf(await server({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked'), PROXMOX_SSH_KEY_PASSPHRASE: 'wrong' }))).toBe('ssh_auth_failed');
    });

    it.each(['rsa', 'ecdsa'])('logs in with a %s key from ssh-keygen', async (type) => {
      if (!usable) return;
      const file = join(dir, `client_${type}`);
      keygen('-q', '-t', type, '-N', '', '-f', file);
      writeFileSync(join(dir, 'authorized_keys'), `${readFileSync(join(dir, 'authorized_keys'), 'utf8')}${readFileSync(`${file}.pub`, 'utf8')}`);
      const res = await run(await server({ PROXMOX_SSH_KEY_FILE: file }), 'echo ok');
      expect(res.data.stdout, res.text).toBe('ok\n');
    });
  });

  describe('commands in the real login shell', () => {
    const HOSTILE = [`it's`, `'; touch pwned; '`, '$(touch pwned)', '`touch pwned`', '$HOME ${PATH}', 'one\ntouch pwned\ntwo', 'a; touch pwned', 'a && touch pwned & b', 'a | touch pwned', 'a > pwned < b', '-rf', '--help', '* ? [a-z]', 'a\\b\\\\c\\', 'a"b"c', '# touch pwned', '~root', '  two  spaces  ', 'a\tb', 'héllo wörld ☃ 日本語 🎉', `'"\`$(touch pwned)\n;touch pwned #`];

    it.each(HOSTILE)('takes %j as one argument, literally', async (payload) => {
      if (!usable) return;
      const place = mkdtempSync(join(dir, 'q-'));
      const res = await run(await server(),`cd ${shQuote(forConfig(place))} && printf '[%s]' ${shQuote(payload)} "$#"`);
      expect(stderrOf(res.data.stderr ?? ''), res.text).toBe('');
      expect(res.data.stdout).toBe(`[${payload}][0]`);
      expect(readdirSync(place)).toEqual([]);
    });

    it('gives stdin, and its end, to a real cat', async (ctx) => {
      ready(ctx);
      const h = await server();
      expect((await run(h, 'cat', { stdin: 'through stdin' })).data.stdout).toBe('through stdin');
      const started = Date.now();
      const res = await run(h, 'cat', { timeout_seconds: 15 });
      expect(res.isError, res.text).toBe(false);
      expect(Date.now() - started).toBeLessThan(10_000);
    });

    it('gets the signal to sshd for a command still running after its input ended', async (ctx) => {
      ready(ctx);
      // The shell runs a trap once sleep returns, so it needs the time to.
      const h = await server({}, knownLine(), 2000);
      const res = await run(h, `trap 'echo got-term; exit 9' TERM; echo started; i=0; while [ $i -lt 40 ]; do sleep 0.1; i=$((i+1)); done; echo finished`, { timeout_seconds: 1 });
      expect(res.data.error_type, res.text).toBe('ssh_timeout');
      expect(res.data.details.stdout).toContain('started');
      expect(res.data.details.stdout).not.toContain('finished');
      // The input had ended: the signal still has to go.
      expect(log).toContain('req signal');
      // The build of sshd in Git for Windows has no privilege separation, and says so instead of signalling.
      if (log.includes('session signalling requires privilege separation')) console.warn('[test] This sshd takes the signal request and refuses to act on it (no privilege separation): delivery to the command is unproven here.');
      else expect(res.data.details.stdout).toContain('got-term');
    }, 20_000);

    it('caps output and reports it', async (ctx) => {
      ready(ctx);
      const res = await run(await server(), `i=0; while [ $i -lt 400 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done`, { max_output_bytes: 1024 });
      expect(res.data).toMatchObject({ truncated: true, exit_code: 0 });
      expect(res.data.stdout).toHaveLength(1024);
    });

    it('runs many at once over one connection, within what sshd allows', async (ctx) => {
      ready(ctx);
      const before = accepted();
      const h = await server();
      const results = await Promise.all(Array.from({ length: 24 }, (_, i) => run(h, `echo ${i}`)));
      expect(results.map((r) => r.data.stdout?.trim())).toEqual(Array.from({ length: 24 }, (_, i) => String(i)));
      expect(accepted()).toBe(before + 1);
    }, 30_000);
  });

  describe('SFTP', () => {
    it('copies a file both ways with the real sftp-server', async (ctx) => {
      ready(ctx);
      const content = Buffer.alloc(200_000, 'ab');
      writeFileSync(join(localDir, 'to_send'), content);
      const h = await server();
      const remote = forConfig(join(dir, 'sent'));
      const up = await h.call('pve_ssh_upload', { node: 'pve1', local_path: 'to_send', path: remote, mode: '0600' });
      expect(up.isError, up.text).toBe(false);
      expect(readFileSync(join(dir, 'sent')).equals(content)).toBe(true);
      const down = await h.call('pve_ssh_download', { node: 'pve1', path: remote, local_path: 'came_back' });
      expect(down.isError, down.text).toBe(false);
      expect(down.data.bytes).toBe(200_000);
      expect(readFileSync(join(localDir, 'came_back')).equals(content)).toBe(true);
      expect((await h.call('pve_ssh_delete_file', { node: 'pve1', path: remote })).data.deleted).toBe(true);
      expect(existsSync(join(dir, 'sent'))).toBe(false);
      expect((await h.call('pve_ssh_download', { node: 'pve1', path: remote, local_path: 'again' })).data.error_type).toBe('not_found');
    }, 30_000);
  });

  describe('a terminal', () => {
    it('has a real PTY, carries input and output, and reports the exit', async (ctx) => {
      ready(ctx);
      const h = await server();
      const opened = await h.call('pve_ssh_session_open', { node: 'pve1', cols: 90, rows: 20 });
      expect(opened.isError, opened.text).toBe(false);
      const { session } = opened.data;
      // Output not looked at yet.
      let fresh: string = opened.data.output ?? '';
      const readUntil = (text: RegExp) =>
        vi.waitFor(
          async () => {
            fresh += (await h.call('pve_ssh_session_read', { session, wait_ms: 100 })).data.output ?? '';
            expect(fresh).toMatch(text);
            fresh = '';
          },
          { timeout: 10_000 },
        );
      const PROMPT = /[$#>] *$/;
      // A shell, and read, can flush what was typed before they ask: each line waits for its prompt.
      await readUntil(PROMPT);
      // The echo of the line holds the expression, only the answer of the shell holds the result.
      await h.call('pve_ssh_session_send', { session, input: `tty >/dev/null && echo "tty=$((1+1))"\n` });
      await readUntil(/tty=2[\s\S]*[$#>] *$/);
      await h.call('pve_ssh_session_send', { session, input: `printf 'a''sk> '; read line; echo "got:$line"\n` });
      await readUntil(/ask> *$/);
      await h.call('pve_ssh_session_send', { session, input: 'typed\n' });
      await readUntil(/got:typed[\s\S]*[$#>] *$/);
      await h.call('pve_ssh_session_send', { session, input: 'exit 5\n' });
      await vi.waitFor(
        async () => {
          const res = await h.call('pve_ssh_session_read', { session, wait_ms: 100 });
          expect(res.data).toMatchObject({ closed: true, exit_code: 5 });
        },
        { timeout: 10_000 },
      );
    }, 30_000);
  });

  describe('through a real MCP client', () => {
    it('pve_ssh_test and pve_ssh_exec', async (ctx) => {
      ready(ctx);
      const h = await server();
      const test = await h.call('pve_ssh_test', { node: 'pve1' });
      expect(test.isError, test.text).toBe(false);
      expect(test.data.connected).toBe(true);
      expect(test.data.user).toBe(user);
      const exec = await run(h, `echo out; echo err >&2; exit 2`);
      expect(exec.data).toMatchObject({ stdout: 'out\n', exit_code: 2, untrusted: true });
      expect(stderrOf(exec.data.stderr)).toBe('err\n');
    });

    it('jumps through the node to a guest: real forwarding, and the guest key checked at the far end', async (ctx) => {
      ready(ctx);
      const pin = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1]!;
      const h = await server({ PROXMOX_GUEST_SSH_KEY_FILE: clientKey, PROXMOX_GUEST_SSH_USER: user });
      const res = await h.call('pve_guest_ssh_exec', { vmid: 100, host: '127.0.0.1', port, via_node: true, fingerprint: pin, command: 'echo through the node' });
      expect(res.isError, res.text).toBe(false);
      expect(res.data).toMatchObject({ stdout: 'through the node\n', exit_code: 0 });
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'wrong_pin'));
      const wrongPin = keygen('-lf', join(dir, 'wrong_pin.pub')).split(' ')[1]!;
      const refused = await h.call('pve_guest_ssh_exec', { vmid: 100, host: '127.0.0.1', port, via_node: true, fingerprint: wrongPin, command: 'echo never' });
      expect(refused.data.error_type).toBe('host_key_mismatch');
    }, 30_000);
  });
});
