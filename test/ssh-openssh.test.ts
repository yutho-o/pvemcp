import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type AddressInfo } from 'node:net';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { loadConfig, type Env } from '../src/config.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { NodeResolver } from '../src/proxmox/nodes.js';
import { fingerprintOf, parseKnownHosts } from '../src/ssh/known-hosts.js';
import { PooledSshTransport } from '../src/ssh/transport.js';
import { sh } from '../src/ssh/index.js';
import { closeAll, connect } from './harness.js';

/**
 * Against the real thing: the OpenSSH server and key tools that come with Git for Windows, or
 * with the system elsewhere, on a local port, with every file in a temp directory. This is what
 * the fake server built on ssh2 cannot show: that both sides really speak the same SSH, and that
 * what ssh-keygen writes is read correctly. The commands run in the login shell of this user,
 * which is what sshd does on a node too.
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
  let daemon: ChildProcess | undefined;
  let log = '';
  let port = 0;
  let hostPublic = '';
  let clientKey = '';
  let usable = false;
  const open: PooledSshTransport[] = [];
  const user = userInfo().username;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'pvemcp-openssh-'));
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

  afterEach(async () => {
    await closeAll();
    for (const transport of open.splice(0)) await transport.close();
  });

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
      ...extra,
    };
  }

  function transport(extra: Env = {}, known = knownLine(), killGraceMs = 100): PooledSshTransport {
    writeFileSync(join(dir, 'known_hosts'), known);
    const instance = loadConfig({ PROXMOX_URL: 'https://192.0.2.1', PROXMOX_TOKEN: 'a@pve!t=s', ...env(extra) }).instances.get('default')!;
    const made = new PooledSshTransport(instance, new NodeResolver({ get: async () => [] }, { apiHost: '192.0.2.1', sshNodes: instance.ssh.nodes }), { killGraceMs });
    open.push(made);
    return made;
  }

  const run = (t: PooledSshTransport, text: string, stdin?: string) => t.exec({ node: 'pve1' }, { text, access: 'read', ...(stdin !== undefined ? { stdin } : {}) });

  const typeOf = (promise: Promise<unknown>) => promise.then(() => 'no error', (err: unknown) => (err instanceof ProxmoxError ? err.type : String(err)));

  /** Tests are declared before beforeAll ran: this is where a server that did not start shows. */
  const ready = (ctx: { skip: () => void }) => {
    if (!usable) ctx.skip();
  };

  describe('the handshake and the host key', () => {
    it('connects, logs in with a key made by ssh-keygen, runs a command', async (ctx) => {
      ready(ctx);
      const res = await run(transport(), 'echo hello; exit 3');
      expect(res).toMatchObject({ stdout: 'hello\n', exit_code: 3, timed_out: false, truncated: false });
      expect(log).toContain('Accepted publickey');
    });

    it('computes the fingerprint ssh-keygen -l gives', async (ctx) => {
      ready(ctx);
      const res = await run(transport(), 'true');
      const printed = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1];
      expect(res.host_key).toEqual({ type: 'ssh-ed25519', fingerprint: printed });
      const blob = Buffer.from(hostPublic.split(' ')[1]!, 'base64');
      expect(fingerprintOf(blob)).toBe(printed);
    });

    it('reads a known_hosts file hashed by ssh-keygen -H, and connects by it', async (ctx) => {
      ready(ctx);
      const file = join(dir, 'to_hash');
      writeFileSync(file, knownLine());
      keygen('-H', '-f', file);
      const hashed = readFileSync(file, 'utf8');
      expect(hashed.startsWith('|1|')).toBe(true);
      rmSync(`${file}.old`, { force: true });
      expect(parseKnownHosts(hashed)).toHaveLength(1);
      expect((await run(transport({}, hashed), 'echo ok')).stdout).toBe('ok\n');
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
      const accepted = (log.match(/Accepted publickey/g) ?? []).length;
      expect(await typeOf(run(transport({}, ''), 'true'))).toBe('host_key_unknown');
      expect((log.match(/Accepted publickey/g) ?? []).length).toBe(accepted);
    });

    it('refuses a changed key before logging in', async (ctx) => {
      ready(ctx);
      const accepted = (log.match(/Accepted publickey/g) ?? []).length;
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'other_key'));
      const other = readFileSync(join(dir, 'other_key.pub'), 'utf8').trim();
      expect(await typeOf(run(transport({}, `[127.0.0.1]:${port} ${other}\n`), 'true'))).toBe('host_key_mismatch');
      expect((log.match(/Accepted publickey/g) ?? []).length).toBe(accepted);
    });

    it('takes a pin from ssh-keygen -l', async (ctx) => {
      ready(ctx);
      const pin = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1]!;
      expect((await run(transport({ PROXMOX_SSH_FINGERPRINTS: `pve1=${pin}` }, ''), 'echo ok')).stdout).toBe('ok\n');
    });

    it('records with accept-new a line that ssh-keygen then finds', async (ctx) => {
      ready(ctx);
      const t = transport({ PROXMOX_SSH_HOST_KEY_POLICY: 'accept-new' }, '');
      await run(t, 'true');
      expect(keygen('-F', `[127.0.0.1]:${port}`, '-f', join(dir, 'known_hosts'))).toContain(hostPublic.split(' ')[1]);
    });

    it('checks a real server offering several key types', async (ctx) => {
      ready(ctx);
      // sshd has only the ed25519 key, and a known RSA entry must not make it unknown by another name.
      keygen('-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', join(dir, 'rsa_key'));
      const rsa = readFileSync(join(dir, 'rsa_key.pub'), 'utf8').trim();
      const res = await typeOf(run(transport({}, `[127.0.0.1]:${port} ${rsa}\n`), 'true'));
      expect(res).toBe('host_key_unknown');
    });
  });

  describe('logging in', () => {
    it('refuses a key sshd does not know', async (ctx) => {
      ready(ctx);
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'stranger'));
      expect(await typeOf(run(transport({ PROXMOX_SSH_KEY_FILE: join(dir, 'stranger') }), 'true'))).toBe('ssh_auth_failed');
    });

    it('opens an encrypted key made by ssh-keygen, with its passphrase, and only with it', async (ctx) => {
      ready(ctx);
      keygen('-q', '-t', 'ed25519', '-N', 'sesame', '-f', join(dir, 'locked'));
      const pub = readFileSync(`${join(dir, 'locked')}.pub`, 'utf8');
      const authorized = readFileSync(join(dir, 'authorized_keys'), 'utf8');
      writeFileSync(join(dir, 'authorized_keys'), `${authorized}${pub}`);
      expect((await run(transport({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked'), PROXMOX_SSH_KEY_PASSPHRASE: 'sesame' }), 'echo ok')).stdout).toBe('ok\n');
      expect(await typeOf(run(transport({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked') }), 'true'))).toBe('ssh_auth_failed');
      expect(await typeOf(run(transport({ PROXMOX_SSH_KEY_FILE: join(dir, 'locked'), PROXMOX_SSH_KEY_PASSPHRASE: 'wrong' }), 'true'))).toBe('ssh_auth_failed');
    });

    it.each(['rsa', 'ecdsa'])('logs in with a %s key from ssh-keygen', async (type) => {
      if (!usable) return;
      const file = join(dir, `client_${type}`);
      keygen('-q', '-t', type, '-N', '', '-f', file);
      writeFileSync(join(dir, 'authorized_keys'), `${readFileSync(join(dir, 'authorized_keys'), 'utf8')}${readFileSync(`${file}.pub`, 'utf8')}`);
      expect((await run(transport({ PROXMOX_SSH_KEY_FILE: file }), 'echo ok')).stdout).toBe('ok\n');
    });
  });

  describe('commands in the real login shell', () => {
    const HOSTILE = [`it's`, `'; touch pwned; '`, '$(touch pwned)', '`touch pwned`', '$HOME ${PATH}', 'one\ntouch pwned\ntwo', 'a; touch pwned', 'a && touch pwned & b', 'a | touch pwned', 'a > pwned < b', '-rf', '--help', '* ? [a-z]', 'a\\b\\\\c\\', 'a"b"c', '# touch pwned', '~root', '  two  spaces  ', 'a\tb', 'héllo wörld ☃ 日本語 🎉', `'"\`$(touch pwned)\n;touch pwned #`];

    it.each(HOSTILE)('takes %j as one argument, literally', async (payload) => {
      if (!usable) return;
      const place = mkdtempSync(join(dir, 'q-'));
      const res = await run(transport(), sh`cd ${forConfig(place)} && printf '[%s]' ${payload} "$#"`);
      expect(stderrOf(res.stderr)).toBe('');
      expect(res.stdout).toBe(`[${payload}][0]`);
      expect(readdirSync(place)).toEqual([]);
    });

    it('gives stdin, and its end, to a real cat', async (ctx) => {
      ready(ctx);
      const t = transport();
      expect((await run(t, 'cat', 'through stdin')).stdout).toBe('through stdin');
      const started = Date.now();
      expect((await t.exec({ node: 'pve1' }, { text: 'cat', access: 'read' }, { timeoutMs: 15_000 })).timed_out).toBe(false);
      expect(Date.now() - started).toBeLessThan(10_000);
    });

    it('gets the signal to sshd for a command still running after its input ended', async (ctx) => {
      ready(ctx);
      // The shell runs a trap once sleep returns, so it needs the time to.
      const res = await transport({}, knownLine(), 2000).exec({ node: 'pve1' }, { text: `trap 'echo got-term; exit 9' TERM; echo started; i=0; while [ $i -lt 40 ]; do sleep 0.1; i=$((i+1)); done; echo finished`, access: 'read' }, { timeoutMs: 800 });
      expect(res.timed_out).toBe(true);
      expect(res.stdout).toContain('started');
      expect(res.stdout).not.toContain('finished');
      // ssh2 itself would not have sent this: the input had ended.
      expect(log).toContain('req signal');
      // The build of sshd in Git for Windows has no privilege separation, and says so instead of signalling.
      if (log.includes('session signalling requires privilege separation')) console.warn('[test] This sshd takes the signal request and refuses to act on it (no privilege separation): delivery to the command is unproven here.');
      else expect(res.stdout).toContain('got-term');
    }, 20_000);

    it('caps output and reports it', async (ctx) => {
      ready(ctx);
      const res = await transport().exec({ node: 'pve1' }, { text: `i=0; while [ $i -lt 400 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done`, access: 'read' }, { maxBytes: 1024 });
      expect(res).toMatchObject({ truncated: true, exit_code: 0 });
      expect(res.stdout).toHaveLength(1024);
    });

    it('runs many at once over one connection, within what sshd allows', async (ctx) => {
      ready(ctx);
      const before = (log.match(/Accepted publickey/g) ?? []).length;
      const t = transport();
      const results = await Promise.all(Array.from({ length: 24 }, (_, i) => run(t, `echo ${i}`)));
      expect(results.map((r) => r.stdout.trim())).toEqual(Array.from({ length: 24 }, (_, i) => String(i)));
      expect((log.match(/Accepted publickey/g) ?? []).length).toBe(before + 1);
    }, 30_000);
  });

  describe('SFTP', () => {
    it('copies a file both ways with the real sftp-server', async (ctx) => {
      ready(ctx);
      const local = join(dir, 'to_send');
      const content = Buffer.alloc(200_000, 'ab');
      writeFileSync(local, content);
      const sftp = await transport().sftp({ node: 'pve1' });
      const remote = forConfig(join(dir, 'sent'));
      await sftp.fastPut(local, remote, { mode: 0o600 });
      expect(readFileSync(join(dir, 'sent')).equals(content)).toBe(true);
      expect(await sftp.stat(remote)).toMatchObject({ size: 200_000, isFile: true });
      await sftp.fastGet(remote, join(dir, 'came_back'));
      expect(readFileSync(join(dir, 'came_back')).equals(content)).toBe(true);
      expect((await sftp.readdir(forConfig(dir))).map((e) => e.name)).toContain('sent');
      await sftp.rename(remote, `${remote}2`);
      await sftp.unlink(`${remote}2`);
      await expect(sftp.stat(remote)).rejects.toMatchObject({ type: 'not_found' });
      sftp.close();
    }, 30_000);
  });

  describe('a terminal', () => {
    it('has a real PTY, carries input and output, and reports the exit', async (ctx) => {
      ready(ctx);
      const channel = await transport().shell({ node: 'pve1' }, { command: `sh -c 'printf "tty=%s\\n" "$(tty >/dev/null && echo yes)"; read line; echo "got:$line"; exit 5'`, cols: 90, rows: 20 });
      let seen = '';
      channel.onData((chunk) => (seen += chunk.toString()));
      const closed = new Promise<{ code: number | null }>((resolve) => channel.onClose(resolve));
      await vi.waitFor(() => expect(seen).toContain('tty=yes'), { timeout: 10_000 });
      channel.write('typed\n');
      await vi.waitFor(() => expect(seen).toContain('got:typed'), { timeout: 10_000 });
      expect((await closed).code).toBe(5);
    }, 30_000);
  });

  describe('through a real MCP client', () => {
    it('pve_ssh_test and pve_ssh_exec', async (ctx) => {
      ready(ctx);
      writeFileSync(join(dir, 'known_hosts'), knownLine());
      const { call } = await connect({ env: env() });
      const test = await call('pve_ssh_test', { node: 'pve1' });
      expect(test.isError, test.text).toBe(false);
      expect(test.data.connected).toBe(true);
      expect(test.data.user).toBe(user);
      const exec = await call('pve_ssh_exec', { node: 'pve1', command: `echo out; echo err >&2; exit 2` });
      expect(exec.data).toMatchObject({ stdout: 'out\n', exit_code: 2, untrusted: true });
      expect(stderrOf(exec.data.stderr)).toBe('err\n');
    });

    it('jumps through the node to a guest: real forwarding, and the guest key checked at the far end', async (ctx) => {
      ready(ctx);
      writeFileSync(join(dir, 'known_hosts'), knownLine());
      const pin = keygen('-lf', join(dir, 'host_key.pub')).split(' ')[1]!;
      const { call } = await connect({ env: env({ PROXMOX_GUEST_SSH_KEY_FILE: clientKey, PROXMOX_GUEST_SSH_USER: user }) });
      const res = await call('pve_guest_ssh_exec', { vmid: 100, host: '127.0.0.1', port, via_node: true, fingerprint: pin, command: 'echo through the node' });
      expect(res.isError, res.text).toBe(false);
      expect(res.data).toMatchObject({ stdout: 'through the node\n', exit_code: 0 });
      keygen('-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'wrong_pin'));
      const wrongPin = keygen('-lf', join(dir, 'wrong_pin.pub')).split(' ')[1]!;
      const refused = await call('pve_guest_ssh_exec', { vmid: 100, host: '127.0.0.1', port, via_node: true, fingerprint: wrongPin, command: 'echo never' });
      expect(refused.data.error_type).toBe('host_key_mismatch');
    }, 30_000);
  });
});
