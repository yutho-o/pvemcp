import { readFileSync } from 'node:fs';
import type { Client, ClientChannel, ConnectConfig, SFTPWrapper } from 'ssh2';
import type { InstanceConfig } from '../config.js';
import { ProxmoxError } from '../proxmox/errors.js';
import type { NodeResolver } from '../proxmox/nodes.js';
import type { ExecOptions, ExecResult, GuestEndpoint, ShellChannel, ShellCommand, ShellOptions, SftpSession, SshTarget, SshTransport } from './index.js';
import { hostKeyAlgorithms, parsePublicKeyLines, verifyHostKey, type HostKeyCheck, type HostKeyInfo } from './known-hosts.js';
import { shQuote } from './quote.js';
import { wrapSftp } from './sftp.js';

export interface TransportOptions {
  /** A node connection with no channel open is closed after this long. */
  idleMs?: number;
  /** Channels at a time on one connection. OpenSSH allows 10 by default. */
  maxChannels?: number;
  keepaliveMs?: number;
  connectTimeoutMs?: number;
  /** Between the signal to a timed out command and destroying its channel. */
  killGraceMs?: number;
}

const DEFAULTS = { idleMs: 60_000, maxChannels: 8, keepaliveMs: 15_000, connectTimeoutMs: 20_000, killGraceMs: 2_000 };

/** A command past its cap goes on, so that its effect and exit code are not lost. Past this, it is stopped. */
const DRAIN_FACTOR = 16;
const MIN_DRAIN_BYTES = 64 * 1024 * 1024;

type Ssh2 = { Client: new () => Client };
let loaded: Promise<Ssh2> | undefined;

/** Only when SSH is first used: a module that fails to load must not take down a server that has it off. */
function loadSsh2(): Promise<Ssh2> {
  loaded ??= import('ssh2').then(
    (mod) => (mod as unknown as { default?: Ssh2 }).default ?? (mod as unknown as Ssh2),
    (err: Error) => {
      loaded = undefined;
      throw new ProxmoxError('ssh_unreachable', `The ssh2 module could not be loaded: ${err.message}`, { hint: 'Reinstall the dependencies of this server.' });
    },
  );
  return loaded;
}

/** A command whose channel never opened: it did not run, so trying again is safe. */
class NotStarted extends Error {}

/**
 * The host said no to a new channel. sshd frees a session slot some time after the channel has
 * closed, so that a burst can go over MaxSessions with fewer commands than that running. Nothing
 * ran, so it is worth waiting a moment. These add up to 3 seconds.
 */
const CHANNEL_RETRY_MS = [50, 150, 300, 500, 1000, 1000];
class ChannelRefused extends Error {}

class Connection {
  private active = 0;
  private readonly waiting: Array<() => void> = [];
  private idleTimer?: NodeJS.Timeout;
  closed = false;

  constructor(
    readonly client: Client,
    readonly hostKey: HostKeyInfo,
    private readonly maxChannels: number,
    private readonly idleMs: number,
  ) {
    client.on('close', () => {
      this.closed = true;
      if (this.idleTimer) clearTimeout(this.idleTimer);
      for (const wake of this.waiting.splice(0)) wake();
    });
    this.armIdle();
  }

  async acquire(): Promise<void> {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    while (this.active >= this.maxChannels && !this.closed) {
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    }
    this.active++;
  }

  /** Keeps one more slot than the caller took with acquire: for what outlives its opening, such as SFTP. */
  acquireHeld(): void {
    this.active++;
  }

  release(): void {
    this.active--;
    this.waiting.shift()?.();
    if (this.active === 0) this.armIdle();
  }

  private armIdle(): void {
    if (this.closed) return;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.client.end(), this.idleMs);
    this.idleTimer.unref();
  }
}

interface ConnectSpec {
  label: string;
  host: string;
  port: number;
  username: string;
  auth: Partial<ConnectConfig>;
  check: HostKeyCheck;
  /** The way in, when going through another host. */
  sock?: NodeJS.ReadableStream;
  /** Answer to a keyboard-interactive password prompt. */
  password?: string;
}

function mapConnectError(err: Error & { level?: string; code?: string }, spec: ConnectSpec): ProxmoxError {
  const where = `${spec.label} (${spec.host}:${spec.port})`;
  if (err.level === 'client-authentication') {
    return new ProxmoxError('ssh_auth_failed', `SSH login as ${spec.username} to ${where} was refused.`, { hint: 'Do not retry with the same credentials. The operator has to check the SSH key or password configured here.' });
  }
  if (err.level === 'client-timeout' || err.code === 'ETIMEDOUT') {
    return new ProxmoxError('ssh_timeout', `No SSH handshake from ${where} in time.`, { hint: 'The host may be down, or a firewall may be dropping the SSH port.' });
  }
  return new ProxmoxError('ssh_unreachable', `Could not reach ${where} over SSH: ${err.code ?? err.message}.`, { hint: 'Check that the host is up and, for a node, that PROXMOX_SSH_NODES gives the right address.' });
}

/** A key that cannot be used is a matter of configuration, whatever the server would say. */
function readKey(path: string, label: string): Buffer {
  try {
    return readFileSync(path);
  } catch (err) {
    throw new ProxmoxError('config_error', `The SSH key file for ${label} cannot be read: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}.`);
  }
}

/**
 * The real transport: one lazy connection per node, kept alive and closed when idle.
 * Guests get a connection of their own for each call: their credentials and host keys
 * are not those of the node, and nothing is gained by keeping them open.
 */
export class PooledSshTransport implements SshTransport {
  private readonly pool = new Map<string, Connection>();
  private readonly connecting = new Map<string, Promise<Connection>>();
  /** Dedicated to one session or one guest call. */
  private readonly dedicated = new Set<Client>();
  private readonly options: typeof DEFAULTS;
  private closing = false;
  private warnedOff = false;

  constructor(
    private readonly instance: InstanceConfig,
    private readonly nodes: NodeResolver,
    options: TransportOptions = {},
  ) {
    this.options = { ...DEFAULTS, ...options };
  }

  async exec(target: SshTarget, command: ShellCommand, opts: ExecOptions = {}): Promise<ExecResult> {
    if (target.guest) return this.execOnGuest(target.guest, command, opts);
    const text = this.withSudo(command.text);
    return this.withChannel(target.node, (conn) => this.runCommand(conn, text, command.stdin, opts));
  }

  async sftp(target: SshTarget): Promise<SftpSession> {
    const open = async (conn: Connection): Promise<SftpSession> => {
      const raw = await new Promise<SFTPWrapper>((resolve, reject) => {
        try {
          conn.client.sftp((err, sftp) => {
            if (!err) return resolve(sftp);
            if (conn.closed) return reject(new NotStarted(err.message));
            if (isChannelRefusal(err)) return reject(new ChannelRefused(err.message));
            reject(new ProxmoxError('ssh_unreachable', `Could not open SFTP on ${target.node}: ${err.message}`, { hint: 'The SFTP subsystem may be off on this host.' }));
          });
        } catch (err) {
          reject(new NotStarted((err as Error).message));
        }
      });
      // The session keeps its slot on the connection until it is closed.
      conn.acquireHeld();
      return wrapSftp(raw, this.instance.ssh.timeoutMs, () => conn.release());
    };
    return this.withChannel(target.node, open, 'SFTP');
  }

  /** Each session has its own connection: sessions last, and must not use up the channels of a node. */
  async shell(target: SshTarget, opts: ShellOptions = {}): Promise<ShellChannel> {
    const conn = await this.connectToNode(target.node);
    this.dedicated.add(conn.client);
    conn.client.once('close', () => this.dedicated.delete(conn.client));
    try {
      const stream = await this.openPty(conn, opts);
      return this.toShellChannel(conn.client, stream);
    } catch (err) {
      conn.client.end();
      throw err;
    }
  }

  async close(): Promise<void> {
    this.closing = true;
    const clients = [...this.dedicated, ...[...this.pool.values()].map((c) => c.client)];
    this.pool.clear();
    this.dedicated.clear();
    await Promise.all(
      clients.map(
        (client) =>
          new Promise<void>((resolve) => {
            const timer = setTimeout(() => {
              client.destroy();
              resolve();
            }, 1000);
            timer.unref();
            client.once('close', () => {
              clearTimeout(timer);
              resolve();
            });
            client.end();
          }),
      ),
    );
  }

  private withSudo(text: string): string {
    const { sudo, user } = this.instance.ssh;
    return sudo && user !== 'root' ? `sudo -n sh -c ${shQuote(text)}` : text;
  }

  private drop(node: string, conn: Connection): void {
    if (this.pool.get(node) === conn) this.pool.delete(node);
  }

  private async connection(node: string): Promise<Connection> {
    if (this.closing) throw new ProxmoxError('ssh_unreachable', 'This server is shutting down.');
    const live = this.pool.get(node);
    if (live && !live.closed) return live;
    this.pool.delete(node);
    let pending = this.connecting.get(node);
    if (!pending) {
      pending = this.connectToNode(node)
        .then((conn) => {
          this.pool.set(node, conn);
          conn.client.once('close', () => this.drop(node, conn));
          return conn;
        })
        .finally(() => this.connecting.delete(node));
      this.connecting.set(node, pending);
    }
    return pending;
  }

  /** A channel that did not open costs some more tries; once one has opened, nobody knows what ran. */
  private async withChannel<T>(node: string, run: (conn: Connection) => Promise<T>, what = 'a new channel'): Promise<T> {
    let lost = 0;
    let refused = 0;
    for (;;) {
      const conn = await this.connection(node);
      await conn.acquire();
      let wait = 0;
      try {
        return await run(conn);
      } catch (err) {
        if (err instanceof NotStarted) {
          this.drop(node, conn);
          if (++lost > 1) throw new ProxmoxError('ssh_unreachable', `Could not open ${what} on ${node}: ${err.message}`, { hint: 'Nothing was run.' });
        } else if (err instanceof ChannelRefused) {
          wait = CHANNEL_RETRY_MS[refused++] ?? -1;
          if (wait < 0) throw new ProxmoxError('ssh_unreachable', `The host refused ${what}: ${err.message}`, { hint: 'Nothing was run. It may have reached its session limit (MaxSessions).' });
        } else {
          throw err;
        }
      } finally {
        conn.release();
      }
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }

  private async connectToNode(node: string): Promise<Connection> {
    const { ssh } = this.instance;
    const host = await this.nodes.sshHost(node);
    if (ssh.hostKeyPolicy === 'off' && !this.warnedOff) {
      this.warnedOff = true;
      console.error('[pvemcp] warning: PROXMOX_SSH_HOST_KEY_POLICY=off: SSH host keys are not verified, so a host in the middle would go unnoticed.');
    }
    const auth: Partial<ConnectConfig> = {};
    if (ssh.keyFile) {
      auth.privateKey = readKey(ssh.keyFile, `node ${node}`);
      if (ssh.keyPassphrase) auth.passphrase = ssh.keyPassphrase;
    }
    if (ssh.password) auth.password = ssh.password;
    if (ssh.agent) auth.agent = ssh.agent;
    const pinned = ssh.fingerprints[node];
    return this.connect({
      label: `node ${node}`,
      host,
      port: ssh.port,
      username: ssh.user,
      auth,
      ...(ssh.password ? { password: ssh.password } : {}),
      check: { label: `node ${node}`, host, port: ssh.port, policy: ssh.hostKeyPolicy, knownHostsFile: ssh.knownHosts, ...(pinned ? { pinned } : {}) },
    });
  }

  private async connect(spec: ConnectSpec): Promise<Connection> {
    const { Client: SshClient } = await loadSsh2();
    return new Promise<Connection>((resolve, reject) => {
      const client = new SshClient();
      let verdict: ProxmoxError | undefined;
      let hostKey: HostKeyInfo | undefined;
      let settled = false;
      const fail = (err: ProxmoxError) => {
        if (settled) return;
        settled = true;
        reject(err);
        client.destroy();
      };
      // After the handshake this only keeps an error from being thrown: the close event that follows does the work.
      client.on('error', (err: Error & { level?: string; code?: string }) => fail(verdict ?? mapConnectError(err, spec)));
      client.on('close', () => fail(verdict ?? new ProxmoxError('ssh_unreachable', `${spec.label} (${spec.host}:${spec.port}) closed the connection during the SSH handshake.`)));
      client.on('keyboard-interactive', (_name, _instructions, _lang, prompts, finish) => {
        finish(spec.password && prompts.length === 1 ? [spec.password] : []);
      });
      client.once('ready', () => {
        if (settled) return;
        settled = true;
        resolve(new Connection(client, hostKey ?? { type: 'unknown', fingerprint: 'unknown' }, this.options.maxChannels, this.options.idleMs));
      });
      const algorithms = hostKeyAlgorithms(spec.check);
      try {
        client.connect({
          ...spec.auth,
          host: spec.host,
          port: spec.port,
          username: spec.username,
          readyTimeout: this.options.connectTimeoutMs,
          keepaliveInterval: this.options.keepaliveMs,
          keepaliveCountMax: 3,
          ...(spec.password ? { tryKeyboard: true } : {}),
          ...(algorithms ? { algorithms: { serverHostKey: algorithms as never } } : {}),
          ...(spec.sock ? { sock: spec.sock as never } : {}),
          hostVerifier: (key: Buffer) => {
            try {
              hostKey = verifyHostKey(spec.check, key);
              return true;
            } catch (err) {
              verdict = err as ProxmoxError;
              return false;
            }
          },
        });
      } catch (err) {
        // ssh2 parses the key here, so this is an encrypted key without its passphrase, or not a key at all.
        fail(new ProxmoxError('ssh_auth_failed', `The SSH credentials for ${spec.label} cannot be used: ${(err as Error).message}`, { hint: 'The operator has to check the key file and its passphrase.' }));
      }
    });
  }

  private runCommand(conn: Connection, text: string, stdin: Buffer | string | undefined, opts: ExecOptions): Promise<ExecResult> {
    const timeoutMs = opts.timeoutMs ?? this.instance.ssh.timeoutMs;
    const maxBytes = opts.maxBytes ?? this.instance.ssh.maxOutputBytes;
    const started = Date.now();
    return new Promise<ExecResult>((resolve, reject) => {
      const onChannel = (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (conn.closed) return reject(new NotStarted(err.message));
          return reject(new ChannelRefused(err.message));
        }
        const out = new CappedBuffer(maxBytes);
        const errOut = new CappedBuffer(maxBytes);
        let exitCode: number | null = null;
        let exitSignal: string | undefined;
        let sawExit = false;
        let timedOut = false;
        let overflowed = false;
        let settled = false;
        let graceTimer: NodeJS.Timeout | undefined;

        const finish = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (graceTimer) clearTimeout(graceTimer);
          if (!sawExit && !timedOut && !overflowed && conn.closed) {
            reject(new ProxmoxError('ssh_unreachable', 'The SSH connection was lost while the command ran.', { hint: 'It may or may not have finished. Check before running it again.', details: { stdout: out.text().slice(-2000), stderr: errOut.text().slice(-2000) } }));
            return;
          }
          resolve({
            stdout: out.text(),
            stderr: errOut.text(),
            exit_code: exitCode,
            ...(exitSignal ? { signal: exitSignal } : {}),
            truncated: out.truncated || errOut.truncated,
            duration_ms: Date.now() - started,
            timed_out: timedOut,
            host_key: conn.hostKey,
          });
        };
        // Signal first, for the command to end cleanly; then the channel goes, whatever it does.
        const stop = () => {
          sendSignal(stream, 'TERM');
          graceTimer = setTimeout(() => {
            stream.close();
            stream.destroy();
            graceTimer = setTimeout(finish, this.options.killGraceMs);
          }, this.options.killGraceMs);
        };
        const timer = setTimeout(() => {
          timedOut = true;
          stop();
        }, timeoutMs);
        const drainLimit = Math.max(maxBytes * DRAIN_FACTOR, MIN_DRAIN_BYTES);
        const onData = (buffer: CappedBuffer) => (chunk: Buffer) => {
          buffer.push(chunk);
          if (!overflowed && !timedOut && out.seen + errOut.seen > drainLimit) {
            overflowed = true;
            stop();
          }
        };

        stream.on('data', onData(out));
        stream.stderr.on('data', onData(errOut));
        stream.on('exit', (code: number | null, signal?: string) => {
          sawExit = true;
          exitCode = typeof code === 'number' ? code : null;
          if (signal) exitSignal = signal;
        });
        stream.on('close', finish);
        stream.on('error', () => undefined);
        // Always an end of input: a command reading stdin would otherwise wait until the timeout.
        if (stdin === undefined) stream.end();
        else stream.end(stdin);
      };
      try {
        conn.client.exec(text, onChannel);
      } catch (err) {
        reject(new NotStarted((err as Error).message));
      }
    });
  }

  private openPty(conn: Connection, opts: ShellOptions): Promise<ClientChannel> {
    const window = { cols: opts.cols ?? 120, rows: opts.rows ?? 40, term: opts.term ?? 'xterm' };
    const { sudo, user } = this.instance.ssh;
    const elevate = sudo && user !== 'root';
    const command = opts.command ? (elevate ? `sudo -n ${opts.command}` : opts.command) : elevate ? 'sudo -n -i' : undefined;
    return new Promise<ClientChannel>((resolve, reject) => {
      const done = (err: Error | undefined, stream: ClientChannel) => (err ? reject(new ProxmoxError('ssh_unreachable', `Could not open a terminal: ${err.message}`)) : resolve(stream));
      if (command) conn.client.exec(command, { pty: window }, done);
      else conn.client.shell(window, done);
    });
  }

  private toShellChannel(client: Client, stream: ClientChannel): ShellChannel {
    const early: Buffer[] = [];
    const dataListeners: Array<(chunk: Buffer) => void> = [];
    const closeListeners: Array<(info: { code: number | null; signal?: string }) => void> = [];
    let closed: { code: number | null; signal?: string } | undefined;
    let code: number | null = null;
    let signal: string | undefined;
    const announce = (info: { code: number | null; signal?: string }) => {
      closed = info;
      for (const listener of closeListeners) listener(info);
    };
    const onChunk = (chunk: Buffer) => {
      if (dataListeners.length === 0) early.push(chunk);
      else for (const listener of dataListeners) listener(chunk);
    };
    stream.on('data', onChunk);
    stream.stderr.on('data', onChunk);
    stream.on('exit', (exitCode: number | null, exitSignal?: string) => {
      code = typeof exitCode === 'number' ? exitCode : null;
      signal = exitSignal;
    });
    stream.on('error', () => undefined);
    stream.on('close', () => {
      if (!closed) announce({ code, ...(signal ? { signal } : {}) });
      client.end();
    });
    client.once('close', () => {
      if (!closed) announce({ code: null });
    });
    return {
      write: (data) => void stream.write(data),
      onData: (listener) => {
        dataListeners.push(listener);
        for (const chunk of early.splice(0)) listener(chunk);
      },
      onClose: (listener) => {
        if (closed) listener(closed);
        else closeListeners.push(listener);
      },
      resize: (cols, rows) => void stream.setWindow(rows, cols, 0, 0),
      close: () => {
        stream.close();
        client.end();
      },
    };
  }

  private async execOnGuest(guest: GuestEndpoint, command: ShellCommand, opts: ExecOptions): Promise<ExecResult> {
    const conn = await this.connectToGuest(guest);
    this.dedicated.add(conn.client);
    try {
      await conn.acquire();
      try {
        return await this.runCommand(conn, command.text, command.stdin, opts);
      } catch (err) {
        if (err instanceof NotStarted || err instanceof ChannelRefused) throw new ProxmoxError('ssh_unreachable', `Could not open a channel on guest ${guest.vmid}: ${err.message}`, { hint: 'Nothing was run.' });
        throw err;
      } finally {
        conn.release();
      }
    } finally {
      this.dedicated.delete(conn.client);
      conn.client.end();
    }
  }

  private async connectToGuest(guest: GuestEndpoint): Promise<Connection> {
    const { ssh } = this.instance;
    // The credentials of the node never go to a guest: whoever runs that guest could collect them.
    const auth: Partial<ConnectConfig> = {};
    if (ssh.guestKeyFile) auth.privateKey = readKey(ssh.guestKeyFile, `guest ${guest.vmid}`);
    if (ssh.guestPassword) auth.password = ssh.guestPassword;
    if (!auth.privateKey && !auth.password) {
      throw new ProxmoxError('config_error', 'No credential is set for SSH to guests.', { hint: 'The operator can set PROXMOX_GUEST_SSH_KEY_FILE or PROXMOX_GUEST_SSH_PASSWORD. pve_lxc_exec reaches a container without one.' });
    }
    const label = `guest ${guest.vmid}`;
    const check: HostKeyCheck = {
      label,
      host: guest.host,
      port: guest.port,
      policy: ssh.hostKeyPolicy,
      knownHostsFile: ssh.knownHosts,
      ...(guest.fingerprint ? { pinned: guest.fingerprint } : {}),
      ...(guest.hostKeys ? { allowedKeys: parsePublicKeyLines(guest.hostKeys.join('\n')) } : {}),
    };
    const spec: ConnectSpec = { label, host: guest.host, port: guest.port, username: guest.user, auth, check, ...(ssh.guestPassword ? { password: ssh.guestPassword } : {}) };
    if (!guest.viaNode) return this.connect(spec);

    const jump = await this.connection(guest.viaNode);
    await jump.acquire();
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        jump.release();
      }
    };
    try {
      const sock = await new Promise<ClientChannel>((resolve, reject) => {
        try {
          jump.client.forwardOut('127.0.0.1', 0, guest.host, guest.port, (err, stream) =>
            err ? reject(new ProxmoxError('ssh_unreachable', `Node ${guest.viaNode} could not reach ${guest.host}:${guest.port}: ${err.message}`, { hint: 'The guest may be down, or the node may not allow TCP forwarding (AllowTcpForwarding).' })) : resolve(stream),
          );
        } catch (err) {
          reject(new ProxmoxError('ssh_unreachable', `Could not go through node ${guest.viaNode}: ${(err as Error).message}`));
        }
      });
      const conn = await this.connect({ ...spec, sock });
      conn.client.once('close', release);
      return conn;
    } catch (err) {
      release();
      throw err;
    }
  }
}

/**
 * Channel.signal of ssh2 does nothing once the input has ended, and here it always has: the
 * protocol allows the request anyway, but only the layer below sends it. If that layer ever
 * moves, the command is still stopped by closing its channel.
 */
function sendSignal(stream: ClientChannel, name: string): void {
  const channel = stream as unknown as { outgoing?: { id?: number; state?: string }; _client?: { _protocol?: { signal?: (id: number, signal: string) => void } } };
  const state = channel.outgoing?.state;
  if (state !== 'open' && state !== 'eof') return;
  try {
    channel._client?._protocol?.signal?.(channel.outgoing!.id!, name);
  } catch {
    /* the channel is already going */
  }
}

/** What ssh2 reports when the host answers a channel open with a failure. */
function isChannelRefusal(err: Error): boolean {
  return /Channel open failure/i.test(err.message);
}

/** Keeps the start of a stream up to a size, and counts the rest. */
class CappedBuffer {
  private readonly chunks: Buffer[] = [];
  private kept = 0;
  seen = 0;

  constructor(private readonly max: number) {}

  push(chunk: Buffer): void {
    this.seen += chunk.length;
    const room = this.max - this.kept;
    if (room <= 0) return;
    const piece = chunk.length <= room ? chunk : chunk.subarray(0, room);
    this.chunks.push(piece);
    this.kept += piece.length;
  }

  get truncated(): boolean {
    return this.seen > this.kept;
  }

  text(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}
