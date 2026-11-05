import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync, writeSync, type Stats } from 'node:fs';
import { connect as netConnect, type AddressInfo, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, normalize, posix } from 'node:path';
import ssh2 from 'ssh2';
import type { AuthenticationType, Connection, ParsedKey, ServerChannel, Session, SFTPWrapper } from 'ssh2';

const { Server, utils } = ssh2;
const { flagsToString, STATUS_CODE } = (utils as unknown as { sftp: { flagsToString(flags: number): string; STATUS_CODE: Record<string, number> } }).sftp;

/**
 * A real SSH server on a local port, built on the Server of ssh2: real key exchange, real host
 * keys, real channels. Commands are answered by scripted handlers or, with a ShellSandbox, by a
 * real POSIX shell confined to a temp directory.
 */

export interface GeneratedKey {
  /** OpenSSH format, for a server or a key file. */
  private: string;
  /** One line: type base64 comment. */
  public: string;
  blob: Buffer;
  fingerprint: string;
}

export function generateKey(type: 'ed25519' | 'rsa' | 'ecdsa' = 'ed25519', opts: { passphrase?: string; comment?: string } = {}): GeneratedKey {
  const generate = () =>
    type === 'ed25519'
      ? utils.generateKeyPairSync('ed25519', { ...(opts.passphrase ? { passphrase: opts.passphrase, cipher: 'aes256-ctr' } : {}), comment: opts.comment ?? 'test' })
      : type === 'ecdsa'
        ? utils.generateKeyPairSync('ecdsa', { bits: 256, comment: opts.comment ?? 'test' })
        : utils.generateKeyPairSync('rsa', { bits: 2048, comment: opts.comment ?? 'test' });
  // The generator of ssh2 drops a leading zero byte of an ed25519 public key, as if it were a
  // number: about one key in 300 comes out malformed. Only this helper uses it.
  let pair = generate();
  while (utils.parseKey(pair.private, opts.passphrase) instanceof Error) pair = generate();
  const blob = Buffer.from(pair.public.trim().split(/\s+/)[1]!, 'base64');
  return { private: pair.private, public: pair.public.trim(), blob, fingerprint: `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}` };
}

export interface ExecRequest {
  command: string;
  stdin: Buffer;
  user: string;
  pty: boolean;
}

export interface ExecReply {
  stdout?: string | Buffer;
  stderr?: string;
  code?: number;
  /** Ends with this signal instead of a code. */
  signal?: string;
  delayMs?: number;
  /** Never exits on its own. */
  hang?: boolean;
  /** Writes this many bytes to stdout, in pieces. */
  flood?: number;
}

export type ExecHandler = (req: ExecRequest) => ExecReply | Promise<ExecReply>;

export interface FakeUser {
  password?: string;
  keys?: string[];
  /** Offer only keyboard-interactive for this password. */
  keyboardOnly?: boolean;
}

export interface FakeSshOptions {
  hostKey?: GeneratedKey;
  /** More host keys, as a real server has. */
  extraHostKeys?: GeneratedKey[];
  users?: Record<string, FakeUser>;
  sandbox?: ShellSandbox;
  /** Where SFTP paths land when there is no sandbox. */
  sftpRoot?: string;
  allowForwarding?: boolean;
  /** Answers every channel open with a failure, as a host at MaxSessions does. */
  refuseChannels?: boolean;
  /** Refuses this many channels and then takes them, as a host does with a session slot not yet freed. */
  refuseFirstChannels?: number;
  /** Containers that pct enter refuses, in a PTY session: it prints and exits as for a stopped one. */
  ptyStoppedGuests?: number[];
}

export const FAKE_SSH_PASSWORD = 'fake-ssh-password';

interface ScriptedExec {
  pattern: RegExp;
  handler: ExecHandler;
}

export class FakeSsh {
  readonly hostKey: GeneratedKey;
  private readonly server: InstanceType<typeof Server>;
  private readonly users: Record<string, FakeUser>;
  private readonly scripted: ScriptedExec[] = [];
  private readonly clients = new Set<Connection>();
  readonly options: FakeSshOptions;
  port = 0;
  /** Connections that got past the TCP accept. */
  connections = 0;
  readonly authAttempts: Array<{ user: string; method: string; password?: string }> = [];
  readonly commands: ExecRequest[] = [];
  readonly signals: string[] = [];
  readonly channelsClosed: string[] = [];
  readonly sftpOps: Array<{ op: string; path: string; mode?: number; flags?: string }> = [];
  readonly forwards: Array<{ host: string; port: number }> = [];
  readonly ptys: Array<{ command?: string; cols: number; rows: number; term: string }> = [];
  readonly windowChanges: Array<{ cols: number; rows: number }> = [];
  readonly typed: string[] = [];
  /** Sessions alive right now. */
  openChannels = 0;
  maxOpenChannels = 0;
  private refusalsLeft: number;

  constructor(options: FakeSshOptions = {}) {
    this.options = options;
    this.refusalsLeft = options.refuseFirstChannels ?? 0;
    this.hostKey = options.hostKey ?? generateKey();
    this.users = options.users ?? { root: { password: FAKE_SSH_PASSWORD } };
    const hostKeys = [this.hostKey, ...(options.extraHostKeys ?? [])].map((k) => k.private);
    this.server = new Server({ hostKeys }, (client) => this.onClient(client));
  }

  async start(): Promise<this> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }

  async stop(): Promise<void> {
    this.dropConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** Cuts every connection without a goodbye, as a host going down does. */
  dropConnections(): void {
    for (const client of this.clients) (client as unknown as { _sock: Socket })._sock.destroy();
  }

  /** A scripted answer for commands matching this. First match wins. */
  on(pattern: RegExp | string, handler: ExecHandler | ExecReply): this {
    const regex = typeof pattern === 'string' ? new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) : pattern;
    this.scripted.push({ pattern: regex, handler: typeof handler === 'function' ? handler : () => handler });
    return this;
  }

  /** known_hosts line for this server, under the name its port gives it. */
  knownHostsLine(host = '127.0.0.1'): string {
    return `[${host}]:${this.port} ${this.hostKey.public}`;
  }

  private onClient(client: Connection): void {
    this.connections++;
    this.clients.add(client);
    let user = '';
    client.on('error', () => undefined);
    client.on('close', () => this.clients.delete(client));
    // sshd takes a signal for as long as the command runs (OpenSSH 7.9 and up). The Server of ssh2
    // drops every request on a session whose input has ended, so this one is caught ahead of it.
    const internals = client as unknown as { _protocol: { _handlers: Record<string, (...args: unknown[]) => void> }; _chanMgr: { get(id: unknown): { emit?: (...args: unknown[]) => void } | undefined } };
    const handlers = internals._protocol._handlers;
    const onRequest = handlers.CHANNEL_REQUEST!;
    handlers.CHANNEL_REQUEST = (p, recipient, type, wantReply, data) => {
      if (type === 'signal') internals._chanMgr.get(recipient)?.emit?.('signal', undefined, undefined, { name: data });
      else onRequest(p, recipient, type, wantReply, data);
    };
    client.on('authentication', (ctx) => {
      user = ctx.username;
      const account = this.users[ctx.username];
      const methods: AuthenticationType[] = account?.keyboardOnly ? ['keyboard-interactive'] : ['password', 'publickey', 'keyboard-interactive'];
      const entry: { user: string; method: string; password?: string } = { user: ctx.username, method: ctx.method };
      this.authAttempts.push(entry);
      if (ctx.method === 'password') {
        entry.password = ctx.password;
        return account?.password === ctx.password && !account?.keyboardOnly ? ctx.accept() : ctx.reject(methods);
      }
      if (ctx.method === 'publickey') {
        const allowed = (account?.keys ?? []).map((text) => utils.parseKey(text)).filter((k): k is ParsedKey => !(k instanceof Error));
        const match = allowed.find((k) => k.getPublicSSH().equals(ctx.key.data));
        if (!match) return ctx.reject(methods);
        if (!ctx.signature) return ctx.accept();
        const ok = match.verify(ctx.blob!, ctx.signature, ctx.hashAlgo);
        return ok === true ? ctx.accept() : ctx.reject(methods);
      }
      if (ctx.method === 'keyboard-interactive' && account?.password) {
        return ctx.prompt([{ prompt: 'Password: ', echo: false }], (answers) => {
          entry.password = answers[0];
          return answers[0] === account.password ? ctx.accept() : ctx.reject(methods);
        });
      }
      return ctx.reject(methods);
    });
    client.on('ready', () => {
      client.on('session', (accept, reject) => {
        if (this.options.refuseChannels || this.refusalsLeft-- > 0) return reject();
        this.onSession(accept(), user);
      });
      client.on('tcpip', (accept, reject, info) => {
        this.forwards.push({ host: info.destIP, port: info.destPort });
        if (this.options.allowForwarding === false) return reject();
        const out = netConnect(info.destPort, info.destIP);
        out.once('connect', () => {
          const channel = accept();
          channel.pipe(out).pipe(channel);
          channel.on('error', () => out.destroy());
          out.on('close', () => channel.close());
        });
        out.once('error', () => reject());
      });
    });
  }

  private onSession(session: Session, user: string): void {
    let pty: { cols: number; rows: number; term: string } | undefined;
    let channel: ServerChannel | undefined;
    let child: ChildProcess | undefined;
    session.on('pty', (accept, _reject, info) => {
      pty = { cols: info.cols, rows: info.rows, term: info.term };
      accept?.();
    });
    session.on('window-change', (accept, _reject, info) => {
      this.windowChanges.push({ cols: info.cols, rows: info.rows });
      accept?.();
    });
    session.on('signal', (accept, _reject, info) => {
      this.signals.push(info.name);
      child?.kill();
      accept?.();
    });
    session.on('shell', (accept) => {
      channel = accept();
      this.ptys.push({ cols: pty?.cols ?? 0, rows: pty?.rows ?? 0, term: pty?.term ?? '' });
      this.runPty(channel, undefined);
    });
    session.on('sftp', (accept, reject) => {
      const root = this.options.sandbox?.root ?? this.options.sftpRoot;
      if (!root) return reject();
      this.serveSftp(accept(), root);
    });
    session.on('exec', (accept, _reject, info) => {
      channel = accept();
      const stream = channel;
      this.track(stream, info.command);
      if (pty) {
        this.ptys.push({ command: info.command, ...pty });
        this.commands.push({ command: info.command, stdin: Buffer.alloc(0), user, pty: true });
        this.runPty(stream, info.command);
        return;
      }
      const chunks: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => {
        const req: ExecRequest = { command: info.command, stdin: Buffer.concat(chunks), user, pty: false };
        this.commands.push(req);
        void this.answer(stream, req, (c) => {
          child = c;
        });
      });
    });
  }

  private track(stream: ServerChannel, command: string): void {
    this.openChannels++;
    this.maxOpenChannels = Math.max(this.maxOpenChannels, this.openChannels);
    stream.once('close', () => {
      this.openChannels--;
      this.channelsClosed.push(command);
    });
  }

  private async answer(stream: ServerChannel, req: ExecRequest, onChild: (child: ChildProcess) => void): Promise<void> {
    const scripted = this.scripted.find((s) => s.pattern.test(req.command));
    if (scripted) {
      const reply = await scripted.handler(req);
      if (reply.delayMs) await new Promise((resolve) => setTimeout(resolve, reply.delayMs));
      if (reply.stderr) stream.stderr.write(reply.stderr);
      if (reply.stdout) stream.write(reply.stdout);
      if (reply.flood) {
        const piece = Buffer.alloc(32 * 1024, 'x');
        for (let sent = 0; sent < reply.flood; sent += piece.length) {
          if (!stream.write(piece)) await new Promise((resolve) => stream.once('drain', resolve));
        }
      }
      if (reply.hang) return;
      if (reply.signal) stream.exit(reply.signal);
      else stream.exit(reply.code ?? 0);
      stream.end();
      return;
    }
    if (!this.options.sandbox) {
      stream.stderr.write(`sh: ${req.command.split(' ')[0]}: not found\n`);
      stream.exit(127);
      stream.end();
      return;
    }
    const child = this.options.sandbox.run(req.command, req.stdin, (stdout, stderr) => {
      if (stderr) stream.stderr.write(stderr);
      if (stdout) stream.write(stdout);
    }, (code) => {
      stream.exit(code ?? 255);
      stream.end();
    });
    onChild(child);
    stream.once('close', () => {
      if (child.exitCode === null) child.kill();
    });
  }

  /** A small scripted terminal: echoes what is typed, and understands a few commands. */
  private runPty(stream: ServerChannel, command: string | undefined): void {
    const stopped = /^(?:sudo -n )?pct enter '?(\d+)'?$/.exec(command ?? '');
    if (stopped && this.options.ptyStoppedGuests?.includes(Number(stopped[1]))) {
      stream.write(`CT ${stopped[1]} not running\r\n`);
      stream.exit(255);
      stream.end();
      return;
    }
    stream.write(command ? `[${command}]\r\nfake# ` : 'fake# ');
    let line = '';
    stream.on('data', (chunk: Buffer) => {
      for (const char of chunk.toString('utf8')) {
        if (char === '\x03') {
          this.typed.push('^C');
          stream.write('^C\r\nfake# ');
          line = '';
        } else if (char === '\x04') {
          stream.exit(0);
          stream.end();
          return;
        } else if (char === '\r' || char === '\n') {
          this.typed.push(line);
          stream.write('\r\n');
          const flood = /^flood (\d+)$/.exec(line);
          if (line === 'exit') {
            stream.exit(0);
            stream.end();
            return;
          }
          if (flood) stream.write(Buffer.alloc(Number(flood[1]), 'y'));
          else if (line === 'color') stream.write('\x1b[31mred\x1b[0m');
          else if (line) stream.write(`ran: ${line}`);
          stream.write('\r\nfake# ');
          line = '';
        } else {
          line += char;
          stream.write(char);
        }
      }
    });
  }

  private serveSftp(sftp: SFTPWrapper, root: string): void {
    const handles = new Map<string, { fd?: number; dir?: string; listed?: boolean }>();
    let nextHandle = 0;
    const toLocal = (remote: string): string | undefined => {
      const clean = posix.normalize(remote);
      const local = normalize(join(root, clean));
      return local === normalize(root) || local.startsWith(normalize(root) + (delimiter === ';' ? '\\' : '/')) ? local : undefined;
    };
    const fail = (id: number, err: unknown) => {
      const code = (err as NodeJS.ErrnoException).code;
      sftp.status(id, code === 'ENOENT' ? STATUS_CODE.NO_SUCH_FILE! : code === 'EACCES' || code === 'EPERM' ? STATUS_CODE.PERMISSION_DENIED! : STATUS_CODE.FAILURE!);
    };
    const attrs = (s: Stats) => ({ mode: s.mode, uid: 0, gid: 0, size: s.size, atime: Math.floor(s.atimeMs / 1000), mtime: Math.floor(s.mtimeMs / 1000) });
    const withPath = (id: number, remote: string, run: (local: string) => void) => {
      const local = toLocal(remote);
      if (!local) return sftp.status(id, STATUS_CODE.PERMISSION_DENIED!);
      try {
        run(local);
      } catch (err) {
        fail(id, err);
      }
    };
    const newHandle = (entry: { fd?: number; dir?: string }) => {
      const handle = Buffer.alloc(4);
      handle.writeUInt32BE(nextHandle++);
      handles.set(handle.toString('hex'), entry);
      return handle;
    };
    sftp.on('OPEN', (id, path, flags, openAttrs) => {
      this.sftpOps.push({ op: 'open', path, flags: flagsToString(flags), ...(openAttrs?.mode !== undefined ? { mode: openAttrs.mode } : {}) });
      withPath(id, path, (local) => {
        const name = flagsToString(flags);
        if (name.includes('w') || name.includes('a')) mkdirSync(dirname(local), { recursive: true });
        sftp.handle(id, newHandle({ fd: openSync(local, name, openAttrs?.mode ?? 0o666) }));
      });
    });
    sftp.on('WRITE', (id, handle, offset, data) => {
      const entry = handles.get(handle.toString('hex'));
      if (entry?.fd === undefined) return sftp.status(id, STATUS_CODE.FAILURE!);
      writeSync(entry.fd, data, 0, data.length, offset);
      sftp.status(id, STATUS_CODE.OK!);
    });
    sftp.on('READ', (id, handle, offset, length) => {
      const entry = handles.get(handle.toString('hex'));
      if (entry?.fd === undefined) return sftp.status(id, STATUS_CODE.FAILURE!);
      const buffer = Buffer.alloc(length);
      const read = readSync(entry.fd, buffer, 0, length, offset);
      if (read === 0) return sftp.status(id, STATUS_CODE.EOF!);
      sftp.data(id, buffer.subarray(0, read));
    });
    sftp.on('CLOSE', (id, handle) => {
      const entry = handles.get(handle.toString('hex'));
      if (entry?.fd !== undefined) closeSync(entry.fd);
      handles.delete(handle.toString('hex'));
      sftp.status(id, STATUS_CODE.OK!);
    });
    sftp.on('FSTAT', (id, handle) => {
      const entry = handles.get(handle.toString('hex'));
      if (entry?.fd === undefined) return sftp.status(id, STATUS_CODE.FAILURE!);
      sftp.attrs(id, attrs(fstatSync(entry.fd)));
    });
    sftp.on('FSETSTAT', (id, handle, setAttrs) => {
      const entry = handles.get(handle.toString('hex'));
      if (entry?.fd !== undefined && setAttrs.size !== undefined) ftruncateSync(entry.fd, setAttrs.size);
      this.sftpOps.push({ op: 'fsetstat', path: '', ...(setAttrs.mode !== undefined ? { mode: setAttrs.mode } : {}) });
      sftp.status(id, STATUS_CODE.OK!);
    });
    const stat = (id: number, path: string) => withPath(id, path, (local) => sftp.attrs(id, attrs(statSync(local))));
    sftp.on('STAT', stat);
    sftp.on('LSTAT', stat);
    sftp.on('SETSTAT', (id, path, setAttrs) => {
      this.sftpOps.push({ op: 'setstat', path, ...(setAttrs.mode !== undefined ? { mode: setAttrs.mode } : {}) });
      sftp.status(id, STATUS_CODE.OK!);
    });
    sftp.on('REMOVE', (id, path) => {
      this.sftpOps.push({ op: 'remove', path });
      withPath(id, path, (local) => {
        unlinkSync(local);
        sftp.status(id, STATUS_CODE.OK!);
      });
    });
    sftp.on('RENAME', (id, from, to) => {
      this.sftpOps.push({ op: 'rename', path: from });
      withPath(id, from, (local) =>
        withPath(id, to, (target) => {
          renameSync(local, target);
          sftp.status(id, STATUS_CODE.OK!);
        }),
      );
    });
    sftp.on('REALPATH', (id, path) => {
      const clean = posix.normalize(path === '.' ? '/' : path);
      sftp.name(id, [{ filename: clean, longname: clean, attrs: {} as never }]);
    });
    sftp.on('OPENDIR', (id, path) => {
      withPath(id, path, (local) => {
        statSync(local);
        sftp.handle(id, newHandle({ dir: local }));
      });
    });
    sftp.on('READDIR', (id, handle) => {
      const entry = handles.get(handle.toString('hex'));
      if (!entry?.dir) return sftp.status(id, STATUS_CODE.FAILURE!);
      if (entry.listed) return sftp.status(id, STATUS_CODE.EOF!);
      entry.listed = true;
      const dir = entry.dir;
      sftp.name(id, readdirSync(dir).map((name) => ({ filename: name, longname: name, attrs: attrs(statSync(join(dir, name))) as never })));
    });
  }
}

/** A port that accepts and then says nothing: what a firewall or a hung host looks like. */
export { createServer as createSilentServer } from 'node:net';

/** A POSIX shell to run scripts in. Dash where there is one: it has no bash extensions to hide a mistake. */
export interface PosixShell {
  /** To spawn. */
  path: string;
  /** Inside the shell's own view of paths, for the wrappers. */
  name: string;
}

export function findPosixShell(): PosixShell | undefined {
  const fixed = process.env.PVEMCP_TEST_SH;
  if (fixed && existsSync(fixed)) return { path: fixed, name: fixed };
  if (process.platform !== 'win32') {
    for (const path of ['/usr/bin/dash', '/bin/dash', '/bin/sh', '/usr/bin/sh']) if (existsSync(path)) return { path, name: path };
    return undefined;
  }
  const programFiles = process.env.ProgramFiles ?? 'C:\\Program Files';
  const candidates = [join(programFiles, 'Git', 'usr', 'bin', 'dash.exe'), join(programFiles, 'Git', 'usr', 'bin', 'sh.exe')];
  for (const dir of (process.env.PATH ?? '').split(';')) {
    // Not System32 or WindowsApps: bash there means WSL, a whole other machine.
    if (dir && !/system32|windowsapps/i.test(dir)) candidates.push(join(dir, 'dash.exe'), join(dir, 'sh.exe'));
  }
  const path = candidates.find((c) => existsSync(c));
  if (!path) return undefined;
  return { path, name: /dash\.exe$/i.test(path) ? '/usr/bin/dash' : '/usr/bin/sh' };
}

export type Distro = 'debian' | 'ubuntu' | 'alpine' | 'rhel' | 'arch' | 'bare';

/** Commands every sandboxed container has, each recording its arguments before running the real one. */
const CORE_COMMANDS = ['cat', 'head', 'tail', 'wc', 'tr', 'ls', 'rm', 'mv', 'cp', 'mkdir', 'mktemp', 'readlink', 'stat', 'date', 'df', 'du', 'ps', 'uname', 'hostname', 'id', 'grep', 'sed', 'cut', 'touch', 'sort', 'sleep'];

export interface LoggedCall {
  /** The command name, then its arguments, exactly as it got them. */
  argv: string[];
}

/**
 * A temp directory holding a fake host: a pct that really runs what it is given, and recording
 * stand-ins for everything a distribution has, on a PATH with nothing else on it.
 *
 * Nothing leaves the directory: command text has its absolute paths moved under it before the
 * shell sees it, as if chrooted, SFTP is rooted there, and the shell starts there.
 */
export class ShellSandbox {
  readonly root: string;
  readonly rootPosix: string;
  private readonly nodeLog: string;
  private readonly ctLog: string;
  private distroName: Distro = 'debian';
  /** Goes into the environment of commands, to tell apart what runs on the node and in the container. */
  private readonly shebang: string;
  private readonly children = new Set<ChildProcess>();

  constructor(readonly shell: PosixShell) {
    this.root = mkdtempSync(join(tmpdir(), 'pvemcp-sandbox-'));
    for (const dir of ['bin', 'core', 'stubs', 'ct', 'tmp', 'etc/ssh', 'var/log', 'run', 'root', 'home', 'proc', 'state', 'usr/sbin', 'scripts']) mkdirSync(join(this.root, dir), { recursive: true });
    this.nodeLog = join(this.root, 'state', 'node.log');
    this.ctLog = join(this.root, 'state', 'ct.log');
    writeFileSync(this.nodeLog, '');
    writeFileSync(this.ctLog, '');
    this.shebang = `#!${shell.name}`;
    const probe = spawnSync(shell.path, ['-c', `cd "$1" && pwd -P`, 'sh', this.root], { encoding: 'utf8' });
    if (probe.status !== 0) throw new Error(`The test shell does not work: ${probe.stderr}`);
    this.rootPosix = probe.stdout.trim();
    this.writeCore();
    this.writeNodeCommands();
    this.writeFixtures();
    this.useDistro('debian');
  }

  /** The state of this sandbox as tests set it: guests that are stopped, and so on. */
  stopGuest(vmid: number): void {
    writeFileSync(join(this.root, 'state', `stopped-${vmid}`), '');
  }

  startGuest(vmid: number): void {
    rmSync(join(this.root, 'state', `stopped-${vmid}`), { force: true });
  }

  flag(name: string, value = true): void {
    const file = join(this.root, 'state', name);
    if (value) writeFileSync(file, '');
    else rmSync(file, { force: true });
  }

  file(path: string): string {
    return join(this.root, ...path.split('/').filter(Boolean));
  }

  write(path: string, content: string | Buffer): void {
    const file = this.file(path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
  }

  read(path: string): string {
    return readFileSync(this.file(path), 'utf8');
  }

  exists(path: string): boolean {
    return existsSync(this.file(path));
  }

  remove(): void {
    for (const child of this.children) child.kill();
    rmSync(this.root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }

  private parseLog(file: string): LoggedCall[] {
    return readFileSync(file, 'utf8')
      .split('\x1e')
      .filter((record) => record.length > 0)
      .map((record) => ({ argv: record.split('\x1f').slice(0, -1).map((a) => this.unmap(a)) }));
  }

  /** Every call on the node, such as pct and sudo. */
  nodeCalls(): LoggedCall[] {
    return this.parseLog(this.nodeLog);
  }

  /** Every call inside a container, with the path of the sandbox taken off. */
  ctCalls(name?: string): LoggedCall[] {
    const calls = this.parseLog(this.ctLog);
    return name ? calls.filter((c) => c.argv[0] === name) : calls;
  }

  clearLogs(): void {
    writeFileSync(this.nodeLog, '');
    writeFileSync(this.ctLog, '');
  }

  private unmap(text: string): string {
    return text.split(this.rootPosix).join('');
  }

  /** What chroot would do: absolute paths land in the sandbox. */
  private remap(command: string): string {
    return command.replace(/(?<![\w./~-])\/(etc|var|tmp|run|usr|root|home|proc|srv|opt|mnt)(?=[/'"\s;)]|$)/g, (_m, top: string) => `${this.rootPosix}/${top}`);
  }

  private env(): NodeJS.ProcessEnv {
    const usrBin = process.platform === 'win32' ? join(dirname(this.shell.path)) : '/usr/bin';
    const toPosix = (dir: string) => `${this.rootPosix}/${dir}`;
    return {
      PATH: process.platform === 'win32' ? [join(this.root, 'bin'), join(this.root, 'core'), usrBin].join(delimiter) : [join(this.root, 'bin'), join(this.root, 'core'), usrBin, '/bin'].join(delimiter),
      SANDBOX_ROOT: this.rootPosix,
      SANDBOX_NODE_LOG: `${this.rootPosix}/state/node.log`,
      SANDBOX_CT_LOG: `${this.rootPosix}/state/ct.log`,
      CT_PATH: `${toPosix(`distro-${this.distroName}`)}:${toPosix('core')}`,
      HOME: toPosix('root'),
      LC_ALL: 'C.UTF-8',
      // Windows needs these to start anything at all.
      ...(process.platform === 'win32' ? { SYSTEMROOT: process.env.SYSTEMROOT, TEMP: this.root, TMP: this.root } : {}),
    };
  }

  /** As sshd does with a command. The text goes through a file: nothing here gets between it and the shell. */
  run(command: string, stdin: Buffer, onOutput: (stdout: Buffer | undefined, stderr: Buffer | undefined) => void, onExit: (code: number | null) => void): ChildProcess {
    const script = join(this.root, 'scripts', `${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
    writeFileSync(script, this.remap(command));
    const child = spawn(this.shell.path, [script], { cwd: join(this.root, 'ct'), env: this.env(), stdio: 'pipe', windowsHide: true });
    this.children.add(child);
    const unmap = (chunk: Buffer) => Buffer.from(this.unmap(chunk.toString('utf8')));
    child.stdout.on('data', (chunk: Buffer) => onOutput(unmap(chunk), undefined));
    child.stderr.on('data', (chunk: Buffer) => onOutput(undefined, unmap(chunk)));
    child.stdin.on('error', () => undefined);
    child.stdin.end(stdin);
    child.on('error', (err) => {
      onOutput(undefined, Buffer.from(String(err)));
      onExit(127);
    });
    child.on('close', (code) => {
      this.children.delete(child);
      rmSync(script, { force: true });
      onExit(code);
    });
    return child;
  }

  private spy(name: string, log: 'SANDBOX_CT_LOG' | 'SANDBOX_NODE_LOG', body: string): string {
    return [
      this.shebang,
      `{ printf '%s\\037' ${name}; for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\036'; } >> "$${log}"`,
      body,
      '',
    ].join('\n');
  }

  private writeCore(): void {
    const names = CORE_COMMANDS.join(' ');
    const located = spawnSync(this.shell.path, ['-c', `PATH=/usr/bin:/bin; for c in ${names} dash sh; do printf '%s=%s\\n' "$c" "$(command -v "$c")"; done`], { encoding: 'utf8', env: { SYSTEMROOT: process.env.SYSTEMROOT, PATH: `${dirname(this.shell.path)}${delimiter}/usr/bin${delimiter}/bin` } });
    const real = new Map(located.stdout.trim().split('\n').map((line) => line.replace(/\r$/, '').split('=') as [string, string]));
    for (const name of CORE_COMMANDS) {
      const target = real.get(name) || `/usr/bin/${name}`;
      writeFileSync(join(this.root, 'core', name), this.spy(name, 'SANDBOX_CT_LOG', `exec ${target} "$@"`), { mode: 0o755 });
    }
    // chmod and chown of the test host say nothing about Linux: recording them is what counts.
    for (const name of ['chmod', 'chown']) writeFileSync(join(this.root, 'core', name), this.spy(name, 'SANDBOX_CT_LOG', 'exit 0'), { mode: 0o755 });
    writeFileSync(join(this.root, 'core', 'sh'), `${this.shebang}\nexec ${this.shell.name} "$@"\n`, { mode: 0o755 });
    // No way to hold a value in a test argument other than a command that records it.
    writeFileSync(join(this.root, 'core', 'spy'), this.spy('spy', 'SANDBOX_CT_LOG', 'exit 0'), { mode: 0o755 });
    writeFileSync(join(this.root, 'core', 'su'), this.spy('su', 'SANDBOX_CT_LOG', 'shift 3\n[ "$1" = -c ] || { echo "bad su usage: $*" >&2; exit 2; }\nAS_USER=1; export AS_USER\nexec sh -c "$2"'), { mode: 0o755 });
    writeFileSync(join(this.root, 'stubs', 'sshd'), this.spy('sshd', 'SANDBOX_CT_LOG', SSHD_STUB), { mode: 0o755 });
  }

  private writeNodeCommands(): void {
    const write = (name: string, body: string) => writeFileSync(join(this.root, 'bin', name), this.spy(name, 'SANDBOX_NODE_LOG', body), { mode: 0o755 });
    write('pct', PCT_STUB);
    write('sudo', 'if [ "$1" = -n ]; then shift; fi\nif [ -e "$SANDBOX_ROOT/state/sudo-refused" ]; then echo "sudo: a password is required" >&2; exit 1; fi\nSUDO_RAN=1; export SUDO_RAN\nexec "$@"');
    write('pveversion', 'echo "pve-manager/9.1.0/abcdef (running kernel: 6.14.0-1-pve)"');
    write('qm', `if [ "$1" = list ]; then printf '      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\\n       100 web                  running    2048              32.00 4242\\n       102 db                   stopped    1024              16.00 0\\n'; fi`);
    write('uptime', 'echo " 12:00:00 up 3 days,  1:00,  1 user,  load average: 0.10, 0.20, 0.30"');
    write('free', 'printf "               total        used\\nMem:            8192        1024\\n"');
    write('zpool', 'echo "all pools are healthy"');
    write('lvs', 'echo "sh: lvs: not found" >&2; exit 127');
    write('pvecm', 'echo "Quorate: Yes"');
    write('systemctl', 'echo "failed.service loaded failed failed Failed unit"');
    write('journalctl', 'printf "2026-01-01T00:00:00 node pveproxy[1]: \\033[31mstarted\\033[0m ARGS:%s\\n" "$*"');
  }

  private writeFixtures(): void {
    // Homes come out of this file at run time, where no text remapping reaches: they have to be inside already.
    this.write('etc/passwd', `root:x:0:0:root:${this.rootPosix}/root:/bin/sh\nnobody:x:65534:65534:nobody:${this.rootPosix}/nonexistent:/bin/false\nalice:x:1000:1000:Alice:${this.rootPosix}/home/alice:/bin/sh\nsvc:x:999:999::${this.rootPosix}/var/lib/svc:/bin/false\n`);
    this.write('etc/os-release', 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n');
    this.write('proc/uptime', '12345.67 54321.00\n');
    this.write('proc/mounts', '/dev/rbd0 / ext4 rw,relatime 0 0\nnone /dev tmpfs rw 0 0\n');
    this.write('home/alice/.keep', '');
    this.write('etc/ssh/ssh_host_ed25519_key.pub', '');
    for (const distro of ['debian', 'ubuntu', 'alpine', 'rhel', 'arch', 'bare'] as const) this.writeDistro(distro);
  }

  /** What a distribution adds on top of the core commands. */
  private writeDistro(distro: Distro): void {
    const dir = join(this.root, `distro-${distro}`);
    mkdirSync(dir, { recursive: true });
    const write = (name: string, body = 'exit 0') => writeFileSync(join(dir, name), this.spy(name, 'SANDBOX_CT_LOG', body), { mode: 0o755 });
    const installsSshd = `case "$*" in *openssh*) cp "$SANDBOX_ROOT/stubs/sshd" "$SANDBOX_ROOT/distro-${distro}/sshd"; cp "$SANDBOX_ROOT/stubs/ssh-keygen" "$SANDBOX_ROOT/distro-${distro}/ssh-keygen" 2>/dev/null;; esac\nexit 0`;
    const common = () => {
      write('pgrep', 'if [ -e "$SANDBOX_ROOT/state/sshd-running" ]; then exit 0; fi\nexit 1');
      write('ip', "echo '1: lo    inet 127.0.0.1/8 scope host lo'; echo '2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0'");
      write('ssh-keygen');
    };
    const shadow = () => {
      write('useradd');
      write('userdel');
      write('chpasswd', 'cat > "$SANDBOX_ROOT/state/chpasswd.in"');
    };
    const systemd = (unit: 'ssh' | 'sshd', socket = false) => {
      write('systemctl', `case "$1" in
  cat) [ "$2" = "${unit}.service" ] && exit 0; ${socket ? '[ "$2" = ssh.socket ] && exit 0;' : ''} exit 1;;
  is-enabled) case "$2" in --) echo enabled; exit 0;; ${socket ? 'ssh.socket) echo enabled; exit 0;;' : ''} *) echo disabled; exit 1;; esac;;
  is-active) case "$2" in --) echo active; exit 0;; "${unit}") exit 0;; ${socket ? 'ssh.socket) exit 0;;' : ''} *) exit 3;; esac;;
  status) echo "$3.service - running";;
  list-units) echo "cron.service loaded active running";;
  reload-or-restart) [ -e "$SANDBOX_ROOT/state/reload-fails" ] && exit 1; exit 0;;
esac
exit 0`);
      write('journalctl', 'printf "2026-01-01T00:00:00 ct unit[1]: line ARGS:%s\\n" "$*"');
      write('ss', "echo 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))'");
    };
    switch (distro) {
      case 'debian':
      case 'ubuntu':
        common();
        shadow();
        systemd('ssh', distro === 'ubuntu');
        write('apt-get', installsSshd);
        write('dpkg-query', "printf 'curl\\t8.5.0-1\\tinstall ok installed\\ngone\\t1.0\\tdeinstall ok config-files\\nbash\\t5.2\\tinstall ok installed\\n'");
        write('adduser');
        break;
      case 'alpine':
        common();
        write('rc-service', 'case "$2" in status) [ -e "$SANDBOX_ROOT/state/sshd-running" ] && exit 0; exit 3;; esac\nexit 0');
        write('rc-update', '[ "$1" = show ] && echo "  sshd | default"\nexit 0');
        write('rc-status', 'echo "Runlevel: default"');
        write('apk', `${installsSshd.replace('exit 0', '')}[ "$1" = info ] && printf 'curl-8.5.0-r0\\nmusl-1.2.4-r2\\nbusybox-1.36.1-r15\\n'\nexit 0`);
        write('adduser');
        write('deluser');
        write('addgroup');
        write('chpasswd', 'cat > "$SANDBOX_ROOT/state/chpasswd.in"');
        write('netstat', "echo 'tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN'");
        break;
      case 'rhel':
        common();
        shadow();
        systemd('sshd');
        write('dnf', installsSshd);
        write('yum', installsSshd);
        write('rpm', "printf 'curl\\t8.5.0-1.el9\\tx86_64\\n'");
        break;
      case 'arch':
        common();
        shadow();
        systemd('sshd');
        write('pacman', `${installsSshd.replace('exit 0', '')}[ "$1" = -Q ] && printf 'curl 8.5.0-1\\nglibc 2.39-1\\n'\nexit 0`);
        break;
      case 'bare':
        break;
    }
    writeFileSync(join(this.root, 'stubs', 'ssh-keygen'), this.spy('ssh-keygen', 'SANDBOX_CT_LOG', 'exit 0'), { mode: 0o755 });
  }

  /** The container now looks like this distribution. */
  useDistro(distro: Distro): void {
    this.distroName = distro;
    rmSync(this.file('run/systemd'), { recursive: true, force: true });
    if (distro === 'debian' || distro === 'ubuntu' || distro === 'rhel' || distro === 'arch') mkdirSync(this.file('run/systemd/system'), { recursive: true });
  }

  /** Puts sshd in place, as if it had been installed before. */
  installSshd(distro: Distro = this.distroName): void {
    writeFileSync(join(this.root, `distro-${distro}`, 'sshd'), readFileSync(join(this.root, 'stubs', 'sshd')), { mode: 0o755 });
  }
}

const PCT_STUB = `sub=$1
shift
stopped() { [ -e "$SANDBOX_ROOT/state/stopped-$1" ]; }
case "$sub" in
  exec)
    id=$1
    shift
    if [ "$1" = "--" ]; then shift; fi
    if stopped "$id"; then echo "CT $id not running" >&2; exit 255; fi
    if [ -e "$SANDBOX_ROOT/state/locked-$id" ]; then echo "CT is locked (backup)" >&2; exit 255; fi
    IN_CT=1
    export IN_CT
    PATH=$CT_PATH
    export PATH
    exec "$@"
    ;;
  push)
    if stopped "$1"; then echo "can only push files to a running CT" >&2; exit 255; fi
    cat "$2" > "$3" || exit 1
    ;;
  pull)
    if stopped "$1"; then echo "can only pull files from a running CT" >&2; exit 255; fi
    cat "$2" > "$3" || exit 1
    ;;
  list)
    printf 'VMID       Status     Lock         Name\\n101        running                 db\\n103        stopped    backup       old\\n'
    ;;
  fsck)
    if ! stopped "$1"; then echo "Cannot run command on active container" >&2; exit 255; fi
    echo "rootfs: clean"
    ;;
  fstrim)
    if stopped "$1"; then echo "CT $1 not running" >&2; exit 255; fi
    echo "/: 1 GiB trimmed"
    ;;
  mount)
    echo "mounted CT $1 in '/var/lib/lxc/$1/rootfs'"
    ;;
  unmount)
    ;;
  *)
    echo "pct: unknown command $sub" >&2
    exit 2
    ;;
esac
exit 0`;

/** sshd -t refuses on a flag; -T prints what the files say, first value winning, as sshd does. */
const SSHD_STUB = `case "$1" in
  -t)
    if [ -e "$SANDBOX_ROOT/state/sshd-t-fails" ]; then echo "/etc/ssh/sshd_config line 3: Bad configuration option" >&2; exit 255; fi
    exit 0
    ;;
  -T)
    {
      if grep -qi '^Include' "$SANDBOX_ROOT/etc/ssh/sshd_config" 2>/dev/null; then
        for f in "$SANDBOX_ROOT"/etc/ssh/sshd_config.d/*.conf; do
          if [ -f "$f" ]; then cat "$f"; fi
        done
      fi
      cat "$SANDBOX_ROOT/etc/ssh/sshd_config" 2>/dev/null
    } | grep -v '^#' | grep -vi '^Include' | sed -e 's/^Port /port /' -e 's/^PermitRootLogin /permitrootlogin /' -e 's/^PasswordAuthentication /passwordauthentication /' -e 's/^PubkeyAuthentication /pubkeyauthentication /' > "$SANDBOX_ROOT/state/sshd-T.tmp"
    seen=
    grep -c '^port ' "$SANDBOX_ROOT/state/sshd-T.tmp" > /dev/null || echo 'port 22'
    while read -r k v; do
      [ -n "$k" ] || continue
      case "$k" in
        port) echo "$k $v" ;;
        *) case " $seen " in *" $k "*) ;; *) seen="$seen $k"; echo "$k $v" ;; esac ;;
      esac
    done < "$SANDBOX_ROOT/state/sshd-T.tmp"
    exit 0
    ;;
esac
touch "$SANDBOX_ROOT/state/sshd-running"
exit 0`;
