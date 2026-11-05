import { createHash } from 'node:crypto';
import type { InstanceConfig } from '../config.js';
import type { DryRunEntry, WriteRecord } from '../proxmox/client.js';
import { ProxmoxError } from '../proxmox/errors.js';
import type { NodeResolver } from '../proxmox/nodes.js';
import { gateRefusal } from '../proxmox/policy.js';
import { scrubText } from '../proxmox/redact.js';
import type { HostKeyInfo } from './known-hosts.js';
import { PooledSshTransport } from './transport.js';

export { sh, ShellRaw, shQuote, shRaw } from './quote.js';

/** A shell command and what it is allowed to be. Build text with the sh tag, never by hand. */
export interface ShellCommand {
  text: string;
  access: 'read' | 'write';
  stdin?: Buffer | string;
  /** Shown in audit and dry-run logs instead of text, when text holds something secret. */
  display?: string;
  /** A digest of a password can be attacked offline: stdin then leaves no trace at all in the logs. */
  sensitiveStdin?: boolean;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exit_code: number | null;
  signal?: string;
  truncated: boolean;
  duration_ms: number;
  timed_out: boolean;
  /** Set when nothing ran, because this is a dry run. */
  dry_run?: boolean;
  /** The key the host presented, once verified. Only the real transport gives this. */
  host_key?: HostKeyInfo;
}

/** A guest reached directly over SSH instead of the node. */
export interface GuestEndpoint {
  vmid: number;
  host: string;
  port: number;
  user: string;
  /** Go through this node, for a guest the server cannot reach. */
  viaNode?: string;
  /** The public key lines the guest must present, read through pct. */
  hostKeys?: string[];
  /** SHA256:... given on the call. */
  fingerprint?: string;
}

export interface SshTarget {
  node: string;
  guest?: GuestEndpoint;
}

export interface ExecOptions {
  timeoutMs?: number;
  maxBytes?: number;
}

export interface SftpStat {
  size: number;
  mode: number;
  mtime: number;
  isDirectory: boolean;
  isFile: boolean;
}

/** Promise-based view of an SFTP channel. Paths are remote; local ones must have gone through resolveLocalPath. */
export interface SftpSession {
  readFile(path: string): Promise<Buffer>;
  writeFile(path: string, data: Buffer | string, opts?: { mode?: number }): Promise<void>;
  /** Streams a local file to the remote path. */
  fastPut(localPath: string, remotePath: string, opts?: { mode?: number; timeoutMs?: number }): Promise<void>;
  /** Streams a remote file to the local path. */
  fastGet(remotePath: string, localPath: string, opts?: { timeoutMs?: number }): Promise<void>;
  stat(path: string): Promise<SftpStat>;
  readdir(path: string): Promise<Array<{ name: string; stat: SftpStat }>>;
  unlink(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  close(): void;
}

export interface ShellOptions {
  cols?: number;
  rows?: number;
  term?: string;
  /** Run this with a PTY instead of the login shell: pct enter 100. */
  command?: string;
}

/** An open PTY channel. Data arrives as Buffers; close() ends the channel, onClose fires once whatever ended it. */
export interface ShellChannel {
  write(data: Buffer | string): void;
  onData(listener: (chunk: Buffer) => void): void;
  onClose(listener: (info: { code: number | null; signal?: string }) => void): void;
  resize?(cols: number, rows: number): void;
  close(): void;
}

/**
 * The seam between the gates below and the actual SSH connections. An implementation owns the
 * pool, the host key checks and the timeouts; it has no policy of its own, and is only ever
 * reached through ScopedSsh.
 */
export interface SshTransport {
  exec(target: SshTarget, command: ShellCommand, opts?: ExecOptions): Promise<ExecResult>;
  sftp(target: SshTarget): Promise<SftpSession>;
  shell(target: SshTarget, opts?: ShellOptions): Promise<ShellChannel>;
  /** Closes every connection. Called at shutdown. */
  close(): Promise<void> | void;
}

export type SshTransportFactory = (instance: InstanceConfig, nodes: NodeResolver) => SshTransport;

/** Called once per instance, on first use. */
export function createSshTransport(instance: InstanceConfig, nodes: NodeResolver): SshTransport {
  return new PooledSshTransport(instance, nodes);
}

export interface SshScope {
  /** Set for read tools: a command that may change something is refused. */
  readOnly: boolean;
  dryRun: boolean;
  dryRunLog: DryRunEntry[];
  /** Records what is about to run, for the audit log. */
  onCommand?: (entry: WriteRecord) => void;
}

function stdinSummary(stdin: Buffer | string): { bytes: number; sha256: string } {
  const data = typeof stdin === 'string' ? Buffer.from(stdin, 'utf8') : stdin;
  return { bytes: data.length, sha256: createHash('sha256').update(data).digest('hex') };
}

/**
 * All SSH access for one tool call. Enforces the gates at the chokepoint, like the API client
 * does for HTTP: a tool cannot reach the transport any other way.
 */
export class ScopedSsh {
  constructor(
    private readonly instance: InstanceConfig,
    private readonly transport: () => SshTransport,
    private readonly scope: SshScope,
  ) {}

  private assertAllowed(access: 'read' | 'write', what: string): void {
    const gate = access === 'write' ? 'ssh_write' : 'ssh_read';
    const refusal = gateRefusal(gate, this.instance, { dryRun: this.scope.dryRun, what });
    if (refusal) throw refusal;
    if (access === 'write' && this.scope.readOnly) {
      throw new ProxmoxError('not_read_only', `${what} can change something, so a read tool refuses it: nothing was run.`, {
        hint: 'A tool that writes is the way to do this, provided writes are enabled.',
      });
    }
  }

  async run(target: SshTarget, cmd: ShellCommand, opts: ExecOptions = {}): Promise<ExecResult> {
    this.assertAllowed(cmd.access, target.guest ? `SSH command on guest ${target.guest.vmid}` : `SSH command on ${target.node}`);
    if (cmd.text.includes('\0')) throw new ProxmoxError('invalid_input', 'The command holds a NUL character.');
    const where = target.guest ? `[guest ${target.guest.vmid} ${target.guest.user}@${target.guest.host}] ` : '';
    const shown = where + (cmd.display ?? cmd.text);
    const stdin = cmd.stdin !== undefined && !cmd.sensitiveStdin ? { stdin: stdinSummary(cmd.stdin) } : {};
    if (this.scope.dryRun) {
      this.scope.dryRunLog.push({ ssh: { node: target.node, command: shown, access: cmd.access, ...stdin } });
      return { stdout: '', stderr: '', exit_code: 0, truncated: false, duration_ms: 0, timed_out: false, dry_run: true };
    }
    if (cmd.access === 'write') this.scope.onCommand?.({ status: 'sent', ssh: { node: target.node, command: shown, ...stdin } });
    const result = await this.transport().exec(target, cmd, opts);
    // Here and not in each tool: what comes back from a host is untrusted, whoever asked for it.
    return { ...result, stdout: scrubText(result.stdout), stderr: scrubText(result.stderr) };
  }

  /** In a read scope only reads work. In a dry run, writes are logged and reads are refused: nothing connects. */
  async sftp(target: SshTarget, access: 'read' | 'write' = 'read'): Promise<SftpSession> {
    this.assertAllowed(access, `SFTP on ${target.node}`);
    if (this.scope.dryRun) return this.dryRunSftp(target);
    const session = await this.transport().sftp(target);
    return this.guardSftp(target, session, access);
  }

  /** A PTY is arbitrary execution: there is no read-only version of it. */
  async shell(target: SshTarget, opts: ShellOptions = {}): Promise<ShellChannel> {
    this.assertAllowed('write', `SSH session on ${target.node}`);
    if (this.scope.dryRun) {
      this.scope.dryRunLog.push({ ssh: { node: target.node, command: opts.command ?? '(login shell)', access: 'write' } });
      throw new ProxmoxError('invalid_input', 'An interactive session cannot be previewed: a dry run opens nothing.', { hint: 'Run it without dry_run, or preview the commands one at a time.' });
    }
    this.scope.onCommand?.({ status: 'sent', ssh: { node: target.node, command: opts.command ?? '(login shell)', pty: true } });
    return this.transport().shell(target, opts);
  }

  private guardSftp(target: SshTarget, session: SftpSession, access: 'read' | 'write'): SftpSession {
    const record = (operation: string, path: string) => this.scope.onCommand?.({ status: 'sent', ssh: { node: target.node, sftp: operation, path } });
    const write = <T>(operation: string, path: string, run: () => Promise<T>): Promise<T> => {
      if (access !== 'write') return Promise.reject(new ProxmoxError('not_read_only', `SFTP ${operation} on ${path} was refused: this session is read-only.`));
      record(operation, path);
      return run();
    };
    return {
      readFile: (path) => session.readFile(path),
      fastGet: (remote, local, opts) => session.fastGet(remote, local, opts),
      stat: (path) => session.stat(path),
      readdir: (path) => session.readdir(path),
      close: () => session.close(),
      writeFile: (path, data, opts) => write('writeFile', path, () => session.writeFile(path, data, opts)),
      fastPut: (local, remote, opts) => write('fastPut', remote, () => session.fastPut(local, remote, opts)),
      unlink: (path) => write('unlink', path, () => session.unlink(path)),
      rename: (from, to) => write('rename', from, () => session.rename(from, to)),
      chmod: (path, mode) => write('chmod', path, () => session.chmod(path, mode)),
    };
  }

  private dryRunSftp(target: SshTarget): SftpSession {
    const log = (sftp: string, path: string, data?: Buffer | string) => {
      this.scope.dryRunLog.push({ ssh: { node: target.node, sftp, path, access: 'write', ...(data !== undefined ? { stdin: stdinSummary(data) } : {}) } });
      return Promise.resolve();
    };
    const noRead = (): Promise<never> =>
      Promise.reject(new ProxmoxError('invalid_input', 'SFTP reads are not available in a dry run: nothing connects.'));
    return {
      readFile: noRead,
      fastGet: noRead,
      stat: noRead,
      readdir: noRead,
      close: () => undefined,
      writeFile: (path, data) => log('writeFile', path, data),
      fastPut: (_local, remote) => log('fastPut', remote),
      unlink: (path) => log('unlink', path),
      rename: (from) => log('rename', from),
      chmod: (path) => log('chmod', path),
    };
  }
}
