import { randomUUID } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { ProxmoxError } from '../proxmox/errors.js';
import { scrubText } from '../proxmox/redact.js';
import type { ShellChannel } from './index.js';

export interface SessionOptions {
  maxSessions?: number;
  idleMs?: number;
  bufferBytes?: number;
}

const DEFAULTS = { maxSessions: 8, idleMs: 15 * 60_000, bufferBytes: 1024 * 1024 };
const SWEEP_MS = 30_000;
/** Output comes in bursts: after the first bytes, a moment more gives whole lines instead of pieces. */
const SETTLE_MS = 60;

export interface SessionInfo {
  session: string;
  instance: string;
  node: string;
  vmid?: number;
  command: string;
  started_at: string;
  idle_seconds: number;
  unread_bytes: number;
  closed: boolean;
  exit_code?: number | null;
}

/** One PTY, with what it printed since the last read. */
export class PtySession {
  readonly id = randomUUID().slice(0, 8);
  private readonly startedAt = Date.now();
  private lastUsed = Date.now();
  private chunks: Buffer[] = [];
  private unread = 0;
  private dropped = 0;
  private readonly decoder = new StringDecoder('utf8');
  private wake: Array<() => void> = [];
  closedWith?: { code: number | null; signal?: string };

  constructor(
    readonly instance: string,
    readonly node: string,
    readonly vmid: number | undefined,
    readonly command: string,
    private readonly channel: ShellChannel,
    private readonly bufferBytes: number,
  ) {
    channel.onData((chunk) => this.push(chunk));
    channel.onClose((info) => {
      this.closedWith = info;
      this.wakeAll();
    });
  }

  private wakeAll(): void {
    for (const wake of this.wake.splice(0)) wake();
  }

  private push(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.unread += chunk.length;
    // A ring in effect: what nobody read in time goes first, and the reader is told how much.
    while (this.unread > this.bufferBytes) {
      const first = this.chunks[0]!;
      const excess = this.unread - this.bufferBytes;
      if (first.length <= excess) {
        this.chunks.shift();
        this.unread -= first.length;
        this.dropped += first.length;
      } else {
        this.chunks[0] = first.subarray(excess);
        this.unread -= excess;
        this.dropped += excess;
      }
    }
    this.wakeAll();
  }

  /** Only what the agent does counts: a program printing on its own must not keep a session open forever. */
  touch(): void {
    this.lastUsed = Date.now();
  }

  idleFor(): number {
    return Date.now() - this.lastUsed;
  }

  send(data: Buffer | string): void {
    this.touch();
    if (this.closedWith) throw new ProxmoxError('invalid_input', `Session ${this.id} is closed.`, { hint: 'Open a new one with pve_ssh_session_open.' });
    this.channel.write(data);
  }

  resize(cols: number, rows: number): void {
    this.channel.resize?.(cols, rows);
  }

  /** Until there is output or the session ends, for at most waitMs. */
  async waitForOutput(waitMs: number): Promise<void> {
    this.touch();
    if (waitMs <= 0) return;
    if (this.unread === 0 && !this.closedWith) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, waitMs);
        this.wake.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    if (this.unread > 0 && !this.closedWith) await new Promise((resolve) => setTimeout(resolve, Math.min(SETTLE_MS, waitMs)));
  }

  /** Drains what is there. Terminal escapes are gone: the output of a guest is untrusted. */
  read(): { output: string; dropped_bytes: number } {
    this.touch();
    const raw = Buffer.concat(this.chunks);
    const dropped = this.dropped;
    this.chunks = [];
    this.unread = 0;
    this.dropped = 0;
    return { output: scrubText(this.decoder.write(raw)), dropped_bytes: dropped };
  }

  info(): SessionInfo {
    return {
      session: this.id,
      instance: this.instance,
      node: this.node,
      ...(this.vmid !== undefined ? { vmid: this.vmid } : {}),
      command: this.command,
      started_at: new Date(this.startedAt).toISOString(),
      idle_seconds: Math.round(this.idleFor() / 1000),
      unread_bytes: this.unread,
      closed: this.closedWith !== undefined,
      ...(this.closedWith ? { exit_code: this.closedWith.code } : {}),
    };
  }

  close(): void {
    this.channel.close();
  }
}

/** Every session of the server. Lives in the runtime, because HTTP mode has no connection to keep them in. */
export class SshSessions {
  private readonly sessions = new Map<string, PtySession>();
  private readonly options: typeof DEFAULTS;
  private sweeper?: NodeJS.Timeout;

  constructor(options: SessionOptions = {}) {
    this.options = { ...DEFAULTS, ...options };
  }

  /** Before connecting: refusing is cheap, a connection that goes unused is not. */
  assertRoom(): void {
    this.sweep();
    const open = [...this.sessions.values()].filter((s) => !s.closedWith).length;
    if (open >= this.options.maxSessions) {
      throw new ProxmoxError('invalid_input', `There are already ${open} open sessions, the limit is ${this.options.maxSessions}.`, { hint: 'Close one with pve_ssh_session_close. pve_ssh_session_list shows them.' });
    }
  }

  add(instance: string, node: string, vmid: number | undefined, command: string, channel: ShellChannel): PtySession {
    const session = new PtySession(instance, node, vmid, command, channel, this.options.bufferBytes);
    this.sessions.set(session.id, session);
    this.startSweeper();
    return session;
  }

  get(id: string, instance: string): PtySession {
    this.sweep();
    const session = this.sessions.get(id);
    if (!session || session.instance !== instance) {
      throw new ProxmoxError('not_found', `No session ${id}.`, { hint: 'It may have been closed after being idle for too long. pve_ssh_session_list shows the open ones.' });
    }
    return session;
  }

  list(instance: string): SessionInfo[] {
    this.sweep();
    return [...this.sessions.values()].filter((s) => s.instance === instance).map((s) => s.info());
  }

  remove(id: string): void {
    this.sessions.delete(id);
  }

  sweep(): void {
    for (const [id, session] of this.sessions) {
      if (session.idleFor() < this.options.idleMs) continue;
      this.sessions.delete(id);
      if (!session.closedWith) session.close();
    }
    if (this.sessions.size === 0 && this.sweeper) {
      clearInterval(this.sweeper);
      this.sweeper = undefined;
    }
  }

  closeAll(): void {
    for (const session of this.sessions.values()) if (!session.closedWith) session.close();
    this.sessions.clear();
    if (this.sweeper) clearInterval(this.sweeper);
    this.sweeper = undefined;
  }

  private startSweeper(): void {
    if (this.sweeper) return;
    this.sweeper = setInterval(() => this.sweep(), Math.min(SWEEP_MS, this.options.idleMs));
    this.sweeper.unref();
  }
}
