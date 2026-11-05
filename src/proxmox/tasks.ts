import { ProxmoxError } from './errors.js';

/** What a dry run returns where the real call would have started a task. */
export const DRY_RUN_UPID = 'UPID:dry-run:00000000:00000000:00000000:dryrun:0:dry-run@pam:';

export interface ParsedUpid {
  upid: string;
  node: string;
  pid: number;
  pstart: number;
  starttime: number;
  type: string;
  id: string;
  user: string;
}

const UPID_RE = /^UPID:([a-zA-Z0-9][a-zA-Z0-9.-]*):([0-9A-Fa-f]{8,}):([0-9A-Fa-f]{8,}):([0-9A-Fa-f]{8,}):([^:\s]+):([^:\s]*):([^:\s]+):$/;

export function isUpid(value: unknown): value is string {
  return typeof value === 'string' && UPID_RE.test(value);
}

export function parseUpid(upid: string): ParsedUpid {
  const m = UPID_RE.exec(upid);
  if (!m) {
    throw new ProxmoxError('invalid_input', `"${upid.slice(0, 200)}" is not a task id (UPID).`, { hint: 'A UPID looks like UPID:pve1:00001234:00ABCDEF:65000000:qmstart:100:root@pam:' });
  }
  return {
    upid,
    node: m[1]!,
    pid: Number.parseInt(m[2]!, 16),
    pstart: Number.parseInt(m[3]!, 16),
    starttime: Number.parseInt(m[4]!, 16),
    type: m[5]!,
    id: m[6]!,
    user: m[7]!,
  };
}

/** The little that tasks need from an API handle: both the client and ScopedApi fit. */
export interface TaskApi {
  get(path: string, opts?: { pathParams?: Record<string, string | number>; params?: Record<string, unknown>; timeoutMs?: number }): Promise<unknown>;
}

export interface TaskResult {
  upid: string;
  node: string;
  status: string;
  exitstatus: string | null;
  log_tail: string[];
  warning?: string;
}

export interface WaitOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  /** First delay between polls. It grows up to maxPollMs. */
  pollMs?: number;
  maxPollMs?: number;
  logLines?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_MS = 500;
const DEFAULT_MAX_POLL_MS = 5_000;
const DEFAULT_LOG_LINES = 20;
const LOG_PAGE = 5000;
const LOG_MAX_PAGES = 20;

function abortable(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error('aborted'));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason ?? new Error('aborted'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Never fails: a task that cannot show its log still has a result to report. */
export async function taskLogTail(api: TaskApi, upid: string, lines = DEFAULT_LOG_LINES): Promise<string[]> {
  const { node } = parseUpid(upid);
  try {
    // start and limit count from the top, and the answer does not say how long the log is.
    const pathParams = { node, upid };
    let tail: Array<{ t?: unknown }> = [];
    for (let page = 0, start = 0; page < LOG_MAX_PAGES; page++) {
      const rows = await api.get('/nodes/{node}/tasks/{upid}/log', { pathParams, params: { start, limit: LOG_PAGE } });
      if (!Array.isArray(rows) || rows.length === 0) break;
      tail = [...tail, ...(rows as Array<{ t?: unknown }>)].slice(-lines);
      if (rows.length < LOG_PAGE) break;
      start += rows.length;
    }
    return tail.map((r) => String(r.t ?? '')).filter((t) => t !== 'no content');
  } catch {
    return [];
  }
}

/**
 * Waits for a task to end. OK is a success, WARNINGS: n a success with a warning, anything
 * else task_failed with the end of the log. The node always comes from the UPID: the task
 * runs there, whichever node the API answered on.
 */
export async function waitForTask(api: TaskApi, upid: string, opts: WaitOptions = {}): Promise<TaskResult> {
  const { node } = parseUpid(upid);
  if (upid === DRY_RUN_UPID) return { upid, node, status: 'stopped', exitstatus: 'OK', log_tail: [] };

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  let delay = opts.pollMs ?? DEFAULT_POLL_MS;
  const maxDelay = opts.maxPollMs ?? DEFAULT_MAX_POLL_MS;
  const pathParams = { node, upid };

  for (;;) {
    const status = (await api.get('/nodes/{node}/tasks/{upid}/status', { pathParams })) as { status?: unknown; exitstatus?: unknown } | null;
    if (status?.status === 'stopped') {
      const exit = typeof status.exitstatus === 'string' ? status.exitstatus : null;
      const log = await taskLogTail(api, upid, opts.logLines ?? DEFAULT_LOG_LINES);
      if (exit === 'OK') return { upid, node, status: 'stopped', exitstatus: exit, log_tail: log };
      if (exit !== null && /^WARNINGS: \d+$/.test(exit)) return { upid, node, status: 'stopped', exitstatus: exit, log_tail: log, warning: `The task finished with ${exit.toLowerCase()}. See log_tail.` };
      throw new ProxmoxError('task_failed', `Task ${upid} failed on ${node}: ${exit ?? 'no exit status'}.`, {
        hint: 'Read the log tail in details before trying again. The failed step may have left something behind.',
        details: { upid, node, exitstatus: exit, log_tail: log },
      });
    }
    const left = deadline - Date.now();
    if (left <= 0) {
      throw new ProxmoxError('task_timeout', `Task ${upid} is still running on ${node} after ${Math.round(timeoutMs / 1000)} s.`, {
        hint: 'It was not cancelled. Check it again with pve_wait_task, or stop it with pve_stop_task.',
        details: { upid, node },
      });
    }
    await abortable(Math.min(delay, left), opts.signal);
    delay = Math.min(Math.ceil(delay * 1.5), maxDelay);
  }
}
