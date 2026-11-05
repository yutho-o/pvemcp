import { z } from 'zod';
import type { InstanceConfig, ServerConfig } from '../config.js';
import type { DryRunEntry, Method, ProxmoxClient, RequestOptions, UploadFile } from '../proxmox/client.js';
import { ProxmoxError } from '../proxmox/errors.js';
import type { NodeResolver } from '../proxmox/nodes.js';
import type { Params } from '../proxmox/params.js';
import type { Gate } from '../proxmox/policy.js';
import { isUpid, parseUpid, waitForTask, type TaskResult, type WaitOptions } from '../proxmox/tasks.js';
import type { Runtime } from '../runtime.js';
import type { ScopedSsh } from '../ssh/index.js';

/** Tools are grouped by domain and can be filtered with PROXMOX_TOOLSETS. */
export const DOMAINS = ['vm', 'lxc', 'node', 'storage', 'backup', 'tasks', 'cluster', 'ha', 'firewall', 'access', 'pools', 'network', 'disks', 'sdn', 'ceph', 'notifications', 'acme', 'mapping', 'ssh', 'workflows', 'api'] as const;
export type Domain = (typeof DOMAINS)[number];

/** Large domains that few setups use stay out of the default list, to spare the context of the agent. */
export const OPT_IN_TOOLSETS: readonly Domain[] = ['sdn', 'ceph', 'notifications', 'acme', 'mapping'];

export type { Gate } from '../proxmox/policy.js';

/** The client with this tool call's scope applied: dry run for writes, read-only for read tools. */
export class ScopedApi {
  constructor(
    private readonly client: ProxmoxClient,
    private readonly defaults: RequestOptions,
  ) {}

  request(method: Method, path: string, opts: RequestOptions = {}): Promise<unknown> {
    return this.client.request(method, path, { ...this.defaults, ...opts });
  }

  get(path: string, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('GET', path, opts);
  }

  post(path: string, params?: Params, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('POST', path, { ...opts, params: params ?? opts.params });
  }

  put(path: string, params?: Params, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('PUT', path, { ...opts, params: params ?? opts.params });
  }

  delete(path: string, params?: Params, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('DELETE', path, { ...opts, params: params ?? opts.params });
  }

  upload(path: string, fields: Params, file: UploadFile, opts: RequestOptions = {}): Promise<unknown> {
    return this.client.upload(path, fields, file, { ...this.defaults, ...opts });
  }
}

/** What to do with an answer that may be a task id. */
export interface FinishOptions {
  /** Default true. False returns the task id straight away. */
  wait?: boolean;
  /** Default PROXMOX_TASK_WAIT_SECONDS. */
  waitSeconds?: number;
}

/** Task helpers bound to this tool call's API scope. */
export class TaskHelper {
  constructor(
    private readonly api: ScopedApi,
    private readonly defaultWaitSeconds: number,
  ) {}

  /** Waits for a UPID. Throws task_failed, or task_timeout when it is still running. */
  wait(upid: string, opts: WaitOptions = {}): Promise<TaskResult> {
    return waitForTask(this.api, upid, { timeoutMs: this.defaultWaitSeconds * 1000, ...opts });
  }

  /**
   * Turns the answer of a write into a tool result. A UPID is waited for: a failed task
   * throws task_failed, and one that outlasts the delay comes back as still running, which is
   * not an error. Anything else is returned as it is.
   */
  async finish(value: unknown, opts: FinishOptions = {}): Promise<Record<string, unknown>> {
    if (!isUpid(value)) return asObject(value);
    const { node } = parseUpid(value);
    if (opts.wait === false) return { task: value, node, next_step: 'pve_wait_task' };
    const seconds = opts.waitSeconds ?? this.defaultWaitSeconds;
    try {
      const result = await waitForTask(this.api, value, { timeoutMs: seconds * 1000 });
      return { ...result };
    } catch (err) {
      if (err instanceof ProxmoxError && err.type === 'task_timeout') return { task: value, node, still_running: true, next_step: 'pve_wait_task' };
      throw err;
    }
  }
}

/** A tool result is always an object. */
export function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  if (Array.isArray(value)) return { rows: value, count: value.length };
  return value === null || value === undefined ? { ok: true } : { result: value };
}

export interface ToolContext {
  api: ScopedApi;
  instance: InstanceConfig;
  server: ServerConfig;
  dryRun: boolean;
  dryRunLog: DryRunEntry[];
  tasks: TaskHelper;
  nodes: NodeResolver;
  ssh: ScopedSsh;
  runtime: Runtime;
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  domain: Domain;
  /** What the instance must allow for this tool to appear and to run. */
  gate: Gate;
  /** A higher gate for these arguments: refused before anyone is asked. The client enforces it anyway. */
  gateWhen?: (args: Record<string, unknown>) => Gate | undefined;
  /** Says what raised the gate, in the refusal: the name of the tool alone would not tell the agent what to change. */
  gateNote?: (args: Record<string, unknown>) => string | undefined;
  /** The handler gets the arguments the schema does not list, and deals with them itself. Any other tool refuses them. */
  acceptsExtraArgs?: boolean;
  /** Refuses bad arguments the schema cannot judge, before anyone is asked to confirm them. */
  checkArgs?: (args: Record<string, unknown>) => void;
  /** Masks what the name of an argument does not say is secret, for the audit log and the question to a human. */
  redactArgs?: (args: Record<string, unknown>) => Record<string, unknown>;
  /** Asks a human first when the client can, and announces destructiveHint. */
  destructive?: boolean;
  /** Same, but depending on the arguments: force=1 on a guest create. */
  destructiveWhen?: (args: Record<string, unknown>) => boolean;
  /** Announces readOnlyHint, takes no dry_run, and any write it tries is refused. Default: from the gate. */
  readOnly?: boolean;
  idempotent?: boolean;
  /** The tool reaches beyond Proxmox itself. */
  openWorld?: boolean;
  /** Other domains that need this tool, for PROXMOX_TOOLSETS. */
  also?: Domain[];
  input: z.ZodRawShape;
  /** Message for the human, for a destructive tool whose client supports elicitation. */
  confirmation?: (args: Record<string, unknown>) => string;
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<unknown>;
}

export function isReadOnlyTool(def: ToolDef): boolean {
  return def.readOnly ?? (def.gate === 'read' || def.gate === 'sensitive' || def.gate === 'ssh_read');
}

export function tool<S extends z.ZodRawShape>(def: Omit<ToolDef, 'input' | 'handler' | 'confirmation' | 'destructiveWhen'> & {
  input: S;
  confirmation?: (args: z.infer<z.ZodObject<S>>) => string;
  destructiveWhen?: (args: z.infer<z.ZodObject<S>>) => boolean;
  handler: (args: z.infer<z.ZodObject<S>>, ctx: ToolContext) => Promise<unknown>;
}): ToolDef {
  return def as unknown as ToolDef;
}

/** The result shape of every listing: renderResult can cut it and say where to go on. */
export function pageRows(rows: unknown[], limit: number | undefined, offset: number | undefined): Record<string, unknown> {
  const start = offset ?? 0;
  const page = limit === undefined ? rows.slice(start) : rows.slice(start, start + limit);
  const end = start + page.length;
  const hasMore = end < rows.length;
  return { rows: page, total: rows.length, count: page.length, offset: start, has_more: hasMore, ...(hasMore ? { next_offset: end } : {}) };
}

/**
 * Written out, because zod would give additionalProperties: {} for this. It means the same, and
 * not every client reads it that way.
 */
export function looseObject<S extends z.ZodRawShape>(shape: S) {
  return z.object(shape).loose().meta({ additionalProperties: true });
}

/**
 * An object with free keys, checked here. z.record would write propertyNames in the JSON Schema,
 * which clients that take a subset of JSON Schema refuse, and it adds nothing an agent can use.
 */
export function mapOf<V extends z.ZodType>(value: V, keys?: { pattern: RegExp; message: string }) {
  const map = z.object({}).catchall(value);
  if (!keys) return map;
  return map.superRefine((object, ctx) => {
    for (const key of Object.keys(object)) {
      if (!keys.pattern.test(key)) ctx.addIssue({ code: 'custom', message: `${keys.message}: "${key}"`, path: [key] });
    }
  });
}

export const paging = {
  page_limit: z.number().int().min(1).max(10_000).optional().describe('Rows per page. Default: as many as fit in the answer.'),
  page_offset: z.number().int().min(0).optional().describe('Rows to skip. Use next_offset from the previous page.'),
};

export const vmid = z.number().int().min(1).max(999_999_999).describe('The guest id.');

export const nodeName = z
  .string()
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/, 'Expected a node name')
  .max(64);

/** Reads several endpoints where each may be missing or forbidden, and reports which ones were. */
export async function gather<T extends Record<string, () => Promise<unknown>>>(sources: T): Promise<{ data: { [K in keyof T]?: unknown }; unavailable: Record<string, string> }> {
  const keys = Object.keys(sources) as Array<keyof T>;
  const results = await Promise.allSettled(keys.map((k) => sources[k]!()));
  const data: { [K in keyof T]?: unknown } = {};
  const unavailable: Record<string, string> = {};
  results.forEach((r, i) => {
    const key = keys[i]!;
    if (r.status === 'fulfilled') data[key] = r.value;
    else unavailable[String(key)] = r.reason instanceof ProxmoxError ? `${r.reason.type}: ${r.reason.message}` : String(r.reason);
  });
  return { data, unavailable };
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
