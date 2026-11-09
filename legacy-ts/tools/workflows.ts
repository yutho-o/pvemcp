import { z } from 'zod';
import { ProxmoxError } from '../proxmox/errors.js';
import type { GuestLocation } from '../proxmox/nodes.js';
import { parseUpid, type TaskApi } from '../proxmox/tasks.js';
import { gather, isObject, nodeName, pageRows, paging, tool, vmid, type ToolContext, type ToolDef } from './helpers.js';

/**
 * Composite tools: several API calls behind one question or one job. Each section that could
 * not be read is named in `unavailable` and is never taken for good news, and each step of a
 * provisioning job is reported, with what it left behind when it stops.
 */

type Row = Record<string, unknown>;

const DAY_SECONDS = 86_400;
const DEFAULT_TASK_HOURS = 24;
const DEFAULT_STORAGE_WARN_PERCENT = 85;
const DEFAULT_STORAGE_CRITICAL_PERCENT = 95;
const DEFAULT_MEMORY_WARN_PERCENT = 90;
const DEFAULT_CERT_WARN_DAYS = 30;
const DEFAULT_BACKUP_MAX_AGE_DAYS = 7;
const DEFAULT_LXC_NET = 'name=eth0,bridge=vmbr0,ip=dhcp';
const DEFAULT_IP_WAIT_SECONDS = 30;
const DEFAULT_AGENT_WAIT_SECONDS = 120;
const MAX_LOG_PAGES = 20;
const LOG_PAGE = 5000;
/** A cluster where a whole section fails should not drown the answer in one reason per guest. */
const MAX_REASONS_PER_SECTION = 10;
const MAX_LISTED = 50;

const CORE_SERVICES = new Set(['pve-cluster', 'corosync', 'pveproxy', 'pvedaemon', 'pvestatd', 'pve-firewall', 'pve-ha-crm', 'pve-ha-lrm']);
/** Roles that amount to running the cluster, when granted on the root path. */
const POWERFUL_ROLES = new Set(['Administrator', 'PVEAdmin', 'PVESysAdmin', 'PVEVMAdmin', 'PVEDatastoreAdmin', 'PVEUserAdmin', 'PVEPoolAdmin', 'PVESDNAdmin']);
const SECOND_FACTORS = new Set(['totp', 'u2f', 'webauthn', 'yubico']);

function rowsOf(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter(isObject) : [];
}

function num(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The API says booleans as 0 and 1, and sometimes as true and false. Undefined stays unknown. */
function flag(value: unknown): boolean | undefined {
  if (value === true || value === 1 || value === '1') return true;
  if (value === false || value === 0 || value === '0') return false;
  return undefined;
}

function round(value: number, digits = 1): number {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function fraction(used: unknown, total: unknown): number | undefined {
  const u = num(used);
  const t = num(total);
  return u !== undefined && t !== undefined && t > 0 ? u / t : undefined;
}

function percent(value: number | undefined): number | null {
  return value === undefined ? null : round(value * 100);
}

function isoTime(epoch: unknown): string | null {
  const n = num(epoch);
  return n === undefined ? null : new Date(n * 1000).toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function reasonOf(err: unknown): string {
  return err instanceof ProxmoxError ? `${err.type}: ${err.message}` : String((err as Error)?.message ?? err);
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/* ------------------------------------------------------------------ findings */

type HealthSeverity = 'critical' | 'warning' | 'info';
type AuditSeverity = 'high' | 'medium' | 'low' | 'info';

interface Finding<S extends string> {
  severity: S;
  check: string;
  object: string;
  evidence: unknown;
  action: string;
}

/** What a report found, what it looked at, and above all what it could not look at. */
class Report<S extends string> {
  readonly findings: Array<Finding<S>> = [];
  readonly checked = new Set<string>();
  readonly unavailable: Record<string, string> = {};

  add(severity: S, check: string, object: string, evidence: unknown, action: string): void {
    this.findings.push({ severity, check, object, evidence, action });
  }

  /** Takes in a gather: section/detail keys count their section as looked at when one of them answered. */
  absorb(result: { data: Record<string, unknown>; unavailable: Record<string, string> }): void {
    for (const key of Object.keys(result.data)) this.checked.add(key.split('/')[0]!);
    Object.assign(this.unavailable, result.unavailable);
  }

  count(severity: S): number {
    return this.findings.filter((f) => f.severity === severity).length;
  }

  summary(severities: readonly S[]): Record<string, unknown> {
    const order = new Map(severities.map((s, i) => [s, i]));
    this.findings.sort((a, b) => (order.get(a.severity) ?? 99) - (order.get(b.severity) ?? 99));
    const unavailable = compactReasons(this.unavailable);
    return {
      complete: Object.keys(unavailable).length === 0,
      counts: Object.fromEntries(severities.map((s) => [s, this.count(s)])),
      findings: this.findings,
      checked: [...this.checked].sort(),
      unavailable,
    };
  }
}

function compactReasons(reasons: Record<string, string>): Record<string, string> {
  const bySection = new Map<string, string[]>();
  for (const key of Object.keys(reasons)) {
    const section = key.split('/')[0]!;
    bySection.set(section, [...(bySection.get(section) ?? []), key]);
  }
  const out: Record<string, string> = {};
  for (const [section, keys] of bySection) {
    for (const key of keys.slice(0, MAX_REASONS_PER_SECTION)) out[key] = reasons[key]!;
    if (keys.length > MAX_REASONS_PER_SECTION) out[`${section}/...`] = `${keys.length - MAX_REASONS_PER_SECTION} more with the same section not read.`;
  }
  return out;
}

/* ------------------------------------------------------------------ shared reads */

interface QuorumState {
  state: 'quorate' | 'no_quorum' | 'standalone' | 'unknown';
  cluster?: string;
  nodes_total: number;
  nodes_online: number;
  offline_nodes: string[];
}

/** A single node that is not in a cluster has no row of type cluster at all. That is not a lost quorum. */
function quorumOf(rows: Row[]): QuorumState {
  const cluster = rows.find((r) => r.type === 'cluster');
  const nodes = rows.filter((r) => r.type === 'node');
  const quorate = cluster ? flag(cluster.quorate) : undefined;
  return {
    state: !cluster ? 'standalone' : quorate === true ? 'quorate' : quorate === false ? 'no_quorum' : 'unknown',
    ...(str(cluster?.name) ? { cluster: str(cluster?.name) } : {}),
    nodes_total: num(cluster?.nodes) ?? nodes.length,
    nodes_online: nodes.filter((n) => flag(n.online) === true).length,
    offline_nodes: nodes.filter((n) => flag(n.online) === false).map((n) => String(n.name)),
  };
}

/** Status of a finished task. Anything but these is the error text of a failed one. */
function taskFailed(row: Row): boolean {
  const status = str(row.status);
  if (!status) return false;
  return !/^(ok|running|stopped)$/i.test(status) && !/^WARNINGS: \d+$/.test(status);
}

function recentFailedTasks(rows: Row[], hours: number): Row[] {
  const since = nowSeconds() - hours * 3600;
  return rows
    .filter(taskFailed)
    .filter((r) => (num(r.endtime) ?? num(r.starttime) ?? since) >= since)
    .sort((a, b) => (num(b.starttime) ?? 0) - (num(a.starttime) ?? 0))
    .map((r) => ({ upid: r.upid, node: r.node, type: r.type, id: r.id, user: r.user, status: r.status, started: isoTime(r.starttime), ended: isoTime(r.endtime) }));
}

interface HaState {
  services: number;
  by_state: Record<string, number>;
  quorate?: boolean;
  problem_services: Row[];
  problem_daemons: Row[];
}

const HA_DOWN = new Set(['error', 'fence', 'recovery']);
const HA_DAEMON_TROUBLE = /dead|old timestamp|unable|error/i;

function haOf(rows: Row[]): HaState {
  const services = rows.filter((r) => r.type === 'service');
  const byState: Record<string, number> = {};
  for (const s of services) {
    const state = str(s.crm_state) ?? str(s.state) ?? 'unknown';
    byState[state] = (byState[state] ?? 0) + 1;
  }
  const quorum = rows.find((r) => r.type === 'quorum');
  const quorate = flag(quorum?.quorate);
  return {
    services: services.length,
    by_state: byState,
    ...(quorate !== undefined ? { quorate } : {}),
    problem_services: services
      .filter((s) => {
        const state = str(s.crm_state) ?? str(s.state) ?? '';
        return HA_DOWN.has(state) || state === 'freeze';
      })
      .map((s) => ({ sid: s.sid, node: s.node, state: s.crm_state ?? s.state, requested: s.request_state, status: s.status })),
    problem_daemons: rows.filter((r) => (r.type === 'lrm' || r.type === 'master') && HA_DAEMON_TROUBLE.test(String(r.status ?? ''))).map((r) => ({ id: r.id, node: r.node, status: r.status })),
  };
}

function guestsOf(rows: Row[]): Row[] {
  return rows.filter((r) => (r.type === 'qemu' || r.type === 'lxc') && num(r.vmid) !== undefined);
}

function storagesOf(rows: Row[]): Row[] {
  return rows.filter((r) => r.type === 'storage');
}

/** A shared storage comes once per node: one entry, with the nodes that see it. */
function mergeShared(rows: Row[]): Array<{ row: Row; nodes: string[] }> {
  const merged = new Map<string, { row: Row; nodes: string[] }>();
  for (const row of rows) {
    const name = String(row.storage);
    const node = String(row.node ?? '');
    const key = flag(row.shared) === true ? name : `${name}@${node}`;
    const entry = merged.get(key);
    if (!entry) {
      merged.set(key, { row, nodes: [node] });
      continue;
    }
    entry.nodes.push(node);
    // The history of a shared storage has to be read through a node that can see it.
    if (entry.row.status === 'unknown' && row.status !== 'unknown') entry.row = row;
  }
  return [...merged.values()];
}

function guestParams(guest: { node: string; vmid: number }): { pathParams: { node: string; vmid: number } } {
  return { pathParams: { node: guest.node, vmid: guest.vmid } };
}

function guestPath(guest: { type: 'qemu' | 'lxc' }, suffix: string): string {
  return `/nodes/{node}/${guest.type}/{vmid}${suffix}`;
}

function locationOf(row: Row): { vmid: number; node: string; type: 'qemu' | 'lxc' } {
  return { vmid: num(row.vmid)!, node: String(row.node), type: row.type === 'lxc' ? 'lxc' : 'qemu' };
}

/** Node names and which of them can answer, from /nodes and, failing that, from the cluster status. */
function nodeNames(nodeRows: Row[], statusRows: Row[]): { online: string[]; offline: string[] } {
  if (nodeRows.length > 0) {
    const online = nodeRows.filter((n) => n.status !== 'offline').map((n) => String(n.node));
    return { online: online.sort(), offline: nodeRows.filter((n) => n.status === 'offline').map((n) => String(n.node)).sort() };
  }
  const entries = statusRows.filter((r) => r.type === 'node');
  return {
    online: entries.filter((n) => flag(n.online) !== false).map((n) => String(n.name)).sort(),
    offline: entries.filter((n) => flag(n.online) === false).map((n) => String(n.name)).sort(),
  };
}

function offlineReasons(sections: string[], offline: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const section of sections) for (const node of offline) out[`${section}/${node}`] = 'not checked: the node is offline.';
  return out;
}

/** Addresses from LXC interfaces or from the guest agent, which name the fields differently. */
function addressesOf(value: unknown): string[] {
  const rows = isObject(value) && Array.isArray(value.result) ? rowsOf(value.result) : rowsOf(value);
  const out: string[] = [];
  for (const iface of rows) {
    if (iface.name === 'lo') continue;
    for (const key of ['inet', 'inet6']) {
      const text = str(iface[key]);
      if (text) out.push(text.split('/')[0]!);
    }
    for (const entry of rowsOf(iface['ip-addresses'])) {
      const text = str(entry['ip-address']);
      if (text) out.push(text);
    }
  }
  return [...new Set(out)].filter((ip) => !ip.startsWith('127.') && ip !== '::1');
}

/** The address someone would connect to, IPv4 before IPv6. Link-local does not count: it is there before the network is up. */
function primaryAddress(ips: string[]): string | undefined {
  const linkLocal = (ip: string) => /^fe80:/i.test(ip) || ip.startsWith('169.254.');
  return ips.find((ip) => ip.includes('.') && !linkLocal(ip)) ?? ips.find((ip) => !linkLocal(ip));
}

async function readAddresses(ctx: ToolContext, guest: { node: string; vmid: number; type: 'qemu' | 'lxc' }): Promise<string[]> {
  const path = guest.type === 'lxc' ? guestPath(guest, '/interfaces') : guestPath(guest, '/agent/network-get-interfaces');
  return addressesOf(await ctx.api.get(path, guestParams(guest)));
}

/* ------------------------------------------------------------------ overview and search */

function overviewTool(): ToolDef {
  return tool({
    name: 'pve_overview',
    title: 'Cluster overview',
    description: 'The state of the cluster in one answer: version, quorum, nodes, guest counts, storage usage, HA and recent failed tasks. Whatever could not be read is named in "unavailable". A token only sees what it has audit rights on, so counts may be partial.',
    domain: 'workflows',
    also: ['cluster'],
    gate: 'read',
    idempotent: true,
    input: {
      task_hours: z.number().int().min(1).max(8760).optional().describe(`How far back failed tasks count, in hours. Default ${DEFAULT_TASK_HOURS}.`),
    },
    handler: async (args, ctx) => {
      const hours = args.task_hours ?? DEFAULT_TASK_HOURS;
      const { data, unavailable } = await gather({
        version: () => ctx.api.get('/version'),
        quorum: () => ctx.api.get('/cluster/status'),
        resources: () => ctx.api.get('/cluster/resources'),
        ha: () => ctx.api.get('/cluster/ha/status/current'),
        tasks: () => ctx.api.get('/cluster/tasks'),
      });
      const resources = rowsOf(data.resources);
      const guests = guestsOf(resources);
      const countBy = (rows: Row[], key: string) => {
        const out: Record<string, number> = {};
        for (const r of rows) out[String(r[key] ?? 'unknown')] = (out[String(r[key] ?? 'unknown')] ?? 0) + 1;
        return out;
      };
      const failed = data.tasks === undefined ? undefined : recentFailedTasks(rowsOf(data.tasks), hours);
      return {
        version: data.version ?? null,
        quorum: data.quorum === undefined ? null : quorumOf(rowsOf(data.quorum)),
        nodes:
          data.resources === undefined
            ? null
            : resources
                .filter((r) => r.type === 'node')
                .map((n) => ({
                  node: n.node,
                  status: n.status,
                  uptime: n.uptime,
                  cores: n.maxcpu,
                  cpu_percent: percent(num(n.cpu)),
                  memory_percent: percent(fraction(n.mem, n.maxmem)),
                })),
        guests:
          data.resources === undefined
            ? null
            : {
                total: guests.length,
                by_type: countBy(guests, 'type'),
                by_status: countBy(guests, 'status'),
                templates: guests.filter((g) => flag(g.template) === true).length,
              },
        storage:
          data.resources === undefined
            ? null
            : mergeShared(storagesOf(resources)).map(({ row, nodes }) => ({
                storage: row.storage,
                type: row.plugintype,
                shared: flag(row.shared) === true,
                nodes,
                status: row.status,
                used_bytes: row.disk,
                total_bytes: row.maxdisk,
                used_percent: percent(fraction(row.disk, row.maxdisk)),
              })),
        ha: data.ha === undefined ? null : haOf(rowsOf(data.ha)),
        failed_tasks: failed === undefined ? null : { window_hours: hours, count: failed.length, recent: failed.slice(0, 10) },
        complete: Object.keys(unavailable).length === 0,
        unavailable,
      };
    },
  });
}

function findGuestTool(): ToolDef {
  return tool({
    name: 'pve_find_guest',
    title: 'Find a guest',
    description: 'Finds VMs and containers by vmid, name, tag, status, node, type or IP address, across the cluster. An IP can only be read from a running LXC or from a running VM with its guest agent: those that could not be checked are listed in ip_not_checked, so no match does not mean the address is free.',
    domain: 'workflows',
    also: ['vm', 'lxc'],
    gate: 'read',
    idempotent: true,
    input: {
      vmid: vmid.optional(),
      name: z.string().min(1).max(255).optional().describe('Part of the name, in any case.'),
      tag: z.string().min(1).max(255).optional().describe('A whole tag, in any case.'),
      status: z.string().min(1).max(32).optional().describe('Such as running or stopped.'),
      node: nodeName.optional().describe('Only guests on this node.'),
      type: z.enum(['qemu', 'lxc']).optional().describe('qemu for VMs, lxc for containers.'),
      ip: z.string().min(2).max(64).optional().describe('An IPv4 or IPv6 address, without prefix length.'),
      include_ips: z.boolean().optional().describe('Also read the addresses of each running guest found. One request per guest. Implied by ip.'),
      ...paging,
    },
    handler: async (args, ctx) => {
      const rows = guestsOf(rowsOf(await ctx.api.get('/cluster/resources', { params: { type: 'vm' } })));
      const name = args.name?.toLowerCase();
      const tag = args.tag?.toLowerCase();
      let found = rows.filter(
        (r) =>
          (args.vmid === undefined || r.vmid === args.vmid) &&
          (name === undefined || String(r.name ?? '').toLowerCase().includes(name)) &&
          (tag === undefined || String(r.tags ?? '').toLowerCase().split(/[;,\s]+/).includes(tag)) &&
          (args.status === undefined || r.status === args.status) &&
          (args.node === undefined || r.node === args.node) &&
          (args.type === undefined || r.type === args.type),
      );
      const addresses = new Map<number, string[]>();
      const notChecked: Array<{ vmid: number; reason: string }> = [];
      if (args.ip !== undefined || args.include_ips === true) {
        const running = found.filter((r) => {
          if (r.status === 'running') return true;
          notChecked.push({ vmid: num(r.vmid)!, reason: `status is ${String(r.status)}: addresses can only be read from a running guest.` });
          return false;
        });
        const read = await gather(Object.fromEntries(running.map((r) => [String(r.vmid), () => readAddresses(ctx, locationOf(r))])));
        for (const [key, value] of Object.entries(read.data)) addresses.set(Number(key), value as string[]);
        for (const [key, reason] of Object.entries(read.unavailable)) notChecked.push({ vmid: Number(key), reason });
      }
      if (args.ip !== undefined) {
        const ip = args.ip.toLowerCase();
        found = found.filter((r) => addresses.get(num(r.vmid)!)?.some((a) => a.toLowerCase() === ip));
      }
      const out = found.map((r) => ({
        vmid: r.vmid,
        name: r.name,
        type: r.type,
        node: r.node,
        status: r.status,
        ...(r.tags ? { tags: r.tags } : {}),
        ...(flag(r.template) === true ? { template: true } : {}),
        ...(r.pool ? { pool: r.pool } : {}),
        ...(r.lock ? { lock: r.lock } : {}),
        ...(r.hastate ? { hastate: r.hastate } : {}),
        ...(addresses.has(num(r.vmid)!) ? { ips: addresses.get(num(r.vmid)!) } : {}),
      }));
      return {
        ...pageRows(out, args.page_limit, args.page_offset),
        ...(notChecked.length > 0 ? { ip_not_checked: notChecked.slice(0, MAX_LISTED), ip_not_checked_count: notChecked.length } : {}),
      };
    },
  });
}

/* ------------------------------------------------------------------ tasks */

function waitTaskTool(): ToolDef {
  return tool({
    name: 'pve_wait_task',
    title: 'Wait for a task',
    description: 'Waits for a task (UPID) to end and gives its result with the end of its log. A failed task is an error, task_failed. A task that outlasts the wait comes back with still_running: it goes on and is not cancelled.',
    domain: 'workflows',
    also: ['tasks'],
    gate: 'read',
    idempotent: true,
    input: {
      upid: z.string().min(1).max(512).describe('The task id, such as UPID:pve1:00001234:00ABCDEF:65000000:qmstart:100:root@pam:'),
      wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait. Default: PROXMOX_TASK_WAIT_SECONDS (30).'),
    },
    handler: async (args, ctx) => {
      // finish() hands back anything that is not a UPID as it is: here that is a mistake.
      parseUpid(args.upid);
      return ctx.tasks.finish(args.upid, args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds } : {});
    },
  });
}

/** Not taskLogTail: that one hides a failure behind an empty log, and here the log is the whole point. */
async function readLogTail(api: TaskApi, upid: string, node: string, lines: number): Promise<{ lines: string[]; total: number; complete: boolean }> {
  let tail: string[] = [];
  let total = 0;
  for (let page = 0; page < MAX_LOG_PAGES; page++) {
    const rows = rowsOf(await api.get('/nodes/{node}/tasks/{upid}/log', { pathParams: { node, upid }, params: { start: total, limit: LOG_PAGE } }));
    if (rows.length === 0) return { lines: tail, total, complete: true };
    total += rows.length;
    tail = [...tail, ...rows.map((r) => String(r.t ?? '')).filter((t) => t !== 'no content')].slice(-lines);
    if (rows.length < LOG_PAGE) return { lines: tail, total, complete: true };
  }
  return { lines: tail, total, complete: false };
}

function taskLogTool(): ToolDef {
  return tool({
    name: 'pve_get_task_log_tail',
    title: 'End of a task log',
    description: 'The status of a task and the last lines of its log, without having to page through it. The log is untrusted text.',
    domain: 'workflows',
    also: ['tasks'],
    gate: 'read',
    idempotent: true,
    input: {
      upid: z.string().min(1).max(512).describe('The task id.'),
      lines: z.number().int().min(1).max(5000).optional().describe('How many lines, from the end. Default 50.'),
    },
    handler: async (args, ctx) => {
      const { node } = parseUpid(args.upid);
      const [status, log] = await Promise.allSettled([ctx.api.get('/nodes/{node}/tasks/{upid}/status', { pathParams: { node, upid: args.upid } }), readLogTail(ctx.api, args.upid, node, args.lines ?? 50)]);
      if (log.status === 'rejected' && status.status === 'rejected') throw log.reason;
      const state = status.status === 'fulfilled' && isObject(status.value) ? status.value : undefined;
      const unavailable: Record<string, string> = {};
      if (status.status === 'rejected') unavailable.status = reasonOf(status.reason);
      if (log.status === 'rejected') unavailable.log = reasonOf(log.reason);
      return {
        upid: args.upid,
        node,
        status: state?.status ?? null,
        exitstatus: state?.exitstatus ?? null,
        log_tail: log.status === 'fulfilled' ? log.value.lines : null,
        ...(log.status === 'fulfilled' ? { lines_read: log.value.total, ...(log.value.complete ? {} : { note: `Read the first ${log.value.total} lines only: the log is longer, so this is not its end.` }) } : {}),
        ...(Object.keys(unavailable).length > 0 ? { unavailable } : {}),
      };
    },
  });
}

/* ------------------------------------------------------------------ one guest, whatever its type */

async function currentStatus(ctx: ToolContext, guest: GuestLocation): Promise<string | undefined> {
  const value = await ctx.api.get(guestPath(guest, '/status/current'), guestParams(guest));
  return isObject(value) ? str(value.status) : undefined;
}

const POWER_NOOP: Record<string, string> = { start: 'running', stop: 'stopped', shutdown: 'stopped' };

function guestPowerTool(): ToolDef {
  return tool({
    name: 'pve_guest_power',
    title: 'Start or stop a guest',
    description: 'Starts, shuts down, stops or reboots a VM or a container from its vmid, finds the node and the type, and waits for the task. stop cuts the power at once, as pulling the plug would; shutdown asks the guest to stop cleanly. Destructive except for start. A guest that is already in the requested state is left alone.',
    domain: 'workflows',
    also: ['vm', 'lxc'],
    gate: 'write',
    destructiveWhen: (args) => args.action !== 'start',
    input: {
      vmid,
      action: z.enum(['start', 'shutdown', 'stop', 'reboot']).describe('What to do.'),
      timeout: z.number().int().min(0).optional().describe('For shutdown and reboot: seconds the guest has to comply.'),
      force_stop: z.boolean().optional().describe('For shutdown: stop the guest hard when it did not comply within the timeout.'),
      wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30).'),
    },
    confirmation: (args) => `${args.action} guest ${args.vmid}? This interrupts whatever runs in it.`,
    handler: async (args, ctx) => {
      if (args.action !== 'shutdown' && args.force_stop !== undefined) {
        throw new ProxmoxError('invalid_input', 'force_stop only applies to shutdown.');
      }
      if (args.action !== 'shutdown' && args.action !== 'reboot' && args.timeout !== undefined) {
        throw new ProxmoxError('invalid_input', 'timeout only applies to shutdown and reboot.');
      }
      const guest = await ctx.nodes.resolveGuest(args.vmid);
      const base = { vmid: guest.vmid, node: guest.node, type: guest.type, action: args.action };
      let before: string | undefined;
      let beforeError: string | undefined;
      try {
        before = await currentStatus(ctx, guest);
      } catch (err) {
        // The action can still be right, and Proxmox will say if it is not.
        beforeError = reasonOf(err);
      }
      if (before !== undefined && POWER_NOOP[args.action] === before) {
        return { ...base, changed: false, status: before, note: `Guest ${guest.vmid} is already ${before}: nothing was sent.` };
      }
      if (args.action === 'reboot' && before === 'stopped') {
        throw new ProxmoxError('guest_not_running', `Guest ${guest.vmid} is stopped, so it cannot be rebooted.`, { hint: 'Use action start.' });
      }
      const params = { ...(args.timeout !== undefined ? { timeout: args.timeout } : {}), ...(args.force_stop !== undefined ? { forceStop: args.force_stop } : {}) };
      const answer = await ctx.api.post(guestPath(guest, `/status/${args.action}`), params, guestParams(guest));
      const outcome = await ctx.tasks.finish(answer, args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds } : {});
      const report: Record<string, unknown> = { ...base, status_before: before ?? null, ...(beforeError ? { status_before_unavailable: beforeError } : {}), ...outcome };
      if (ctx.dryRun || outcome.still_running) return report;
      report.changed = true;
      try {
        report.status_after = (await currentStatus(ctx, guest)) ?? null;
      } catch (err) {
        report.status_after = null;
        report.status_after_unavailable = reasonOf(err);
      }
      return report;
    },
  });
}

const snapshotName = z.string().regex(/^[a-zA-Z][a-zA-Z0-9_-]{1,39}$/, 'Expected a letter, then 1 to 39 letters, digits, - or _').describe('Name of the snapshot.');

function snapshotTool(): ToolDef {
  return tool({
    name: 'pve_snapshot_guest',
    title: 'Snapshot a guest',
    description: 'Takes a snapshot of a VM or a container from its vmid and waits for the task. Only VMs can include their memory.',
    domain: 'workflows',
    also: ['vm', 'lxc'],
    gate: 'write',
    input: {
      vmid,
      snapname: snapshotName,
      description: z.string().max(8192).optional().describe('A note kept with the snapshot.'),
      vmstate: z.boolean().optional().describe('VMs only: save the memory too.'),
      wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30).'),
    },
    handler: async (args, ctx) => {
      const guest = await ctx.nodes.resolveGuest(args.vmid);
      if (guest.type === 'lxc' && args.vmstate !== undefined) {
        throw new ProxmoxError('invalid_input', `Guest ${guest.vmid} is a container, and a container snapshot cannot include memory.`, { hint: 'Leave vmstate out.' });
      }
      const params = {
        snapname: args.snapname,
        ...(args.description !== undefined ? { description: args.description } : {}),
        ...(args.vmstate !== undefined ? { vmstate: args.vmstate } : {}),
      };
      const answer = await ctx.api.post(guestPath(guest, '/snapshot'), params, guestParams(guest));
      const outcome = await ctx.tasks.finish(answer, args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds } : {});
      return { vmid: guest.vmid, node: guest.node, type: guest.type, snapname: args.snapname, ...outcome };
    },
  });
}

function listSnapshotsTool(): ToolDef {
  return tool({
    name: 'pve_list_guest_snapshots',
    title: 'List the snapshots of a guest',
    description: 'The snapshots of a VM or a container from its vmid, oldest first, and which one the guest currently runs from. The "current" entry of the API is not a snapshot and is left out of rows.',
    domain: 'workflows',
    also: ['vm', 'lxc'],
    gate: 'read',
    idempotent: true,
    input: { vmid, ...paging },
    handler: async (args, ctx) => {
      const guest = await ctx.nodes.resolveGuest(args.vmid);
      const rows = rowsOf(await ctx.api.get(guestPath(guest, '/snapshot'), guestParams(guest)));
      const current = rows.find((r) => r.name === 'current');
      const snapshots = rows.filter((r) => r.name !== 'current').sort((a, b) => (num(a.snaptime) ?? 0) - (num(b.snaptime) ?? 0));
      return {
        vmid: guest.vmid,
        node: guest.node,
        type: guest.type,
        current_parent: current?.parent ?? null,
        ...pageRows(snapshots, args.page_limit, args.page_offset),
      };
    },
  });
}

/* ------------------------------------------------------------------ provisioning */

type StepStatus = 'done' | 'would_run' | 'skipped' | 'warning' | 'failed' | 'still_running';

interface StepReport extends Record<string, unknown> {
  step: string;
  status: StepStatus;
}

class StillRunning extends Error {
  constructor(
    readonly task: string,
    readonly node: string,
  ) {
    super('still running');
  }
}

/** Errors that do not tell whether Proxmox went on with the request. */
const OUTCOME_UNKNOWN = new Set(['task_failed', 'task_timeout', 'timeout', 'unreachable', 'bad_response', 'node_unreachable']);

/** The account of a provisioning job: what ran, what it created, and what is left to do. */
class Provision {
  readonly steps: StepReport[] = [];
  readonly created: Row[] = [];
  readonly warnings: string[] = [];
  /** How to remove what was created, if it is not wanted: it is never done automatically. */
  private readonly cleanups: string[] = [];
  private plan: Array<{ step: string; how: string }> = [];
  private uncertain?: string;
  private failedStep?: string;

  constructor(
    private readonly ctx: ToolContext,
    private readonly toolName: string,
    private readonly secrets: string[],
    private readonly waitSeconds: number | undefined,
  ) {}

  /** What this job still has to do, as tool calls an agent can make itself if it stops here. */
  setPlan(plan: Array<{ step: string; how: string }>): void {
    this.plan = plan;
  }

  private settled(step: string): void {
    this.plan = this.plan.filter((p) => p.step !== step);
  }

  note(step: string, status: StepStatus, fields: Row = {}): void {
    this.steps.push({ step, status, ...fields });
    // Still running counts: remaining must not invite anyone to start it a second time.
    this.settled(step);
  }

  warn(step: string, message: string): void {
    this.warnings.push(message);
    this.note(step, 'warning', { detail: message });
  }

  private fail(step: string, err: unknown): void {
    this.failedStep = step;
    const details = err instanceof ProxmoxError && isObject(err.details) ? err.details : undefined;
    this.steps.push({
      step,
      status: 'failed',
      error_type: err instanceof ProxmoxError ? err.type : 'internal_error',
      error: (err as Error)?.message ?? String(err),
      ...(err instanceof ProxmoxError && err.status !== undefined ? { http_status: err.status } : {}),
      ...(Array.isArray(details?.log_tail) ? { log_tail: details.log_tail } : {}),
      ...(isObject(details?.fields) ? { field_errors: details.fields } : {}),
    });
  }

  /** A read: it really runs in a dry run too, so a dry run can say what it found. */
  async read<T>(step: string, fields: (value: T) => Row, run: () => Promise<T>): Promise<T> {
    try {
      const value = await run();
      this.note(step, 'done', fields(value));
      return value;
    } catch (err) {
      this.fail(step, err);
      throw err;
    }
  }

  /** A write that answers at once. */
  async write(step: string, fields: Row, run: () => Promise<unknown>): Promise<void> {
    try {
      await run();
      this.note(step, this.ctx.dryRun ? 'would_run' : 'done', fields);
    } catch (err) {
      this.fail(step, err);
      throw err;
    }
  }

  /** A write that starts a task, followed to its end. Past the delay the whole job stops, reporting so. */
  async task(step: string, fields: Row, send: () => Promise<unknown>, creates?: { what: string; row: Row; cleanup: string }): Promise<void> {
    let outcome: Record<string, unknown>;
    try {
      const answer = await send();
      outcome = await this.ctx.tasks.finish(answer, this.waitSeconds !== undefined ? { waitSeconds: this.waitSeconds } : {});
    } catch (err) {
      this.fail(step, err);
      if (creates && err instanceof ProxmoxError && OUTCOME_UNKNOWN.has(err.type)) {
        this.uncertain = `${creates.what} may exist in part: the request was sent and did not end well (${err.type}). Check with pve_find_guest and with the task log.`;
        this.cleanups.push(creates.cleanup);
      }
      throw err;
    }
    if (outcome.still_running) {
      this.note(step, 'still_running', { ...fields, task: outcome.task });
      if (creates) {
        this.uncertain = `${creates.what} is still being created by task ${String(outcome.task)}.`;
        this.cleanups.push(creates.cleanup);
      }
      throw new StillRunning(String(outcome.task), String(outcome.node));
    }
    if (this.ctx.dryRun) {
      this.note(step, 'would_run', fields);
      return;
    }
    const warning = str(outcome.warning);
    if (warning) this.warnings.push(`${step}: ${warning}`);
    this.note(step, 'done', { ...fields, task: outcome.upid, exitstatus: outcome.exitstatus, ...(warning ? { warning } : {}) });
    if (creates) {
      this.created.push(creates.row);
      this.cleanups.push(creates.cleanup);
    }
  }

  private account(): Row {
    return {
      steps: this.steps,
      created: this.created,
      remaining: this.plan.map((p) => `${p.step}: ${p.how}`),
      ...(this.warnings.length > 0 ? { warnings: this.warnings } : {}),
      ...(this.uncertain ? { uncertain: this.uncertain } : {}),
    };
  }

  report(fields: Row): Row {
    const status = this.ctx.dryRun ? 'dry_run' : this.warnings.length > 0 ? 'complete_with_warnings' : 'complete';
    return this.scrub({ status, ...fields, ...this.account() });
  }

  stillRunning(err: StillRunning): Row {
    return this.scrub({
      status: 'still_running',
      task: err.task,
      node: err.node,
      next_step: 'pve_wait_task',
      note: 'The job stopped waiting here and did not go on: the steps under remaining were not run. Once the task has ended, carry them out one by one.',
      ...this.account(),
    });
  }

  failure(err: unknown): ProxmoxError {
    const message = `${this.toolName} stopped${this.failedStep ? ` at step "${this.failedStep}"` : ''}: ${(err as Error)?.message ?? String(err)}`;
    const nothingLeft = this.created.length === 0 && !this.uncertain;
    const type = err instanceof ProxmoxError ? err.type : 'upstream_error';
    const hint = err instanceof ProxmoxError ? err.hint : undefined;
    return new ProxmoxError(type, this.scrub(message), {
      ...(hint ? { hint: this.scrub(hint) } : {}),
      ...(err instanceof ProxmoxError && err.status !== undefined ? { status: err.status } : {}),
      details: this.scrub({
        failed_step: this.failedStep ?? null,
        ...this.account(),
        cleanup: nothingLeft ? 'Nothing was created, so there is nothing to clean up.' : `Nothing was deleted automatically.${this.cleanups.length > 0 ? ` What is not wanted can be removed with: ${this.cleanups.join('; ')}.` : ''}`,
      }),
    });
  }

  /** Proxmox can quote a refused value in its error: a password given as input must not come back that way. */
  private scrub<T>(value: T): T {
    if (this.secrets.length === 0) return value;
    const clean = (v: unknown): unknown => {
      if (typeof v === 'string') return this.secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), v);
      if (Array.isArray(v)) return v.map(clean);
      if (isObject(v)) return Object.fromEntries(Object.entries(v).map(([k, item]) => [k, clean(item)]));
      return v;
    };
    return clean(value) as T;
  }
}

async function provisioning(ctx: ToolContext, toolName: string, secrets: Array<string | undefined>, waitSeconds: number | undefined, body: (run: Provision) => Promise<Row>): Promise<Row> {
  const kept = secrets.filter((s): s is string => typeof s === 'string' && s !== '');
  const run = new Provision(ctx, toolName, [...kept, ...kept.map(encodeURIComponent).filter((e) => !kept.includes(e))], waitSeconds);
  try {
    return run.report(await body(run));
  } catch (err) {
    if (err instanceof StillRunning) return run.stillRunning(err);
    throw run.failure(err);
  }
}

function assertPublicKeys(value: string | undefined): void {
  if (value !== undefined && /PRIVATE KEY/.test(value)) {
    throw new ProxmoxError('invalid_input', 'The SSH keys given hold a private key. Only public keys go here: nothing was sent.');
  }
}

/** Given: Proxmox itself says whether it is free. Not given: Proxmox picks. */
async function chooseVmid(run: Provision, ctx: ToolContext, given: number | undefined): Promise<number> {
  if (given !== undefined) {
    await run.read('check_vmid', () => ({ vmid: given }), () => ctx.api.get('/cluster/nextid', { params: { vmid: given } }));
    return given;
  }
  return run.read(
    'pick_vmid',
    (id) => ({ vmid: id }),
    async () => {
      const id = num(await ctx.api.get('/cluster/nextid'));
      if (id === undefined) throw new ProxmoxError('bad_response', '/cluster/nextid did not answer with a vmid.');
      return id;
    },
  );
}

/** Polls until there is an answer or the time is up. Only trouble that can pass is tried again. */
async function poll<T>(seconds: number, attempt: () => Promise<T | undefined>, transient: (err: unknown) => boolean): Promise<{ value?: T; lastError?: string }> {
  const deadline = Date.now() + seconds * 1000;
  let wait = 500;
  let lastError: string | undefined;
  for (;;) {
    try {
      const value = await attempt();
      if (value !== undefined) return { value };
      lastError = undefined;
    } catch (err) {
      if (!transient(err)) return { lastError: reasonOf(err) };
      lastError = reasonOf(err);
    }
    const left = deadline - Date.now();
    if (left <= 0) return lastError ? { lastError } : {};
    await delay(Math.min(wait, left));
    wait = Math.min(wait * 2, 5000);
  }
}

function isTransientGuestError(err: unknown): boolean {
  return err instanceof ProxmoxError && (err.type === 'upstream_error' || err.type === 'timeout' || err.type === 'guest_locked');
}

function templateBasename(volid: string): string {
  return volid.slice(volid.lastIndexOf('/') + 1);
}

function matchTemplate(names: string[], wanted: string): string[] {
  const exact = names.filter((n) => n === wanted);
  return exact.length > 0 ? exact : names.filter((n) => n.startsWith(wanted));
}

/** Finds the template on a storage of the node, else downloads it from the appliance index. */
async function resolveLxcTemplate(run: Provision, ctx: ToolContext, node: string, args: { template: string; template_storage?: string | undefined; download_template?: boolean | undefined }): Promise<string> {
  const pathParams = { node };
  const wanted = args.template;
  const storageOf = wanted.includes(':') ? wanted.slice(0, wanted.indexOf(':')) : undefined;

  // A volume names its storage: being refused the list of storages should not stop that case.
  const allStorages = storageOf
    ? []
    : await run.read(
        'list_template_storages',
        (rows: Row[]) => ({ storages: rows.map((r) => r.storage) }),
        async () => rowsOf(await ctx.api.get('/nodes/{node}/storage', { pathParams, params: { content: 'vztmpl' } })).filter((r) => flag(r.enabled) !== false && (r.content === undefined || String(r.content).split(',').includes('vztmpl'))),
      );
  const names = storageOf ? [storageOf] : args.template_storage ? [args.template_storage] : allStorages.map((r) => String(r.storage));
  const contents = await gather(
    Object.fromEntries(names.map((storage) => [storage, async () => rowsOf(await ctx.api.get('/nodes/{node}/storage/{storage}/content', { pathParams: { node, storage }, params: { content: 'vztmpl' } }))])),
  );
  const unread = Object.entries(contents.unavailable);
  for (const [storage, reason] of unread) run.warn('read_template_storage', `Could not list templates on storage ${storage}: ${reason}`);

  if (storageOf) {
    const rows = (contents.data[storageOf] as Row[] | undefined) ?? [];
    if (rows.some((r) => r.volid === wanted)) {
      run.note('find_template', 'done', { ostemplate: wanted, source: 'storage' });
      return wanted;
    }
    // Proxmox has the last word when the storage could not be listed.
    if (unread.length > 0) {
      run.warn('find_template', `Template ${wanted} could not be verified before use.`);
      return wanted;
    }
    throw new ProxmoxError('invalid_input', `Template ${wanted} is not on storage ${storageOf} of node ${node}.`, {
      hint: 'pve_list_storage_content lists what is there. Give a template name without storage to have it looked up and downloaded.',
    });
  }

  const local = Object.values(contents.data).flatMap((rows) => (rows as Row[]).map((r) => String(r.volid ?? '')).filter(Boolean));
  const localHits = local.filter((volid) => matchTemplate(local.map(templateBasename), wanted).includes(templateBasename(volid)));
  if (localHits.length > 1) {
    throw new ProxmoxError('invalid_input', `"${wanted}" matches several templates on this node: ${localHits.join(', ')}.`, { hint: 'Give the full volume id.', details: { candidates: localHits } });
  }
  if (localHits.length === 1) {
    run.note('find_template', 'done', { ostemplate: localHits[0], source: 'storage' });
    return localHits[0]!;
  }

  const index = await run.read(
    'read_appliance_index',
    (rows: Row[]) => ({ available: rows.length }),
    async () => rowsOf(await ctx.api.get('/nodes/{node}/aplinfo', { pathParams })),
  );
  const offered = index.map((r) => String(r.template ?? '')).filter(Boolean);
  const hits = matchTemplate(offered, wanted);
  if (hits.length === 0) {
    throw new ProxmoxError('invalid_input', `No template "${wanted}" on the storages of node ${node} nor in the appliance index.`, {
      hint: 'pve_list_appliance_templates lists what can be downloaded.',
      details: { offered: offered.slice(0, MAX_LISTED) },
    });
  }
  if (hits.length > 1) {
    throw new ProxmoxError('invalid_input', `"${wanted}" matches several templates in the appliance index: ${hits.slice(0, 20).join(', ')}.`, { hint: 'Give the full name of one of them.', details: { candidates: hits.slice(0, MAX_LISTED) } });
  }
  if (args.download_template === false) {
    throw new ProxmoxError('invalid_input', `Template ${hits[0]} is not on this node, and download_template is false.`);
  }
  const storage = args.template_storage ?? str(allStorages[0]?.storage);
  if (!storage) {
    throw new ProxmoxError('invalid_input', `No storage on node ${node} accepts container templates.`, { hint: 'Give template_storage, or have the operator enable vztmpl content on a storage.' });
  }
  const volid = `${storage}:vztmpl/${hits[0]!}`;
  await run.task('download_template', { template: hits[0], storage }, () => ctx.api.post('/nodes/{node}/aplinfo', { storage, template: hits[0] }, { pathParams }), {
    what: `Template ${volid}`,
    row: { type: 'template', volid, node },
    cleanup: `pve_delete_storage_volume with storage ${storage} and volume ${volid}`,
  });
  return volid;
}

function provisionLxcTool(): ToolDef {
  return tool({
    name: 'pve_provision_lxc',
    title: 'Provision a container',
    description:
      'Creates a container from start to finish: free vmid, template found on a storage or downloaded from the appliance index, creation, start, IP address. Each step is reported. If one fails, the error says what was created and what remains: nothing is ever deleted automatically. It never replaces an existing guest. The password is never returned.',
    domain: 'workflows',
    also: ['lxc'],
    gate: 'write',
    input: {
      hostname: z.string().regex(/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/, 'Expected a host name').max(255).describe('Host name of the container.'),
      template: z.string().min(1).max(512).describe('A volume such as local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst, or a name or start of name such as debian-12-standard, looked up on the storages of the node and then in the appliance index.'),
      node: nodeName.optional().describe('The node. Optional when there is a default node or only one node.'),
      vmid: vmid.optional().describe('The id to use. Default: the next free one.'),
      storage: z.string().min(1).max(128).optional().describe('Storage of the root disk.'),
      disk_gb: z.number().int().min(1).max(131072).optional().describe('Size of the root disk in GiB. Needs storage.'),
      template_storage: z.string().min(1).max(128).optional().describe('Storage to look for the template on and to download it to. Default: the storages of the node that accept templates.'),
      download_template: z.boolean().optional().describe('Download the template when it is not on the node. Default true.'),
      net0: z.string().min(1).max(512).optional().describe(`First network interface, as a Proxmox property string. Default: ${DEFAULT_LXC_NET}.`),
      ssh_public_keys: z.string().max(65536).optional().describe('Public SSH keys for root, one per line.'),
      password: z.string().min(5).max(512).optional().describe('Root password of the container. Never returned nor logged.'),
      cores: z.number().int().min(1).max(8192).optional().describe('CPU cores.'),
      memory: z.number().int().min(16).optional().describe('Memory in MiB.'),
      swap: z.number().int().min(0).optional().describe('Swap in MiB.'),
      unprivileged: z.boolean().optional().describe('Run as an unprivileged container. Default true, which is safer than the Proxmox default.'),
      features: z.string().max(512).optional().describe('Features as a property string, such as nesting=1.'),
      nameserver: z.string().max(512).optional().describe('DNS servers.'),
      searchdomain: z.string().max(512).optional().describe('DNS search domain.'),
      tags: z.string().max(512).optional().describe('Tags, separated by semicolons.'),
      pool: z.string().max(128).optional().describe('Resource pool.'),
      onboot: z.boolean().optional().describe('Start with the node.'),
      description: z.string().max(8192).optional().describe('Notes.'),
      start: z.boolean().optional().describe('Start it at the end. Default true.'),
      ip_wait_seconds: z.number().int().min(0).max(600).optional().describe(`How long to wait for an IP address after the start. Default ${DEFAULT_IP_WAIT_SECONDS}.`),
      wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait for each task. Default: PROXMOX_TASK_WAIT_SECONDS (30). Past this the job stops and reports what remains.'),
    },
    handler: (args, ctx) =>
      provisioning(ctx, 'pve_provision_lxc', [args.password], args.wait_seconds, async (run) => {
        assertPublicKeys(args.ssh_public_keys);
        if (args.disk_gb !== undefined && args.storage === undefined) {
          throw new ProxmoxError('invalid_input', 'disk_gb needs storage: the root disk has to go somewhere.');
        }
        const node = args.node ?? (await run.read('resolve_node', (n: string) => ({ node: n }), () => ctx.nodes.defaultNode()));
        const id = await chooseVmid(run, ctx, args.vmid);
        const where = { node, vmid: id };
        const start = args.start !== false;
        run.setPlan([
          { step: 'create', how: `pve_create_lxc with vmid ${id} and the wanted values` },
          ...(start ? [{ step: 'start', how: `pve_start_lxc with vmid ${id}` }] : []),
        ]);
        const ostemplate = await resolveLxcTemplate(run, ctx, node, args);
        const params = {
          vmid: id,
          ostemplate,
          hostname: args.hostname,
          unprivileged: args.unprivileged ?? true,
          net0: args.net0 ?? DEFAULT_LXC_NET,
          ...(args.disk_gb !== undefined ? { rootfs: `${args.storage}:${args.disk_gb}` } : args.storage !== undefined ? { storage: args.storage } : {}),
          ...(args.ssh_public_keys !== undefined ? { 'ssh-public-keys': args.ssh_public_keys } : {}),
          ...(args.password !== undefined ? { password: args.password } : {}),
          ...(args.cores !== undefined ? { cores: args.cores } : {}),
          ...(args.memory !== undefined ? { memory: args.memory } : {}),
          ...(args.swap !== undefined ? { swap: args.swap } : {}),
          ...(args.features !== undefined ? { features: args.features } : {}),
          ...(args.nameserver !== undefined ? { nameserver: args.nameserver } : {}),
          ...(args.searchdomain !== undefined ? { searchdomain: args.searchdomain } : {}),
          ...(args.tags !== undefined ? { tags: args.tags } : {}),
          ...(args.pool !== undefined ? { pool: args.pool } : {}),
          ...(args.onboot !== undefined ? { onboot: args.onboot } : {}),
          ...(args.description !== undefined ? { description: args.description } : {}),
        };
        await run.task('create', { vmid: id, ostemplate }, () => ctx.api.post('/nodes/{node}/lxc', params, { pathParams: { node } }), {
          what: `Container ${id} on ${node}`,
          row: { type: 'lxc', vmid: id, node },
          cleanup: `pve_delete_lxc with vmid ${id}`,
        });

        const common = { vmid: id, node, hostname: args.hostname, ostemplate };
        if (!start) {
          run.note('start', 'skipped', { detail: 'start is false.' });
          return { ...common, running: false, ip: null };
        }
        await run.task('start', { vmid: id }, () => ctx.api.post('/nodes/{node}/lxc/{vmid}/status/start', undefined, { pathParams: where }));
        if (ctx.dryRun) {
          run.note('find_ip', 'would_run', { detail: 'The address can only be read once the container runs.' });
          return { ...common, running: false, ip: null };
        }
        const found = await poll(
          args.ip_wait_seconds ?? DEFAULT_IP_WAIT_SECONDS,
          async () => {
            const ips = await readAddresses(ctx, { ...where, type: 'lxc' });
            return primaryAddress(ips) ? ips : undefined;
          },
          isTransientGuestError,
        );
        if (found.value) {
          run.note('find_ip', 'done', { ips: found.value });
          return { ...common, running: true, ip: primaryAddress(found.value), ips: found.value };
        }
        run.warn('find_ip', `No IP address seen on container ${id} in the time given${found.lastError ? ` (${found.lastError})` : ''}. It may still be getting one: see pve_list_lxc_interfaces.`);
        return { ...common, running: true, ip: null };
      }),
  });
}

/** The first disk of the boot order, else the old bootdisk key, else nothing. */
function bootDisk(config: Row): string | undefined {
  const isDisk = (name: string) => /^(ide|sata|scsi|virtio)\d+$/.test(name) && typeof config[name] === 'string' && !/(^|,)media=cdrom(,|$)/.test(config[name]);
  const order = /(?:^|;|,)order=([^,]+)/.exec(String(config.boot ?? ''))?.[1];
  const inOrder = order?.split(';').find(isDisk);
  if (inOrder) return inOrder;
  const legacy = str(config.bootdisk);
  return legacy && isDisk(legacy) ? legacy : undefined;
}

function agentEnabled(config: Row): boolean {
  // A property string: the switch comes either as a bare first value or as enabled=, in any place.
  const parts = String(config.agent ?? '0').split(',');
  const on = /^(1|true|yes|on)$/i;
  return on.test(parts[0]!) || parts.some((part) => part.startsWith('enabled=') && on.test(part.slice('enabled='.length)));
}

function hasCloudInitDrive(config: Row): boolean {
  return Object.entries(config).some(([k, v]) => /^(ide|sata|scsi|virtio)\d+$/.test(k) && typeof v === 'string' && /cloudinit/.test(v));
}

function provisionVmTool(): ToolDef {
  return tool({
    name: 'pve_provision_vm_from_template',
    title: 'Provision a VM from a template',
    description:
      'Makes a VM from a VM template from start to finish: clone, cloud-init (ciuser, cipassword, sshkeys, ipconfig0), disk resize, start, wait for the guest agent. Each step is reported. If one fails, the error says what was created and what remains: nothing is ever deleted automatically. It never replaces an existing guest. The password is never returned.',
    domain: 'workflows',
    also: ['vm'],
    gate: 'write',
    input: {
      template_vmid: vmid.describe('The vmid of the VM template to clone.'),
      newid: vmid.optional().describe('The id of the new VM. Default: the next free one.'),
      name: z.string().regex(/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/, 'Expected a host name').max(255).describe('Name of the new VM.'),
      target_node: nodeName.optional().describe("Node of the new VM. Default: the template's. A different node needs storage the target can reach."),
      full: z.boolean().optional().describe('Full copy rather than linked clone. Implied by storage.'),
      storage: z.string().min(1).max(128).optional().describe('Storage for a full clone.'),
      pool: z.string().max(128).optional().describe('Resource pool.'),
      description: z.string().max(8192).optional().describe('Notes.'),
      ciuser: z.string().max(128).optional().describe('Cloud-init user.'),
      cipassword: z.string().min(5).max(512).optional().describe('Cloud-init password. Never returned nor logged.'),
      sshkeys: z.string().max(65536).optional().describe('Public SSH keys for cloud-init, one per line, in plain text.'),
      ipconfig0: z.string().max(512).optional().describe('Cloud-init address of the first interface, such as ip=dhcp or ip=10.0.0.5/24,gw=10.0.0.1.'),
      nameserver: z.string().max(512).optional().describe('Cloud-init DNS servers.'),
      searchdomain: z.string().max(512).optional().describe('Cloud-init search domain.'),
      cores: z.number().int().min(1).max(8192).optional().describe('CPU cores.'),
      memory: z.number().int().min(16).optional().describe('Memory in MiB.'),
      tags: z.string().max(512).optional().describe('Tags, separated by semicolons.'),
      onboot: z.boolean().optional().describe('Start with the node.'),
      enable_agent: z.boolean().optional().describe('Set agent=1 on the new VM. The guest system still has to run qemu-guest-agent.'),
      disk: z.string().regex(/^(ide|sata|scsi|virtio)\d+$/, 'Expected a disk such as scsi0').optional().describe('Disk to resize. Default: the first disk of the boot order.'),
      disk_size: z.string().regex(/^\+?\d+(\.\d+)?[KMGT]?$/, 'Expected a size such as 40G or +10G').optional().describe('New size such as 40G, or growth such as +10G. Disks cannot shrink.'),
      start: z.boolean().optional().describe('Start it at the end. Default true.'),
      agent_wait_seconds: z.number().int().min(0).max(1800).optional().describe(`How long to wait for the guest agent after the start. Default ${DEFAULT_AGENT_WAIT_SECONDS}. 0 does not wait.`),
      wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait for each task. Default: PROXMOX_TASK_WAIT_SECONDS (30). Past this the job stops and reports what remains.'),
    },
    handler: (args, ctx) =>
      provisioning(ctx, 'pve_provision_vm_from_template', [args.cipassword], args.wait_seconds, async (run) => {
        assertPublicKeys(args.sshkeys);
        const source = await run.read(
          'find_template',
          (g: GuestLocation) => ({ vmid: g.vmid, node: g.node, name: g.name }),
          async () => {
            const guest = await ctx.nodes.resolveGuest(args.template_vmid);
            if (guest.type !== 'qemu') throw new ProxmoxError('invalid_input', `Guest ${guest.vmid} is a container.`, { hint: 'pve_provision_lxc or pve_clone_lxc are the tools for containers.' });
            if (!guest.template) throw new ProxmoxError('invalid_input', `VM ${guest.vmid} is not a template.`, { hint: 'pve_clone_vm clones any VM. pve_convert_vm_to_template makes a template, irreversibly.' });
            return guest;
          },
        );
        const config = await run.read(
          'read_template_config',
          () => ({ vmid: source.vmid }),
          async () => {
            const value = await ctx.api.get('/nodes/{node}/qemu/{vmid}/config', guestParams(source));
            return isObject(value) ? value : {};
          },
        );
        const resizeDisk = args.disk ?? (args.disk_size !== undefined ? bootDisk(config) : undefined);
        if (args.disk_size !== undefined && !resizeDisk) {
          throw new ProxmoxError('invalid_input', `Could not tell which disk of template ${source.vmid} to resize.`, { hint: 'Give disk, such as scsi0.' });
        }

        const id = await chooseVmid(run, ctx, args.newid);
        const node = args.target_node ?? source.node;
        const where = { node, vmid: id };
        const settings = {
          ...(args.ciuser !== undefined ? { ciuser: args.ciuser } : {}),
          ...(args.cipassword !== undefined ? { cipassword: args.cipassword } : {}),
          ...(args.sshkeys !== undefined ? { sshkeys: args.sshkeys } : {}),
          ...(args.ipconfig0 !== undefined ? { ipconfig0: args.ipconfig0 } : {}),
          ...(args.nameserver !== undefined ? { nameserver: args.nameserver } : {}),
          ...(args.searchdomain !== undefined ? { searchdomain: args.searchdomain } : {}),
          ...(args.cores !== undefined ? { cores: args.cores } : {}),
          ...(args.memory !== undefined ? { memory: args.memory } : {}),
          ...(args.tags !== undefined ? { tags: args.tags } : {}),
          ...(args.onboot !== undefined ? { onboot: args.onboot } : {}),
          ...(args.enable_agent !== undefined ? { agent: args.enable_agent ? '1' : '0' } : {}),
        };
        const configure = Object.keys(settings).length > 0;
        const start = args.start !== false;
        run.setPlan([
          { step: 'clone', how: `pve_clone_vm with vmid ${source.vmid} and newid ${id}` },
          ...(configure ? [{ step: 'configure', how: `pve_update_vm_config with vmid ${id} and the wanted values` }] : []),
          ...(args.disk_size !== undefined ? [{ step: 'resize', how: `pve_resize_vm_disk with vmid ${id}, disk ${resizeDisk} and size ${args.disk_size}` }] : []),
          ...(start ? [{ step: 'start', how: `pve_start_vm with vmid ${id}` }] : []),
        ]);

        const full = args.full ?? (args.storage !== undefined ? true : undefined);
        const cloneParams = {
          newid: id,
          name: args.name,
          ...(full !== undefined ? { full } : {}),
          ...(args.storage !== undefined ? { storage: args.storage } : {}),
          ...(args.target_node !== undefined ? { target: args.target_node } : {}),
          ...(args.pool !== undefined ? { pool: args.pool } : {}),
          ...(args.description !== undefined ? { description: args.description } : {}),
        };
        await run.task('clone', { source: source.vmid, newid: id }, () => ctx.api.post('/nodes/{node}/qemu/{vmid}/clone', cloneParams, guestParams(source)), {
          what: `VM ${id} on ${node}`,
          row: { type: 'qemu', vmid: id, node },
          cleanup: `pve_delete_vm with vmid ${id}`,
        });

        const cloudInit = ['ciuser', 'cipassword', 'sshkeys', 'ipconfig0', 'nameserver', 'searchdomain'].some((k) => k in settings);
        if (cloudInit && !hasCloudInitDrive(config)) {
          run.warnings.push(`Template ${source.vmid} has no cloud-init drive: the cloud-init values are stored, but the guest will not receive them until one is added.`);
        }
        if (configure) {
          await run.write('configure', { keys: Object.keys(settings) }, () => ctx.api.put('/nodes/{node}/qemu/{vmid}/config', settings, { pathParams: where }));
        } else {
          run.note('configure', 'skipped', { detail: 'No value to set.' });
        }
        if (args.disk_size !== undefined) {
          await run.task('resize', { disk: resizeDisk, size: args.disk_size }, () => ctx.api.put('/nodes/{node}/qemu/{vmid}/resize', { disk: resizeDisk, size: args.disk_size }, { pathParams: where }));
        } else {
          run.note('resize', 'skipped', { detail: 'No disk_size given.' });
        }

        const common = { vmid: id, node, name: args.name, template: source.vmid };
        if (!start) {
          run.note('start', 'skipped', { detail: 'start is false.' });
          return { ...common, running: false, ip: null };
        }
        await run.task('start', { vmid: id }, () => ctx.api.post('/nodes/{node}/qemu/{vmid}/status/start', undefined, { pathParams: where }));

        const agentOn = args.enable_agent ?? agentEnabled(config);
        const agentSeconds = args.agent_wait_seconds ?? DEFAULT_AGENT_WAIT_SECONDS;
        if (ctx.dryRun) {
          run.note('wait_agent', agentOn && agentSeconds > 0 ? 'would_run' : 'skipped');
          return { ...common, running: false, ip: null };
        }
        if (!agentOn || agentSeconds === 0) {
          run.note('wait_agent', 'skipped', { detail: agentOn ? 'agent_wait_seconds is 0.' : 'The guest agent is not enabled on this VM: there is nothing to wait for, and no way to read its address here. enable_agent turns it on.' });
          return { ...common, running: true, ip: null };
        }
        const agent = await poll(
          agentSeconds,
          async () => {
            await ctx.api.post('/nodes/{node}/qemu/{vmid}/agent/ping', undefined, { pathParams: where });
            const ips = await readAddresses(ctx, { ...where, type: 'qemu' });
            return primaryAddress(ips) ? ips : undefined;
          },
          isTransientGuestError,
        );
        if (agent.value) {
          run.note('wait_agent', 'done', { ips: agent.value });
          return { ...common, running: true, ip: primaryAddress(agent.value), ips: agent.value };
        }
        run.warn('wait_agent', `The guest agent of VM ${id} gave no address in the time given${agent.lastError ? ` (${agent.lastError})` : ''}. The guest system may still be booting, or may not run qemu-guest-agent: see pve_ping_vm_agent.`);
        return { ...common, running: true, ip: null };
      }),
  });
}

/* ------------------------------------------------------------------ health */

const HEALTH_SEVERITIES: readonly HealthSeverity[] = ['critical', 'warning', 'info'];

function checkCeph(report: Report<HealthSeverity>, ceph: { data: Record<string, unknown>; unavailable: Record<string, string> }): Record<string, string> {
  const notApplicable: Record<string, string> = {};
  const reason = ceph.unavailable.ceph;
  if (reason !== undefined) {
    // What Proxmox answers where Ceph was never set up. It is not a failure to read.
    if (/not initialized|not installed|not configured/i.test(reason)) notApplicable.ceph = reason;
    else report.unavailable.ceph = reason;
    return notApplicable;
  }
  const status = ceph.data.ceph;
  const health = isObject(status) && isObject(status.health) ? status.health : undefined;
  const value = str(health?.status);
  if (!value) {
    report.unavailable.ceph = 'The answer holds no health status.';
    return notApplicable;
  }
  report.checked.add('ceph');
  if (value === 'HEALTH_OK') return notApplicable;
  const checks = isObject(health?.checks) ? Object.keys(health.checks) : [];
  report.add(value === 'HEALTH_ERR' ? 'critical' : 'warning', 'ceph', 'ceph', { status: value, checks }, 'See pve_get_cluster_ceph_status for the detail of each check.');
  return notApplicable;
}

function checkNodeStorage(report: Report<HealthSeverity>, perNode: Map<string, Row[]>, warn: number, critical: number): void {
  const rows: Row[] = [];
  for (const [node, list] of perNode) for (const row of list) rows.push({ ...row, node });
  for (const { row, nodes } of mergeShared(rows.filter((r) => flag(r.enabled) !== false))) {
    const object = `storage ${String(row.storage)}`;
    if (flag(row.active) === false) {
      report.add('critical', 'storage', object, { nodes, active: false, type: row.type }, 'The storage is enabled but not reachable from these nodes. Check its backend, then pve_list_node_storage.');
      continue;
    }
    const used = num(row.used_fraction) ?? fraction(row.used, row.total);
    if (used === undefined) continue;
    const usedPercent = round(used * 100);
    if (usedPercent >= warn) {
      report.add(usedPercent >= critical ? 'critical' : 'warning', 'storage', object, { nodes, used_percent: usedPercent, used_bytes: row.used, total_bytes: row.total, threshold_percent: usedPercent >= critical ? critical : warn }, 'Free space or extend the storage. pve_capacity_report shows the trend and the biggest guests.');
    }
  }
}

function healthTool(): ToolDef {
  return tool({
    name: 'pve_health_check',
    title: 'Health check',
    description:
      'Checks nodes, quorum, storage usage, failed services, failed tasks, HA, Ceph if there is any, replication and subscriptions. Each finding has a severity, the object, the evidence and a suggested action. Sections that could not be read are in "unavailable" and are not counted as healthy: overall says "incomplete" rather than good news. The thresholds used are returned with the answer.',
    domain: 'workflows',
    also: ['cluster'],
    gate: 'read',
    idempotent: true,
    input: {
      storage_warn_percent: z.number().min(1).max(100).optional().describe(`Usage from which a storage or root disk is a warning. Default ${DEFAULT_STORAGE_WARN_PERCENT}.`),
      storage_critical_percent: z.number().min(1).max(100).optional().describe(`Usage from which it is critical. Default ${DEFAULT_STORAGE_CRITICAL_PERCENT}.`),
      memory_warn_percent: z.number().min(1).max(100).optional().describe(`Node memory usage from which it is a warning. Default ${DEFAULT_MEMORY_WARN_PERCENT}.`),
      task_hours: z.number().int().min(1).max(8760).optional().describe(`How far back failed tasks count, in hours. Default ${DEFAULT_TASK_HOURS}.`),
    },
    handler: async (args, ctx) => {
      const thresholds = {
        storage_warn_percent: args.storage_warn_percent ?? DEFAULT_STORAGE_WARN_PERCENT,
        storage_critical_percent: args.storage_critical_percent ?? DEFAULT_STORAGE_CRITICAL_PERCENT,
        memory_warn_percent: args.memory_warn_percent ?? DEFAULT_MEMORY_WARN_PERCENT,
        task_hours: args.task_hours ?? DEFAULT_TASK_HOURS,
      };
      const report = new Report<HealthSeverity>();
      const top = await gather({
        nodes: () => ctx.api.get('/nodes'),
        quorum: () => ctx.api.get('/cluster/status'),
        tasks: () => ctx.api.get('/cluster/tasks'),
        ha: () => ctx.api.get('/cluster/ha/status/current'),
      });
      report.absorb(top);
      const ceph = await gather({ ceph: () => ctx.api.get('/cluster/ceph/status') });
      const notApplicable = checkCeph(report, ceph);

      const nodeRows = rowsOf(top.data.nodes);
      const statusRows = rowsOf(top.data.quorum);
      for (const n of nodeRows) {
        const object = `node ${String(n.node)}`;
        if (n.status === 'offline') {
          report.add('critical', 'nodes', object, { status: n.status }, 'Bring the node back or find out why it left. Its guests and local storage are out of reach.');
          continue;
        }
        if (n.status !== 'online') report.add('warning', 'nodes', object, { status: n.status ?? null }, 'The cluster cannot tell the state of this node: check corosync and the node itself.');
        const used = fraction(n.mem, n.maxmem);
        if (used !== undefined && round(used * 100) >= thresholds.memory_warn_percent) {
          report.add('warning', 'nodes', object, { memory_percent: round(used * 100), threshold_percent: thresholds.memory_warn_percent }, 'Look at the guests on this node with pve_capacity_report.');
        }
      }

      if (top.data.quorum !== undefined) {
        const quorum = quorumOf(statusRows);
        if (quorum.state === 'no_quorum') report.add('critical', 'quorum', `cluster ${quorum.cluster ?? ''}`.trim(), { quorate: false, nodes_online: quorum.nodes_online, nodes_total: quorum.nodes_total }, 'Without quorum, /etc/pve is read-only and guests cannot be changed. Bring nodes back before anything else.');
        if (quorum.state === 'unknown') report.add('warning', 'quorum', `cluster ${quorum.cluster ?? ''}`.trim(), { quorate: null }, 'The cluster status does not say whether there is quorum: check with pve_get_cluster_status.');
        for (const name of quorum.offline_nodes) {
          if (top.data.nodes === undefined) report.add('critical', 'nodes', `node ${name}`, { online: false, source: '/cluster/status' }, 'Bring the node back or find out why it left.');
        }
      }

      if (top.data.tasks !== undefined) {
        const failed = recentFailedTasks(rowsOf(top.data.tasks), thresholds.task_hours);
        if (failed.length > 0) {
          report.add('warning', 'tasks', 'tasks', { window_hours: thresholds.task_hours, count: failed.length, recent: failed.slice(0, 20) }, 'Read why with pve_get_task_log_tail and the upid.');
        }
      }

      if (top.data.ha !== undefined) {
        const ha = haOf(rowsOf(top.data.ha));
        if (ha.quorate === false) report.add('critical', 'ha', 'ha quorum', { quorate: false }, 'HA does nothing without quorum. Restore the quorum first.');
        for (const s of ha.problem_services) {
          report.add(s.state === 'freeze' ? 'warning' : 'critical', 'ha', `ha resource ${String(s.sid)}`, s, s.state === 'freeze' ? 'A frozen resource is not being recovered: this is normal while its node restarts, otherwise look at the node.' : 'Read pve_get_ha_status and the task log of the node, then clear the state with pve_update_ha_resource.');
        }
        for (const d of ha.problem_daemons) report.add('warning', 'ha', `ha daemon ${String(d.id)}`, d, 'Look at pve-ha-lrm and pve-ha-crm on this node with pve_list_node_services.');
      }

      const { online, offline } = nodeNames(nodeRows, statusRows);
      const perNodeSections = ['node_status', 'storage', 'services', 'replication', 'subscription'];
      if (online.length === 0 && offline.length === 0) {
        for (const section of perNodeSections) report.unavailable[section] = 'not checked: no node list could be read.';
      }
      Object.assign(report.unavailable, offlineReasons(perNodeSections, offline));

      const sources: Record<string, () => Promise<unknown>> = {};
      for (const node of online) {
        const pathParams = { node };
        sources[`node_status/${node}`] = () => ctx.api.get('/nodes/{node}/status', { pathParams });
        sources[`storage/${node}`] = () => ctx.api.get('/nodes/{node}/storage', { pathParams });
        sources[`services/${node}`] = () => ctx.api.get('/nodes/{node}/services', { pathParams });
        sources[`replication/${node}`] = () => ctx.api.get('/nodes/{node}/replication', { pathParams });
        sources[`subscription/${node}`] = () => ctx.api.get('/nodes/{node}/subscription', { pathParams });
      }
      const perNode = await gather(sources);
      report.absorb(perNode);

      const storageByNode = new Map<string, Row[]>();
      for (const node of online) {
        const rootfs = perNode.data[`node_status/${node}`];
        if (isObject(rootfs) && isObject(rootfs.rootfs)) {
          const used = fraction(rootfs.rootfs.used, rootfs.rootfs.total);
          const usedPercent = used === undefined ? undefined : round(used * 100);
          if (usedPercent !== undefined && usedPercent >= thresholds.storage_warn_percent) {
            const critical = usedPercent >= thresholds.storage_critical_percent;
            report.add(critical ? 'critical' : 'warning', 'node_status', `node ${node} root disk`, { used_percent: usedPercent, used_bytes: rootfs.rootfs.used, total_bytes: rootfs.rootfs.total, threshold_percent: critical ? thresholds.storage_critical_percent : thresholds.storage_warn_percent }, 'A full root disk stops the cluster filesystem and logging on this node. Free space there.');
          }
        }
        const storage = perNode.data[`storage/${node}`];
        if (storage !== undefined) storageByNode.set(node, rowsOf(storage));

        for (const service of rowsOf(perNode.data[`services/${node}`])) {
          if (service['active-state'] === 'failed' || service.state === 'failed') {
            const name = String(service.service ?? service.name);
            report.add(CORE_SERVICES.has(name) ? 'critical' : 'warning', 'services', `service ${name} on ${node}`, { 'active-state': service['active-state'], state: service.state, 'unit-state': service['unit-state'] }, 'Read why with pve_get_node_journal, then restart it with pve_restart_node_service.');
          }
        }

        // The schema only documents the id here: fail_count and error are what the state file holds.
        for (const job of rowsOf(perNode.data[`replication/${node}`])) {
          const failures = num(job.fail_count) ?? 0;
          if (failures > 0 || str(job.error)) {
            report.add('warning', 'replication', `replication job ${String(job.id)}`, { node, guest: job.guest, target: job.target, fail_count: failures, error: job.error, last_sync: isoTime(job.last_sync) }, 'Read pve_get_node_replication_log for this job. Until it works, the guest has no recent copy on the target.');
          }
        }

        const subscription = perNode.data[`subscription/${node}`];
        if (isObject(subscription)) {
          const status = String(subscription.status ?? 'unknown').toLowerCase();
          const evidence = { status, level: subscription.level, message: subscription.message, nextduedate: subscription.nextduedate };
          if (status === 'notfound' || status === 'new') report.add('info', 'subscription', `node ${node}`, evidence, 'No active subscription: only an issue if this cluster should use the enterprise repository or support.');
          else if (status !== 'active') report.add('warning', 'subscription', `node ${node}`, evidence, 'Renew or check the subscription key of this node.');
        }
      }
      checkNodeStorage(report, storageByNode, thresholds.storage_warn_percent, thresholds.storage_critical_percent);

      const body = report.summary(HEALTH_SEVERITIES);
      const overall = report.count('critical') > 0 ? 'critical' : report.count('warning') > 0 ? 'warning' : body.complete ? 'no_findings' : 'incomplete';
      return {
        overall,
        ...body,
        ...(Object.keys(notApplicable).length > 0 ? { not_applicable: notApplicable } : {}),
        thresholds,
        note: 'These are the checks listed under checked, on the data this token may read. No finding in one of them does not prove that all is well, and unavailable sections say nothing at all.',
      };
    },
  });
}

/* ------------------------------------------------------------------ security audit */

const AUDIT_SEVERITIES: readonly AuditSeverity[] = ['high', 'medium', 'low', 'info'];

function nicsWithFirewall(config: Row): { nics: number; withFirewall: number } {
  const nics = Object.entries(config).filter(([k, v]) => /^net\d+$/.test(k) && typeof v === 'string');
  return { nics: nics.length, withFirewall: nics.filter(([, v]) => /(^|,)firewall=1(,|$)/.test(v as string)).length };
}

function auditTokens(report: Report<AuditSeverity>, users: Row[]): void {
  const noExpiry: string[] = [];
  const noPrivsep: string[] = [];
  for (const user of users) {
    for (const token of rowsOf(user.tokens)) {
      const id = `${String(user.userid)}!${String(token.tokenid)}`;
      // Left out, a token expires with its user.
      const expire = num(token.expire) ?? num(user.expire) ?? 0;
      if (expire === 0) noExpiry.push(id);
      if (flag(token.privsep) === false) noPrivsep.push(id);
    }
  }
  if (noExpiry.length > 0) report.add('low', 'tokens', 'api tokens', { without_expiry: noExpiry }, 'Set an expiry on tokens that do not need to live forever: pve_update_user_token.');
  if (noPrivsep.length > 0) {
    const root = noPrivsep.some((id) => id.startsWith('root@pam!'));
    report.add(root ? 'high' : 'medium', 'tokens', 'api tokens', { without_privilege_separation: noPrivsep }, 'These tokens hold all the rights of their user. Prefer privsep=1 with an ACL for only what the token needs.');
  }
}

function auditRootTfa(report: Report<AuditSeverity>, entries: unknown): void {
  const rows = rowsOf(entries);
  const usable = rows.filter((e) => SECOND_FACTORS.has(String(e.type)) && flag(e.enable) !== false);
  if (usable.length > 0) return;
  report.add('high', 'root_tfa', 'root@pam', { entries: rows.map((e) => ({ type: e.type, enable: e.enable ?? 1 })) }, 'root@pam has no enabled second factor (recovery keys do not count). Add one in the web interface: the API refuses this to tokens.');
}

function auditAcl(report: Report<AuditSeverity>, acl: Row[]): void {
  for (const entry of acl) {
    if (entry.path !== '/' || !POWERFUL_ROLES.has(String(entry.roleid))) continue;
    report.add(entry.roleid === 'Administrator' ? 'high' : 'medium', 'acl', `${String(entry.type)} ${String(entry.ugid)}`, { path: entry.path, roleid: entry.roleid, propagate: flag(entry.propagate) ?? true }, 'Confirm that this account needs this much on the whole cluster. Otherwise grant a narrower role on a narrower path with pve_update_acl.');
  }
}

function auditCertificates(report: Report<AuditSeverity>, node: string, certs: Row[], warnDays: number): void {
  const now = nowSeconds();
  for (const cert of certs) {
    const after = num(cert.notafter);
    if (after === undefined) continue;
    const daysLeft = Math.floor((after - now) / DAY_SECONDS);
    if (daysLeft > warnDays) continue;
    const object = `certificate ${String(cert.filename ?? cert.fingerprint ?? 'unnamed')} on ${node}`;
    report.add(daysLeft < 0 ? 'high' : 'medium', 'certificates', object, { not_after: isoTime(after), days_left: daysLeft, subject: cert.subject, threshold_days: warnDays }, 'Renew it, with ACME (pve_renew_node_acme_certificate) or by hand, before clients start refusing it.');
  }
}

function securityAuditTool(): ToolDef {
  return tool({
    name: 'pve_security_audit',
    title: 'Security audit',
    description:
      'Reads the security-related settings: firewall state (cluster, nodes, guests), privileged containers, API tokens without expiry or privilege separation, second factor on root@pam, powerful ACLs on /, backups, pending updates, certificate expiry. Findings state what the data shows, with evidence and a suggested action. Sections it could not read are named in "unavailable". This is neither a certification nor a statement of compliance, and only sees what this token may read.',
    domain: 'workflows',
    also: ['access', 'firewall'],
    gate: 'read',
    idempotent: true,
    input: {
      cert_warn_days: z.number().int().min(0).max(3650).optional().describe(`Days before expiry from which a certificate is a finding. Default ${DEFAULT_CERT_WARN_DAYS}.`),
      include_guests: z.boolean().optional().describe('Also read the config and firewall options of each guest. Two requests per guest. Default true.'),
    },
    handler: async (args, ctx) => {
      const certWarnDays = args.cert_warn_days ?? DEFAULT_CERT_WARN_DAYS;
      const report = new Report<AuditSeverity>();
      const top = await gather({
        cluster_firewall: () => ctx.api.get('/cluster/firewall/options'),
        tokens: () => ctx.api.get('/access/users', { params: { full: 1 } }),
        root_tfa: () => ctx.api.get('/access/tfa/{userid}', { pathParams: { userid: 'root@pam' } }),
        acl: () => ctx.api.get('/access/acl'),
        not_backed_up: () => ctx.api.get('/cluster/backup-info/not-backed-up'),
        backup_jobs: () => ctx.api.get('/cluster/backup'),
        node_list: () => ctx.api.get('/nodes'),
        guests: () => ctx.api.get('/cluster/resources', { params: { type: 'vm' } }),
      });
      report.absorb(top);

      if (isObject(top.data.cluster_firewall) && flag(top.data.cluster_firewall.enable) !== true) {
        report.add('medium', 'cluster_firewall', 'datacenter firewall', { enable: top.data.cluster_firewall.enable ?? 0 }, 'The firewall is off for the whole cluster, so no rule of any node or guest applies. Review the rules first, as enabling it can cut access: pve_update_cluster_firewall_options.');
      }
      if (top.data.tokens !== undefined) auditTokens(report, rowsOf(top.data.tokens));
      if (top.data.root_tfa !== undefined) auditRootTfa(report, top.data.root_tfa);
      if (top.data.acl !== undefined) auditAcl(report, rowsOf(top.data.acl));
      if (top.data.not_backed_up !== undefined) {
        const missing = rowsOf(top.data.not_backed_up);
        if (missing.length > 0) report.add('medium', 'not_backed_up', 'guests', { count: missing.length, guests: missing.slice(0, MAX_LISTED).map((g) => ({ vmid: g.vmid, name: g.name, type: g.type })) }, 'These guests are in no backup job. See pve_backup_coverage.');
      }
      if (top.data.backup_jobs !== undefined) {
        const jobs = rowsOf(top.data.backup_jobs);
        if (!jobs.some((j) => flag(j.enabled) !== false)) report.add('medium', 'backup_jobs', 'backup jobs', { jobs: jobs.length, enabled: 0 }, 'No enabled backup job. Create one with pve_create_backup_job.');
      }

      const { online, offline } = nodeNames(rowsOf(top.data.node_list), []);
      const perNodeSections = ['node_firewall', 'updates', 'certificates'];
      if (online.length === 0 && offline.length === 0) {
        for (const section of perNodeSections) report.unavailable[section] = 'not checked: no node list could be read.';
      }
      Object.assign(report.unavailable, offlineReasons(perNodeSections, offline));
      const offlineSet = new Set(offline);
      const guests = args.include_guests === false ? [] : guestsOf(rowsOf(top.data.guests)).filter((g) => flag(g.template) !== true);
      const sources: Record<string, () => Promise<unknown>> = {};
      for (const node of online) {
        const pathParams = { node };
        sources[`node_firewall/${node}`] = () => ctx.api.get('/nodes/{node}/firewall/options', { pathParams });
        sources[`updates/${node}`] = () => ctx.api.get('/nodes/{node}/apt/update', { pathParams });
        sources[`certificates/${node}`] = () => ctx.api.get('/nodes/{node}/certificates/info', { pathParams });
      }
      if (args.include_guests !== false && top.data.guests === undefined) {
        report.unavailable.guest_config = 'not checked: the guest list could not be read.';
        report.unavailable.guest_firewall = 'not checked: the guest list could not be read.';
      }
      for (const row of guests) {
        const guest = locationOf(row);
        if (offlineSet.has(guest.node)) {
          report.unavailable[`guest_config/${guest.vmid}`] = `not checked: node ${guest.node} is offline.`;
          report.unavailable[`guest_firewall/${guest.vmid}`] = `not checked: node ${guest.node} is offline.`;
          continue;
        }
        sources[`guest_config/${guest.vmid}`] = () => ctx.api.get(guestPath(guest, '/config'), guestParams(guest));
        sources[`guest_firewall/${guest.vmid}`] = () => ctx.api.get(guestPath(guest, '/firewall/options'), guestParams(guest));
      }
      const details = await gather(sources);
      report.absorb(details);

      for (const node of online) {
        const firewall = details.data[`node_firewall/${node}`];
        // Host rules default to on here, unlike the cluster and guest switches.
        if (isObject(firewall) && flag(firewall.enable) === false) {
          report.add('low', 'node_firewall', `node ${node}`, { enable: firewall.enable }, 'Host firewall rules are off on this node. Check that this is intended: pve_update_node_firewall_options.');
        }
        const updates = details.data[`updates/${node}`];
        if (updates !== undefined && rowsOf(updates).length > 0) {
          const rows = rowsOf(updates);
          report.add('low', 'updates', `node ${node}`, { pending: rows.length, from_proxmox: rows.filter((r) => r.Origin === 'Proxmox').length, sample: rows.slice(0, 10).map((r) => `${String(r.Package)} ${String(r.OldVersion ?? '?')} -> ${String(r.Version)}`) }, 'Plan the upgrade. The list is from the last package index refresh: pve_refresh_apt_index renews it.');
        }
        const certs = details.data[`certificates/${node}`];
        if (certs !== undefined) auditCertificates(report, node, rowsOf(certs), certWarnDays);
      }

      const privileged: Row[] = [];
      const firewallOff: Row[] = [];
      const firewallNotOnNics: Row[] = [];
      for (const row of guests) {
        const guest = locationOf(row);
        const label = { vmid: guest.vmid, name: row.name, type: guest.type, node: guest.node };
        const config = details.data[`guest_config/${guest.vmid}`];
        const options = details.data[`guest_firewall/${guest.vmid}`];
        if (guest.type === 'lxc' && isObject(config) && flag(config.unprivileged) !== true) privileged.push(label);
        if (!isObject(options)) continue;
        // Off by default, on guests.
        if (flag(options.enable) !== true) firewallOff.push(label);
        else if (isObject(config)) {
          const { nics, withFirewall } = nicsWithFirewall(config);
          if (nics > 0 && withFirewall === 0) firewallNotOnNics.push({ ...label, nics });
        }
      }
      if (privileged.length > 0) {
        report.add('medium', 'guest_config', 'privileged containers', { count: privileged.length, guests: privileged.slice(0, MAX_LISTED) }, 'Root in a privileged container is much closer to root on the node. Move them to unprivileged containers where possible.');
      }
      if (firewallOff.length > 0) {
        report.add('low', 'guest_firewall', 'guests with the firewall off', { count: firewallOff.length, guests: firewallOff.slice(0, MAX_LISTED) }, 'Rules defined for these guests do not apply. Enable with pve_update_vm_firewall_options or pve_update_lxc_firewall_options where traffic should be filtered.');
      }
      if (firewallNotOnNics.length > 0) {
        report.add('low', 'guest_firewall', 'guests with the firewall on but on no interface', { count: firewallNotOnNics.length, guests: firewallNotOnNics.slice(0, MAX_LISTED) }, 'The guest firewall is enabled, but no net interface has firewall=1, so no traffic goes through it. Set it in the interface config.');
      }

      return {
        ...report.summary(AUDIT_SEVERITIES),
        thresholds: { cert_warn_days: certWarnDays, powerful_roles: [...POWERFUL_ROLES] },
        limits: [
          'Users, tokens and second factors are limited to the accounts this token is allowed to see, and ACL entries to the objects whose permissions it may modify: an empty list does not prove there are none.',
          'Pending updates come from the last refresh of the package index.',
          'A second factor enforced at realm level is not looked at.',
          ...(args.include_guests === false ? ['Guest config and firewall were not read, since include_guests is false.'] : []),
        ],
        disclaimer: 'This reports what the data shows on the checks listed. It is not a certification nor a statement of compliance, and no finding does not mean secure.',
      };
    },
  });
}

/* ------------------------------------------------------------------ backups */

function backupCoverageTool(): ToolDef {
  return tool({
    name: 'pve_backup_coverage',
    title: 'Backup coverage',
    description:
      'For each guest: whether it is in a backup job, and the age of its last backup found on the backup storages. Also the jobs and the guests that no job covers. A storage or node that could not be read is named in "unavailable", and a guest whose last backup could therefore be missed is listed under not_determined instead of being called unprotected. Having a backup says nothing of whether it restores.',
    domain: 'workflows',
    also: ['backup'],
    gate: 'read',
    idempotent: true,
    input: {
      max_age_days: z.number().min(0).max(36500).optional().describe(`A last backup older than this is a finding. Default ${DEFAULT_BACKUP_MAX_AGE_DAYS}.`),
      ...paging,
    },
    handler: async (args, ctx) => {
      const maxAgeDays = args.max_age_days ?? DEFAULT_BACKUP_MAX_AGE_DAYS;
      const report = new Report<AuditSeverity>();
      const top = await gather({
        not_backed_up: () => ctx.api.get('/cluster/backup-info/not-backed-up'),
        jobs: () => ctx.api.get('/cluster/backup'),
        guests: () => ctx.api.get('/cluster/resources', { params: { type: 'vm' } }),
        node_list: () => ctx.api.get('/nodes'),
      });
      report.absorb(top);

      const { online, offline } = nodeNames(rowsOf(top.data.node_list), []);
      if (online.length === 0 && offline.length === 0) report.unavailable.backups = 'not checked: no node list could be read.';
      Object.assign(report.unavailable, offlineReasons(['backups'], offline));

      const listed = await gather(Object.fromEntries(online.map((node) => [`storages/${node}`, () => ctx.api.get('/nodes/{node}/storage', { pathParams: { node }, params: { content: 'backup' } })])));
      report.absorb(listed);

      // A shared storage holds the same backups from every node: it is listed once.
      const places: Array<{ node: string; storage: string }> = [];
      const seenShared = new Set<string>();
      for (const node of online) {
        for (const row of rowsOf(listed.data[`storages/${node}`])) {
          const storage = String(row.storage);
          if (flag(row.enabled) === false) continue;
          if (row.content !== undefined && !String(row.content).split(',').includes('backup')) continue;
          if (flag(row.active) === false) {
            report.unavailable[`backups/${storage}@${node}`] = 'not read: the storage is not active.';
            continue;
          }
          if (flag(row.shared) === true) {
            if (seenShared.has(storage)) continue;
            seenShared.add(storage);
          }
          places.push({ node, storage });
        }
      }
      const contents = await gather(
        Object.fromEntries(places.map(({ node, storage }) => [`backups/${storage}@${node}`, () => ctx.api.get('/nodes/{node}/storage/{storage}/content', { pathParams: { node, storage }, params: { content: 'backup' } })])),
      );
      report.absorb(contents);

      const last = new Map<number, { ctime: number; volid: unknown; storage: string; count: number; verification: unknown }>();
      for (const [key, value] of Object.entries(contents.data)) {
        const storage = key.slice('backups/'.length, key.lastIndexOf('@'));
        for (const volume of rowsOf(value)) {
          if (volume.content !== undefined && volume.content !== 'backup') continue;
          const id = num(volume.vmid);
          if (id === undefined) continue;
          const ctime = num(volume.ctime) ?? 0;
          const known = last.get(id);
          if (!known || ctime > known.ctime) last.set(id, { ctime, volid: volume.volid, storage, count: (known?.count ?? 0) + 1, verification: isObject(volume.verification) ? volume.verification.state : undefined });
          else known.count++;
        }
      }

      const jobless = top.data.not_backed_up === undefined ? undefined : new Set(rowsOf(top.data.not_backed_up).map((g) => num(g.vmid)));
      const storagesComplete = !Object.keys(report.unavailable).some((k) => k.startsWith('backups') || k.startsWith('storages'));
      const now = nowSeconds();
      const stale: Row[] = [];
      const none: Row[] = [];
      const notDetermined: Row[] = [];
      const guests = guestsOf(rowsOf(top.data.guests));
      const rows = guests
        .sort((a, b) => num(a.vmid)! - num(b.vmid)!)
        .map((g) => {
          const id = num(g.vmid)!;
          const backup = last.get(id);
          // Without a date there is no age to judge, only a backup that exists.
          const ageDays = backup && backup.ctime > 0 ? round((now - backup.ctime) / DAY_SECONDS) : null;
          const tooOld = ageDays !== null && ageDays > maxAgeDays;
          const label = { vmid: id, name: g.name, type: g.type, node: g.node };
          // A template does not change, so an old backup of it says nothing: it is listed, not judged.
          if (flag(g.template) !== true) {
            if (backup && tooOld && storagesComplete) stale.push({ ...label, age_days: ageDays, last_backup: isoTime(backup.ctime) });
            else if (backup && tooOld) notDetermined.push({ ...label, reason: 'The newest backup found is old, and a newer one may be on a storage that could not be read.' });
            else if (!backup && storagesComplete) none.push(label);
            else if (!backup) notDetermined.push({ ...label, reason: 'No backup found, but some storages could not be read.' });
          }
          return {
            ...label,
            status: g.status,
            ...(flag(g.template) === true ? { template: true } : {}),
            in_backup_job: jobless ? !jobless.has(id) : null,
            last_backup: backup && backup.ctime > 0 ? isoTime(backup.ctime) : null,
            age_days: ageDays,
            ...(backup ? { storage: backup.storage, volid: backup.volid, backups_found: backup.count, ...(backup.verification ? { verification: backup.verification } : {}) } : {}),
          };
        });

      if (jobless && jobless.size > 0) {
        report.add('medium', 'not_backed_up', 'guests in no backup job', { count: jobless.size, guests: rowsOf(top.data.not_backed_up).slice(0, MAX_LISTED).map((g) => ({ vmid: g.vmid, name: g.name, type: g.type })) }, 'Add them to a job, or exclude them knowingly: pve_create_backup_job, pve_update_backup_job.');
      }
      if (none.length > 0) report.add('medium', 'backups', 'guests without any backup found', { count: none.length, guests: none.slice(0, MAX_LISTED) }, 'Check that they are meant to be backed up, and pve_run_backup for a first one.');
      if (stale.length > 0) report.add('low', 'backups', 'guests whose last backup is old', { threshold_days: maxAgeDays, count: stale.length, guests: stale.slice(0, MAX_LISTED) }, 'Check the job that should cover them and the logs of its last run.');
      if (top.data.jobs !== undefined && !rowsOf(top.data.jobs).some((j) => flag(j.enabled) !== false)) {
        report.add('medium', 'jobs', 'backup jobs', { jobs: rowsOf(top.data.jobs).length, enabled: 0 }, 'No enabled backup job. Create one with pve_create_backup_job.');
      }

      const summary = report.summary(AUDIT_SEVERITIES);
      return {
        ...summary,
        thresholds: { max_age_days: maxAgeDays },
        jobs:
          top.data.jobs === undefined
            ? null
            : rowsOf(top.data.jobs).map((j) => ({ id: j.id, enabled: flag(j.enabled) ?? true, schedule: j.schedule, storage: j.storage, all: flag(j.all) ?? false, vmid: j.vmid, pool: j.pool, exclude: j.exclude, node: j.node, next_run: isoTime(j['next-run']), mode: j.mode })),
        storages_read: places.filter(({ node, storage }) => contents.data[`backups/${storage}@${node}`] !== undefined).map(({ node, storage }) => `${storage}@${node}`),
        not_determined: notDetermined.slice(0, MAX_LISTED),
        ...pageRows(rows, args.page_limit, args.page_offset),
      };
    },
  });
}

/* ------------------------------------------------------------------ capacity */

const MIN_FORECAST_POINTS = 3;

/** Least squares on used bytes over time. A straight line through the past, and it says so. */
function forecastStorage(points: Row[], totalBytes: number | undefined, window: string): Record<string, unknown> {
  const clean = points.map((p) => ({ t: num(p.time), y: num(p.used) })).filter((p): p is { t: number; y: number } => p.t !== undefined && p.y !== undefined);
  if (clean.length < MIN_FORECAST_POINTS) return { available: false, reason: `Only ${clean.length} data points in the window: at least ${MIN_FORECAST_POINTS} are needed.` };
  const n = clean.length;
  const meanT = clean.reduce((s, p) => s + p.t, 0) / n;
  const meanY = clean.reduce((s, p) => s + p.y, 0) / n;
  const denominator = clean.reduce((s, p) => s + (p.t - meanT) ** 2, 0);
  if (denominator === 0) return { available: false, reason: 'All the data points have the same time.' };
  const slope = clean.reduce((s, p) => s + (p.t - meanT) * (p.y - meanY), 0) / denominator;
  const perDay = slope * DAY_SECONDS;
  const lastTotal = num(points.at(-1)?.total) ?? totalBytes;
  const latest = clean.at(-1)!.y;
  const base = { available: true, method: `linear least squares on RRD averages, last ${window}`, points: n, growth_bytes_per_day: Math.round(perDay) };
  if (perDay <= 0) return { ...base, days_until_full: null, trend: 'not_growing' };
  if (lastTotal === undefined || lastTotal <= 0) return { ...base, days_until_full: null, trend: 'growing', reason: 'The total size is not known.' };
  const days = Math.max(0, (lastTotal - latest) / perDay);
  return { ...base, days_until_full: round(days), trend: 'growing', assumption: 'Extrapolates past growth in a straight line: a rough idea, not a prediction.' };
}

function capacityTool(): ToolDef {
  return tool({
    name: 'pve_capacity_report',
    title: 'Capacity report',
    description:
      'CPU, memory and disk per node, what the guests are allocated against that (overcommit ratios), storage usage with a straight-line forecast from its history, and the biggest guests. Facts and ratios only: no threshold judges them. Sections that could not be read are in "unavailable".',
    domain: 'workflows',
    also: ['cluster', 'storage'],
    gate: 'read',
    idempotent: true,
    input: {
      forecast_window: z.enum(['day', 'week', 'month', 'year']).optional().describe('History the storage forecast is based on. Default month.'),
      forecast: z.boolean().optional().describe('Read the history of each storage for a forecast. One request per storage. Default true.'),
      top: z.number().int().min(1).max(100).optional().describe('How many guests in each list of the biggest. Default 5.'),
    },
    handler: async (args, ctx) => {
      const window = args.forecast_window ?? 'month';
      const top = args.top ?? 5;
      const { data, unavailable } = await gather({ resources: () => ctx.api.get('/cluster/resources') });
      if (data.resources === undefined) {
        return { complete: false, nodes: null, storage: null, biggest_guests: null, unavailable };
      }
      const resources = rowsOf(data.resources);
      const guests = guestsOf(resources).filter((g) => flag(g.template) !== true);

      const nodes = resources
        .filter((r) => r.type === 'node')
        .map((n) => {
          const here = guests.filter((g) => g.node === n.node);
          const running = here.filter((g) => g.status === 'running');
          const sum = (rows: Row[], key: string) => rows.reduce((total, g) => total + (num(g[key]) ?? 0), 0);
          const cores = num(n.maxcpu);
          const memory = num(n.maxmem);
          const ratio = (allocated: number, available: number | undefined) => (available !== undefined && available > 0 ? round(allocated / available, 2) : null);
          return {
            node: n.node,
            status: n.status,
            cores: cores ?? null,
            cpu_percent: percent(num(n.cpu)),
            memory_used_bytes: n.mem ?? null,
            memory_total_bytes: n.maxmem ?? null,
            memory_percent: percent(fraction(n.mem, n.maxmem)),
            root_disk_used_bytes: n.disk ?? null,
            root_disk_total_bytes: n.maxdisk ?? null,
            root_disk_percent: percent(fraction(n.disk, n.maxdisk)),
            guests: here.length,
            guests_running: running.length,
            vcpus_allocated: sum(here, 'maxcpu'),
            vcpus_running: sum(running, 'maxcpu'),
            memory_allocated_bytes: sum(here, 'maxmem'),
            memory_running_bytes: sum(running, 'maxmem'),
            // More than 1 means overcommitted, which is a choice rather than a fault.
            cpu_overcommit_ratio: ratio(sum(here, 'maxcpu'), cores),
            cpu_overcommit_ratio_running: ratio(sum(running, 'maxcpu'), cores),
            memory_overcommit_ratio: ratio(sum(here, 'maxmem'), memory),
            memory_overcommit_ratio_running: ratio(sum(running, 'maxmem'), memory),
          };
        });

      const storages = mergeShared(storagesOf(resources));
      const history = await gather(
        Object.fromEntries(
          args.forecast === false
            ? []
            : storages.filter(({ row }) => row.status !== 'unknown').map(({ row }) => [`forecast/${String(row.storage)}@${String(row.node)}`, () => ctx.api.get('/nodes/{node}/storage/{storage}/rrddata', { pathParams: { node: String(row.node), storage: String(row.storage) }, params: { timeframe: window, cf: 'AVERAGE' } })]),
        ),
      );
      Object.assign(unavailable, history.unavailable);
      const storage = storages.map(({ row, nodes: seenOn }) => {
        const key = `forecast/${String(row.storage)}@${String(row.node)}`;
        const total = num(row.maxdisk);
        return {
          storage: row.storage,
          type: row.plugintype,
          shared: flag(row.shared) === true,
          nodes: seenOn,
          status: row.status,
          used_bytes: row.disk ?? null,
          total_bytes: row.maxdisk ?? null,
          used_percent: percent(fraction(row.disk, row.maxdisk)),
          forecast: args.forecast === false ? null : history.data[key] !== undefined ? forecastStorage(rowsOf(history.data[key]), total, window) : { available: false, reason: history.unavailable[key] ?? 'The storage is in an unknown state.' },
        };
      });

      const biggest = (key: string) =>
        [...guests]
          .filter((g) => num(g[key]) !== undefined)
          .sort((a, b) => num(b[key])! - num(a[key])!)
          .slice(0, top)
          .map((g) => ({ vmid: g.vmid, name: g.name, type: g.type, node: g.node, status: g.status, [key]: g[key] }));

      return {
        complete: Object.keys(unavailable).length === 0,
        nodes,
        storage,
        biggest_guests: { by_memory: biggest('maxmem'), by_disk: biggest('maxdisk'), by_vcpus: biggest('maxcpu') },
        templates_excluded: guestsOf(resources).length - guests.length,
        note: 'Allocations count guests that are not templates. A token only sees what it has audit rights on, so totals may be partial.',
        unavailable,
      };
    },
  });
}

/** Composite tools. */
export function workflowTools(): ToolDef[] {
  return [
    overviewTool(),
    findGuestTool(),
    waitTaskTool(),
    taskLogTool(),
    guestPowerTool(),
    snapshotTool(),
    listSnapshotsTool(),
    provisionLxcTool(),
    provisionVmTool(),
    healthTool(),
    securityAuditTool(),
    backupCoverageTool(),
    capacityTool(),
  ];
}
