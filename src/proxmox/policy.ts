import { matchPath, type HttpMethod } from '../catalog/index.js';
import { ProxmoxError } from './errors.js';

/**
 * Access policy, enforced by the HTTP client so that no tool can get around it.
 *
 * Classification works on the catalog template when the path is known, and on the concrete
 * path otherwise, so that a route missing from the catalog can still hit a block rule.
 * An unknown path fails closed: a GET counts as sensitive, anything else as elevated.
 */
export type Gate = 'read' | 'sensitive' | 'write' | 'elevated' | 'guest_exec' | 'console' | 'blocked' | 'ssh_read' | 'ssh_write';

export interface Decision {
  gate: Gate;
  destructive: boolean;
  /** Absent when the path is not in the catalog. */
  template?: string;
  pathParams: Record<string, string>;
  reason?: string;
  /** Canonical path with decoded values, for logs. */
  path: string;
  /** The same path, percent-encoded segment by segment, ready to go after /api2/json. */
  urlPath: string;
  /** The answer's only purpose is a secret: it is kept when allowSensitive is on. */
  returnsSecret: boolean;
}

export interface PolicySubject {
  name: string;
  allowWrites: boolean;
  allowElevated: boolean;
  allowGuestExec: boolean;
  allowSensitive: boolean;
  allowSsh: boolean;
  dryRun: boolean;
}

export interface AuthorizeOptions {
  /** Set for tools announced as read-only: anything that changes state is refused. */
  readOnly?: boolean;
  /** Nothing will be sent, which is what opens the write gates on a read-only instance. */
  dryRun?: boolean;
  /** Fills {placeholders} in the path. Values may hold characters that a raw path may not. */
  pathParams?: Record<string, string | number>;
  /** What the call would send: a few arguments raise its gate, see hostAccessArg. */
  params?: Record<string, unknown>;
}

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Values that legitimately hold a slash once encoded (local:iso/x.iso, 10.0.0.0/24).
 * Anywhere else a slash is refused, whatever the upstream router does with %2F:
 * a node name must never be able to add path segments.
 */
const SLASH_ALLOWED = new Set(['volume', 'cidr', 'subnet']);

function invalidPath(path: string, why: string, hint?: string): ProxmoxError {
  return new ProxmoxError('invalid_path', `"${scrub(path)}" is not a valid API path: ${why}.`, hint ? { hint } : {});
}

function scrub(text: string): string {
  return text.replace(new RegExp(CONTROL_CHARS.source, 'g'), '?').slice(0, 300);
}

const RAW_PATH_HINT = 'Give the plain path, such as /nodes/pve/qemu/100/config, without encoding. For a value with special characters, use a {placeholder} in the path and pass the value in path_params: it is encoded for you.';

function assertRawSegment(path: string, segment: string): void {
  if (segment === '') throw invalidPath(path, 'empty segment (double or leading slash)');
  if (segment === '.' || segment === '..') throw invalidPath(path, 'dot segments are not allowed');
  if (CONTROL_CHARS.test(segment)) throw invalidPath(path, 'control characters are not allowed');
  if (/[?#\\{}]/.test(segment)) throw invalidPath(path, 'query strings, fragments, backslashes and braces are not allowed in a path', RAW_PATH_HINT);
  // All of it rather than %2f and friends: %74 for "t" would get "agent/exec" past the rules below.
  if (segment.includes('%')) throw invalidPath(path, 'percent-encoding is not allowed', RAW_PATH_HINT);
}

function assertValue(path: string, name: string, value: string): void {
  if (value === '') throw invalidPath(path, `path parameter "${name}" is empty`);
  if (value.length > 1024) throw invalidPath(path, `path parameter "${name}" is too long`);
  if (CONTROL_CHARS.test(value) || value.includes('\\')) throw invalidPath(path, `path parameter "${name}" holds control characters or a backslash`);
  const pieces = value.split('/');
  if (pieces.length > 1 && !SLASH_ALLOWED.has(name)) throw invalidPath(path, `path parameter "${name}" may not contain a slash`);
  if (pieces.some((p) => p === '.' || p === '..' || p === '')) throw invalidPath(path, `path parameter "${name}" holds a dot or empty segment`);
}

/** Splits a path into decoded segments, or refuses it. A trailing slash is dropped. */
export function normalizePath(path: string, values?: Record<string, string | number>): string[] {
  if (typeof path !== 'string' || !path.startsWith('/')) throw invalidPath(String(path), 'it must start with /');
  if (path.length > 4096) throw invalidPath(path, 'too long');
  const trimmed = path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
  if (trimmed === '/') return [];
  return trimmed
    .slice(1)
    .split('/')
    .map((segment) => {
      const name = /^\{([^{}/]+)\}$/.exec(segment)?.[1];
      if (name !== undefined && values) {
        const value = values[name];
        if (value === undefined || value === null) throw new ProxmoxError('invalid_input', `Missing value for path parameter "${name}" of ${scrub(path)}.`);
        const text = String(value);
        assertValue(path, name, text);
        return text;
      }
      assertRawSegment(path, segment);
      return segment;
    });
}

/** The characters left readable are the ones the Proxmox API itself shows in UPIDs and ids. */
export function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/%3A/g, ':').replace(/%40/g, '@').replace(/%2C/g, ',').replace(/%3D/g, '=');
}

const NODE = '/nodes/[^/]+';
const GUEST = `${NODE}/(?:qemu|lxc)/[^/]+`;
const QEMU = `${NODE}/qemu/[^/]+`;

function re(...patterns: string[]): RegExp {
  return new RegExp(`^(?:${patterns.join('|')})$`);
}

interface Rule {
  methods?: HttpMethod[];
  pattern: RegExp;
  reason?: string;
}

const BLOCKED: Rule[] = [
  { pattern: re(`${NODE}/execute`), reason: 'It runs a batch of API calls on the node, which would bypass this policy.' },
  { pattern: re(`${GUEST}/vncwebsocket`, `${NODE}/vncwebsocket`), reason: 'A websocket console cannot be driven by a tool call.' },
  { pattern: re(`${GUEST}/mtunnelwebsocket`, `${GUEST}/mtunnel`), reason: 'Migration tunnels are internal to remote_migrate.' },
  { pattern: re('/access/ticket'), reason: 'This server handles authentication itself.' },
  { methods: ['POST'], pattern: re('/access/openid/login'), reason: 'OpenID login is an interactive browser flow.' },
];

const CONSOLE = re(`${GUEST}/(?:vncproxy|termproxy|spiceproxy)`, `${NODE}/(?:vncshell|termproxy|spiceshell)`, '/access/vncticket');

const GUEST_EXEC: Rule[] = [
  { methods: ['POST'], pattern: re(`${QEMU}/agent`, `${QEMU}/agent/(?:exec|file-write|set-user-password)`, `${QEMU}/monitor`) },
  { methods: ['GET'], pattern: re(`${QEMU}/agent/exec-status`) },
  // Typing on the console of a logged-in guest is running commands in it.
  { methods: ['PUT'], pattern: re(`${QEMU}/sendkey`) },
];

const SENSITIVE_GET = re(
  '/cluster/metrics/export',
  '/cluster/config/join',
  `${QEMU}/agent/file-read`,
  `${QEMU}/cloudinit/dump`,
  `${NODE}/vzdump/extractconfig`,
  `${NODE}/storage/[^/]+/file-restore/download`,
  // Not a plain read: it starts a restore VM on the node, and shows what is inside a backup.
  `${NODE}/storage/[^/]+/file-restore/list`,
  `${NODE}/report`,
  '/cluster/acme/plugins(?:/.*)?',
  `${NODE}/ceph/cfg/(?:raw|db|value)`,
  // These make the node connect to a host of the caller's choice, some with credentials:
  // a read tool must not be a way to probe the network behind the hypervisor.
  `${NODE}/scan/(?:cifs|iscsi|nfs|pbs)`,
  `${NODE}/query-url-metadata`,
  `${NODE}/query-oci-repo-tags`,
  '/cluster/acme/(?:meta|tos)',
);

const ELEVATED_WRITE = re(
  '/access(?:/.*)?',
  '/storage(?:/.*)?',
  '/cluster/config(?:/.*)?',
  '/cluster/options',
  '/cluster/ceph(?:/.*)?',
  `${NODE}/ceph(?:/.*)?`,
  '/cluster/acme(?:/.*)?',
  `${NODE}/certificates(?:/.*)?`,
  '/cluster/sdn(?:/.*)?',
  `${NODE}/sdn(?:/.*)?`,
  '/cluster/firewall(?:/.*)?',
  `${NODE}/firewall(?:/.*)?`,
  '/cluster/bulk-action(?:/.*)?',
  // Rewrites users and ACLs on a schedule, so it is /access by another path.
  '/cluster/jobs/realm-sync(?:/.*)?',
  // Releases the watchdogs of the whole cluster.
  '/cluster/ha/status/(?:arm-ha|disarm-ha)',
  // Exposes host devices and directories to guests.
  '/cluster/mapping(?:/.*)?',
  // Hold credentials, and send cluster data to a host of the caller's choice.
  '/cluster/metrics/server(?:/.*)?',
  '/cluster/notifications(?:/.*)?',
  // Shared by every VM that uses the model.
  '/cluster/qemu/custom-cpu-models(?:/.*)?',
  `${NODE}/status`,
  `${NODE}/(?:startall|stopall|suspendall|migrateall|wakeonlan)`,
  `${NODE}/apt(?:/.*)?`,
  `${NODE}/network(?:/.*)?`,
  `${NODE}/(?:dns|hosts|time|config)`,
  `${NODE}/services(?:/.*)?`,
  `${NODE}/subscription`,
  `${NODE}/disks(?:/.*)?`,
  `${GUEST}/remote_migrate`,
);

const DESTRUCTIVE_WRITE: Rule[] = [
  {
    pattern: re(
      `${GUEST}/status/(?:stop|reset|shutdown|reboot|suspend)`,
      `${GUEST}/snapshot/[^/]+/rollback`,
      `${GUEST}/template`,
      `${NODE}/status`,
      `${NODE}/(?:stopall|suspendall|migrateall)`,
      `${NODE}/disks/(?:wipedisk|initgpt)`,
      '/cluster/bulk-action/guest/(?:shutdown|suspend|migrate)',
      // The guest stops or freezes, or runs what it is told, and no one can tell what that does.
      `${QEMU}/agent/(?:shutdown|suspend-disk|suspend-hybrid|suspend-ram|fsfreeze-freeze|exec|file-write|set-user-password)`,
      `${QEMU}/agent`,
      `${QEMU}/monitor`,
      `${QEMU}/sendkey`,
      // Removes the disk images it names.
      `${QEMU}/unlink`,
      // Cuts a service that guests or the API depend on.
      `${NODE}/services/[^/]+/(?:stop|restart)`,
      `${NODE}/ceph/(?:stop|restart|restart-bulk)`,
      '/cluster/ceph/restart-bulk',
      `${NODE}/ceph/osd/[^/]+/out`,
      // Reloads the network of every node, or throws the pending changes away.
      '/cluster/sdn',
      '/cluster/sdn/rollback',
      '/cluster/ha/status/disarm-ha',
      // Stops the guest and starts it again on the other node.
      '/cluster/ha/resources/[^/]+/relocate',
      // Membership: a joining node loses its own configuration, and quorum can be lost.
      '/cluster/config',
      '/cluster/config/join',
      '/cluster/config/nodes/[^/]+',
      // Replaces the whole file: a wrong one takes the node out of the cluster.
      `${NODE}/hosts`,
      '/access/password',
    ),
  },
  // Only the reload: POST on this path adds an interface, which stays pending until then.
  { methods: ['PUT'], pattern: re(`${NODE}/network`) },
  // POST formats the disk it is given. GET lists, which is excluded anyway.
  { methods: ['POST'], pattern: re(`${NODE}/disks/(?:directory|lvm|lvmthin|zfs)`, `${NODE}/ceph/osd`) },
];

function truthy(v: unknown): boolean {
  return v === true || v === 1 || (typeof v === 'string' && /^(?:1|true|yes|on)$/i.test(v));
}

function given(v: unknown): boolean {
  return v !== undefined && v !== null && v !== '';
}

/**
 * The values of a numbered parameter, however it is spelled: hostpci0 on the API,
 * hostpci: {"0": "..."} or hostpci_n: {"0": "..."} as a tool argument.
 */
function indexedValues(args: Record<string, unknown>, base: string): unknown[] {
  const out: unknown[] = [];
  for (const [key, value] of Object.entries(args)) {
    if (key === base || key === `${base}_n`) {
      if (value && typeof value === 'object') out.push(...Object.values(value));
    } else if (key.startsWith(base) && /^\d+$/.test(key.slice(base.length))) {
      out.push(value);
    }
  }
  return out.filter(given);
}

const VM_CONFIG = re(`${NODE}/qemu`, `${QEMU}/config`);
const CT_CONFIG = re(`${NODE}/lxc`, `${NODE}/lxc/[^/]+/config`);
const CT_CREATE = re(`${NODE}/lxc`);
const BACKUP_RUN = re(`${NODE}/vzdump`, '/cluster/backup', '/cluster/backup/[^/]+');
/** A mount point on a path of the host rather than on a volume: /srv/x,mp=/mnt or volume=/srv/x. */
const BIND_SOURCE = /^(?:volume=)?\/|,volume=\//;

const HOST_ACCESS: Array<{ pattern: RegExp; params: readonly string[] }> = [
  { pattern: VM_CONFIG, params: ['hookscript', 'args', 'hostpci[n]', 'parallel[n]', 'usb[n]', 'serial[n]'] },
  { pattern: CT_CONFIG, params: ['hookscript', 'dev[n]', 'mp[n]', 'rootfs', 'unprivileged'] },
  { pattern: BACKUP_RUN, params: ['script', 'dumpdir', 'tmpdir'] },
];

/** The parameters of this endpoint that hostAccessArg looks at, for a tool to announce them. */
export function hostAccessParams(endpointParams: Record<string, unknown>, method: string, template: string): string[] {
  if (method !== 'POST' && method !== 'PUT') return [];
  return (HOST_ACCESS.find((h) => h.pattern.test(template))?.params ?? []).filter((p) => p in endpointParams);
}

/**
 * Arguments that reach the hypervisor itself: a hook script runs as root on the node, and kvm
 * arguments, host devices and bind mounts all get past the walls of the guest. On a tool of gate
 * write they need PROXMOX_ALLOW_ELEVATED; the rest of the call stays what it is.
 * Returns the name of the first one found.
 */
export function hostAccessArg(method: string, template: string | undefined, args: Record<string, unknown> | undefined): string | undefined {
  if ((method !== 'POST' && method !== 'PUT') || !template || !args) return undefined;
  if (VM_CONFIG.test(template)) {
    if (given(args.hookscript)) return 'hookscript';
    if (given(args.args)) return 'args';
    if (indexedValues(args, 'hostpci').length > 0) return 'hostpci';
    if (indexedValues(args, 'parallel').length > 0) return 'parallel';
    // These two also name harmless things: usb0=spice, serial0=socket.
    if (indexedValues(args, 'usb').some((v) => /(?:^|,)host=/.test(String(v)))) return 'usb';
    if (indexedValues(args, 'serial').some((v) => String(v) !== 'socket')) return 'serial';
    return undefined;
  }
  if (CT_CONFIG.test(template)) {
    if (given(args.hookscript)) return 'hookscript';
    if (indexedValues(args, 'dev').length > 0) return 'dev';
    if (indexedValues(args, 'mp').some((v) => BIND_SOURCE.test(String(v)))) return 'mp';
    if (typeof args.rootfs === 'string' && BIND_SOURCE.test(args.rootfs)) return 'rootfs';
    // Root inside a privileged container is root on the node, as far as the kernel can tell. Proxmox
    // creates one when the argument is left out, and a restore takes it from the backup.
    if (method === 'POST' && CT_CREATE.test(template) ? !truthy(args.unprivileged) : given(args.unprivileged) && !truthy(args.unprivileged)) return 'unprivileged';
    return undefined;
  }
  if (BACKUP_RUN.test(template)) {
    for (const name of ['script', 'dumpdir', 'tmpdir']) if (given(args[name])) return name;
  }
  return undefined;
}

/** What a refusal says about an argument hostAccessArg found. */
export function describeHostAccess(what: string, arg: string): string {
  return arg === 'unprivileged' ? `${what} without unprivileged=1 (a privileged container)` : `${what} with "${arg}"`;
}

interface ArgRule {
  methods?: HttpMethod[];
  pattern: RegExp;
  /** Parameters of the endpoint that can trigger the rule: having one is what makes a tool check. */
  params: readonly string[];
  when: (args: Record<string, unknown>, method: string, template: string) => boolean;
}

const GUEST_CONFIG = re(`${QEMU}/config`, `${NODE}/lxc/[^/]+/config`);

/** Arguments that turn an ordinary call into a destructive one. They read tool arguments and API parameters alike. */
const DESTRUCTIVE_ARGS: ArgRule[] = [
  { pattern: /./, params: ['purge'], when: (a) => truthy(a.purge) },
  // Created with force, a guest replaces the one that had this vmid.
  { methods: ['POST'], pattern: re(`${NODE}/(?:qemu|lxc)`), params: ['force'], when: (a) => truthy(a.force) },
  // unused[n] is a real volume: taking it out of the configuration takes it off the storage.
  { pattern: GUEST_CONFIG, params: ['delete', 'force'], when: (a) => truthy(a.force) || /(?:^|[,;\s])unused\d/.test(String(a.delete ?? '')) },
  { pattern: re(`${QEMU}/move_disk`, `${NODE}/lxc/[^/]+/move_volume`, `${GUEST}/remote_migrate`), params: ['delete'], when: (a) => truthy(a.delete) },
  { pattern: re(`${NODE}/lxc/[^/]+/(?:migrate|remote_migrate)`), params: ['restart'], when: (a) => truthy(a.restart) },
  // The old secret stops working at once.
  { methods: ['PUT'], pattern: re('/access/users/[^/]+/token/[^/]+'), params: ['regenerate'], when: (a) => truthy(a.regenerate) },
  { pattern: re('/access/acl'), params: ['delete'], when: (a) => truthy(a.delete) },
  // Takes users, groups or ACLs away, unless it is only the preview.
  {
    pattern: re('/access/domains/[^/]+/sync', '/cluster/jobs/realm-sync/[^/]+'),
    params: ['remove-vanished', 'full'],
    when: (a) => !truthy(a['dry-run']) && (truthy(a.full) || (given(a['remove-vanished']) && a['remove-vanished'] !== 'none')),
  },
  { pattern: re('/cluster/ha/resources', '/cluster/ha/resources/[^/]+'), params: ['state'], when: (a) => a.state === 'stopped' || a.state === 'disabled' },
  // Also removes the replicated volumes on the target.
  { pattern: re('/cluster/replication', '/cluster/replication/[^/]+'), params: ['remove_job'], when: (a) => given(a.remove_job) },
  { pattern: re(`${NODE}/vzdump`), params: ['mode', 'stop'], when: (a) => a.mode === 'stop' || truthy(a.stop) },
  { pattern: re('/cluster/ceph/flags'), params: ['pause'], when: (a) => truthy(a.pause) },
  { pattern: re('/cluster/ceph/flags/[^/]+'), params: ['value'], when: (a) => a.flag === 'pause' && truthy(a.value) },
  { pattern: re(`${NODE}/certificates/custom`, `${NODE}/certificates/acme/certificate`), params: ['force'], when: (a) => truthy(a.force) },
  // Switched on with the wrong rules, this can cut the API off. Switched off, it opens everything.
  { pattern: re('/cluster/firewall/options', `${NODE}/firewall/options`), params: ['enable'], when: (a) => given(a.enable) },
  ...HOST_ACCESS.map(
    (h): ArgRule => ({
      pattern: h.pattern,
      params: h.params,
      when: (a, method, template) => hostAccessArg(method, template, a) !== undefined,
    }),
  ),
];

function argRulesFor(method: string, template: string): ArgRule[] {
  return DESTRUCTIVE_ARGS.filter((rule) => (!rule.methods || rule.methods.includes(method as HttpMethod)) && rule.pattern.test(template));
}

function firstRule(rules: Rule[], method: HttpMethod, subject: string): Rule | undefined {
  return rules.find((r) => (!r.methods || r.methods.includes(method)) && r.pattern.test(subject));
}

function assertMethod(method: string): asserts method is HttpMethod {
  if (method !== 'GET' && method !== 'POST' && method !== 'PUT' && method !== 'DELETE') {
    throw new ProxmoxError('invalid_input', `Unsupported HTTP method "${scrub(String(method))}": use GET, POST, PUT or DELETE.`);
  }
}

/** Secrets that a tool exists to hand over, as opposed to ones that travel with other data. */
const SECRET_ANSWERS = re('/access/users/[^/]+/token/[^/]+', '/access/tfa/[^/]+');

function classifySubject(method: HttpMethod, subject: string, known: boolean): { gate: Gate; reason?: string } {
  const blocked = firstRule(BLOCKED, method, subject);
  if (blocked) return { gate: 'blocked', reason: blocked.reason ?? 'Blocked by policy.' };
  if (CONSOLE.test(subject)) return { gate: 'console' };
  if (firstRule(GUEST_EXEC, method, subject)) return { gate: 'guest_exec' };
  if (!known) {
    return method === 'GET'
      ? { gate: 'sensitive', reason: 'This path is not in the API catalog, so its answer cannot be assumed to be harmless.' }
      : { gate: 'elevated', reason: 'This path is not in the API catalog, so it is treated as the most privileged kind of write.' };
  }
  if (method === 'GET') return SENSITIVE_GET.test(subject) ? { gate: 'sensitive' } : { gate: 'read' };
  return ELEVATED_WRITE.test(subject) ? { gate: 'elevated' } : { gate: 'write' };
}

/** Throws invalid_path on a path that cannot be trusted. */
export function classify(method: string, path: string, pathParams?: Record<string, string | number>): Decision {
  assertMethod(method);
  const segments = normalizePath(path, pathParams);
  const match = matchPath(segments);
  const known = match?.methods.has(method) ?? false;
  const subject = known ? match!.template : `/${segments.join('/')}`;
  const { gate, reason } = classifySubject(method, subject, known);
  return {
    gate,
    destructive: method === 'DELETE' || (method !== 'GET' && firstRule(DESTRUCTIVE_WRITE, method, subject) !== undefined),
    ...(known ? { template: match!.template } : {}),
    pathParams: known ? match!.pathParams : {},
    ...(reason ? { reason } : {}),
    path: `/${segments.join('/')}`,
    urlPath: `/${segments.map(encodeSegment).join('/')}`,
    returnsSecret: method !== 'GET' && SECRET_ANSWERS.test(subject),
  };
}

/** Arguments that turn an ordinary call into a destructive one. */
export function destructiveArgs(method: string, template: string, args: Record<string, unknown>): boolean {
  if (method === 'GET') return false;
  return argRulesFor(method, template).some((rule) => rule.when(args, method, template));
}

/** Whether some argument values can make this call destructive, from the parameters the endpoint has. */
export function hasDestructiveArgs(endpointParams: Record<string, unknown>, method: string, template: string): boolean {
  if (method === 'GET') return false;
  return argRulesFor(method, template).some((rule) => rule.params.some((p) => p in endpointParams));
}

export function isUnblocked(unblocked: readonly string[], method: string, decision: Decision): boolean {
  const target = decision.template ?? decision.path;
  return unblocked.some((entry) => {
    const parts = entry.trim().split(/\s+/);
    const [wantMethod, wantPath] = parts.length === 2 ? [parts[0]!.toUpperCase(), parts[1]!] : [undefined, parts[0]!];
    return (wantMethod === undefined || wantMethod === method) && wantPath.replace(/\/$/, '') === target;
  });
}

const DRY_RUN_NOTE = 'or preview with PROXMOX_DRY_RUN=true';

function writesOpen(subject: PolicySubject, dryRun: boolean): boolean {
  return subject.allowWrites || subject.dryRun || dryRun;
}

/**
 * Whether a gate is open for this instance, without any path: this is what hides tools
 * and refuses them before anything is sent or anyone is asked. `readOnly` marks the GET
 * half of guest_exec.
 */
export function gateRefusal(gate: Gate, subject: PolicySubject, opts: { dryRun?: boolean; readOnly?: boolean; what: string }): ProxmoxError | undefined {
  const { what } = opts;
  const dryRun = opts.dryRun ?? false;
  const stop = 'Do not retry.';
  const writeRefusal = () =>
    new ProxmoxError('write_disabled', `Instance "${subject.name}" is read-only: ${what} was not run and nothing was sent.`, {
      hint: `${stop} The operator can enable writes with PROXMOX_ALLOW_WRITES=true (or allow_writes on the instance), ${DRY_RUN_NOTE}.`,
    });
  switch (gate) {
    case 'read':
      return undefined;
    case 'sensitive':
      if (subject.allowSensitive) return undefined;
      return new ProxmoxError('sensitive_disabled', `${what} can return secrets or raw exports, or makes the node reach out to another host or into a backup, which is off by default.`, {
        hint: `${stop} The operator can allow it with PROXMOX_ALLOW_SENSITIVE=true.`,
      });
    case 'write':
      return writesOpen(subject, dryRun) ? undefined : writeRefusal();
    case 'elevated':
      if (!writesOpen(subject, dryRun)) return writeRefusal();
      if (subject.allowElevated) return undefined;
      return new ProxmoxError('elevated_disabled', `${what} changes the cluster itself or reaches the host (accounts, storage, network, firewall, node power, host devices, privileged containers...), which needs a separate permission.`, {
        hint: `${stop} The operator can allow it with PROXMOX_ALLOW_ELEVATED=true, on top of PROXMOX_ALLOW_WRITES.`,
      });
    case 'guest_exec':
      if (!subject.allowGuestExec) {
        return new ProxmoxError('guest_exec_disabled', `${what} runs commands or touches files inside a guest, which is off by default.`, {
          hint: `${stop} The operator can allow it with PROXMOX_ALLOW_GUEST_EXEC=true.`,
        });
      }
      return opts.readOnly || writesOpen(subject, dryRun) ? undefined : writeRefusal();
    case 'console':
      if (subject.allowElevated && subject.allowSensitive && subject.allowWrites) return undefined;
      return new ProxmoxError('elevated_disabled', `${what} opens a console, which hands out a login-equivalent ticket.`, {
        hint: `${stop} The operator must set all of PROXMOX_ALLOW_WRITES, PROXMOX_ALLOW_ELEVATED and PROXMOX_ALLOW_SENSITIVE.`,
      });
    case 'blocked':
      return new ProxmoxError('blocked_endpoint', `${what} is blocked by this server.`, {
        hint: `${stop} A human can do this in the Proxmox web interface, or the operator can list the endpoint in PROXMOX_UNBLOCK.`,
      });
    case 'ssh_read':
      if (subject.allowSsh) return undefined;
      return new ProxmoxError('ssh_disabled', `${what} needs SSH access to the node, which is off by default.`, {
        hint: `${stop} The operator can allow it with PROXMOX_ALLOW_SSH=true.`,
      });
    case 'ssh_write':
      if (!subject.allowSsh) {
        return new ProxmoxError('ssh_disabled', `${what} needs SSH access to the node, which is off by default.`, {
          hint: `${stop} The operator can allow it with PROXMOX_ALLOW_SSH=true, along with PROXMOX_ALLOW_WRITES.`,
        });
      }
      return writesOpen(subject, dryRun) ? undefined : writeRefusal();
  }
}

/** Throws unless the call is allowed. Returns the decision for logging and dry-run handling. */
export function authorize(subject: PolicySubject, method: string, path: string, unblocked: readonly string[] = [], opts: AuthorizeOptions = {}): Decision {
  const decision = classify(method, path, opts.pathParams);
  const what = `${method} ${decision.path}`;
  let gate = decision.gate;
  const hostArg = gate === 'write' ? hostAccessArg(method, decision.template, opts.params) : undefined;
  if (hostArg) gate = 'elevated';
  if (gate === 'blocked') {
    if (!isUnblocked(unblocked, method, decision)) {
      throw new ProxmoxError('blocked_endpoint', `${what} is blocked: ${decision.reason ?? 'blocked by policy.'}`, {
        hint: 'Do not retry. A human can do this in the Proxmox web interface, or the operator can list the endpoint in PROXMOX_UNBLOCK.',
      });
    }
    gate = 'elevated';
  }
  if (opts.readOnly && (method !== 'GET' || (gate !== 'read' && gate !== 'sensitive' && gate !== 'guest_exec'))) {
    throw new ProxmoxError('not_read_only', `${what} can change something, so a read tool refuses it: nothing was sent.`, {
      hint: 'A tool that writes is the way to do this, provided writes are enabled. pve_api_describe gives the name of the tool for an endpoint.',
    });
  }
  const refusal = gateRefusal(gate, subject, { dryRun: opts.dryRun ?? false, readOnly: method === 'GET', what: hostArg ? describeHostAccess(what, hostArg) : what });
  if (refusal) throw refusal;
  return { ...decision, gate };
}

/** The owner of a volume or a backup: local-lvm:vm-100-disk-0, local:backup/vzdump-qemu-100-..., pbs:backup/ct/100/... */
const VOLUME_OWNER = /(?:^|[:/])(?:vm|base|subvol)-(\d+)-|vzdump-(?:qemu|lxc|openvz)-(\d+)-|backup\/(?:vm|ct)\/(\d+)\//g;

/** What acts on all the guests of a node or a cluster, or on those in its "vms" list. */
const BULK_ACTION = re(`${NODE}/(?:startall|stopall|suspendall|migrateall)`, '/cluster/bulk-action/guest/[^/]+');

/** A value of a vmid list, as any of the Proxmox list parsers would read it. */
function vmidsIn(list: unknown): number[] {
  const items = Array.isArray(list) ? list : typeof list === 'string' ? list.split(/[,;\s]+/).filter(Boolean) : list === undefined || list === null ? [] : [list];
  return items.map(Number).filter(Number.isInteger);
}

function protectedRefusal(message: string, hint: string): ProxmoxError {
  return new ProxmoxError('protected_guest', message, { hint: `${hint} Do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS.` });
}

/**
 * A vmid in the path, or given to a create or clone, of a change, or named in the list of a bulk
 * action. Reaching everything counts as naming the protected guests. What this cannot see is in
 * the README: a pool, the power of a node, HA, any SSH command.
 */
export function assertNotProtected(protectedVmids: ReadonlySet<number>, method: string, decision: Decision, params?: Record<string, unknown>): void {
  if (method === 'GET' || protectedVmids.size === 0) return;
  const inPath = decision.template ? decision.pathParams.vmid : undefined;
  // An HA resource is the guest under another name: vm:100, ct:100.
  const candidates: unknown[] = [inPath, decision.pathParams.sid, params?.vmid, params?.newid, params?.sid];
  const template = decision.template ?? '';
  const all = [...protectedVmids].sort((a, b) => a - b).join(', ');
  if (BULK_ACTION.test(template) && vmidsIn(params?.vms).length === 0) {
    throw protectedRefusal(`${method} ${decision.path} without a "vms" list would reach every guest, and guests ${all} are protected on this server: it was not sent.`, 'Name the guests in "vms".');
  }
  if (BACKUP_RUN.test(template) && truthy(params?.all)) {
    const excluded = new Set(vmidsIn(params?.exclude));
    const reached = [...protectedVmids].filter((v) => !excluded.has(v));
    if (reached.length > 0) throw protectedRefusal(`${method} ${decision.path} with "all" would reach protected guests ${reached.join(', ')}: it was not sent.`, 'List them in "exclude", or name the guests in "vmid".');
  }
  // On a remote migration this names a guest of the other cluster.
  if (!template.endsWith('/remote_migrate')) candidates.push(params?.['target-vmid']);
  // Being in a pool or not changes nothing on the guest.
  if (!template.startsWith('/pools')) candidates.push(...(Array.isArray(params?.vms) ? params.vms : [params?.vms]));
  for (const owner of (decision.pathParams.volume ?? '').matchAll(VOLUME_OWNER)) candidates.push(owner[1] ?? owner[2] ?? owner[3]);
  // A replication job is called <vmid>-<number>.
  if (template.startsWith('/cluster/replication')) candidates.push(String(decision.pathParams.id ?? params?.id ?? '').split('-')[0]);
  // Not in the catalog, so no telling which segment is a vmid: any match counts.
  if (!decision.template) candidates.push(...decision.path.split('/'));
  for (const candidate of candidates) {
    if (candidate === undefined || candidate === null || candidate === '') continue;
    // vzdump takes a list: 100,101. The Proxmox parser also takes ; and spaces.
    const items = typeof candidate === 'string' ? candidate.replace(/^(?:vm|ct):/, '').split(/[,;\s]+/) : [candidate];
    const n = items.map(Number).find((v) => Number.isInteger(v) && protectedVmids.has(v));
    if (n !== undefined) {
      throw new ProxmoxError('protected_guest', `Guest ${n} is protected on this server: ${method} ${decision.path} was not sent.`, {
        hint: 'Do not retry and do not look for another route to the same change. The operator can remove it from PROXMOX_PROTECTED_VMIDS.',
      });
    }
  }
}
