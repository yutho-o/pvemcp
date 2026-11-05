import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { catalog, findEndpoint, matchPath, type CatalogEndpoint, type HttpMethod } from '../src/catalog/index.js';

/**
 * A local stand-in for the Proxmox API. It answers the way the real one does: errors in the
 * reason phrase and in {errors, message}, CSRF checks on ticket auth, form bodies, parameter
 * checks taken from the catalog, UPID tasks with status and log, 595 for an offline node.
 *
 * What it does not model answers 501, like a Proxmox version without that endpoint. With
 * permissive: true it answers generic data of the documented type instead.
 */

export const FAKE_TOKEN_ID = 'mcp@pve!test';
export const FAKE_TOKEN_SECRET = '11111111-2222-3333-4444-555555555555';
export const FAKE_TOKEN = `${FAKE_TOKEN_ID}=${FAKE_TOKEN_SECRET}`;
export const FAKE_USER = 'root@pam';
export const FAKE_PASSWORD = 'correct horse';

export class Reply {
  constructor(
    readonly status: number,
    readonly reason: string,
    readonly body: unknown = { data: null },
    readonly headers: Record<string, string> = {},
  ) {}
}

/** The socket is closed without an answer: the client sees ECONNRESET. */
export const RESET = Symbol('reset');

/** A Proxmox error: the text goes in the reason phrase and in message, field errors in errors. */
export function pveError(status: number, message: string, errors?: Record<string, string>): Reply {
  return new Reply(status, message.split('\n')[0]!.slice(0, 200), { data: null, message: `${message}\n`, ...(errors ? { errors } : {}) });
}

export interface RecordedRequest {
  method: string;
  /** Path after /api2/json, with each segment decoded. A %2F stays a slash inside its segment. */
  path: string;
  /** Exactly as it was on the wire. */
  rawUrl: string;
  query: Record<string, string | string[]>;
  body: Record<string, string | string[]>;
  rawBody: string;
  headers: http.IncomingHttpHeaders;
  auth: 'token' | 'ticket' | 'none';
  template?: string;
  pathParams: Record<string, string>;
  /** For a multipart upload. */
  file?: { field: string; filename: string; bytes: number; content: Buffer };
}

export interface FakeGuest {
  vmid: number;
  type: 'qemu' | 'lxc';
  node: string;
  name: string;
  status: string;
  config: Record<string, unknown>;
  snapshots: Array<{ name: string; description?: string }>;
  tags?: string;
  template?: boolean;
  /** For LXC interfaces and the guest agent. */
  ip?: string;
  agent?: boolean;
}

export interface FakeTask {
  upid: string;
  node: string;
  type: string;
  id: string;
  user: string;
  starttime: number;
  /** Status reads left before it stops. */
  pollsLeft: number;
  exitstatus: string;
  log: string[];
  stopped: boolean;
}

export type FakeHandler = (req: RecordedRequest, params: Record<string, string>) => unknown | Promise<unknown>;

export interface FakeOptions {
  nodes?: string[];
  guests?: Array<Partial<FakeGuest> & { vmid: number }>;
  /** Answer generic data on what is not modelled, instead of 501. */
  permissive?: boolean;
  /** Skip the parameter checks from the catalog. */
  lenient?: boolean;
  /** Serve HTTPS. */
  tls?: { key: string; cert: string };
  /** Accounts that get NeedTFA at login. */
  tfaUsers?: string[];
  /** Status reads before a task stops. Default 0: stopped at the first read. */
  taskPolls?: number;
}

function hex(n: number, width = 8): string {
  return n.toString(16).toUpperCase().padStart(width, '0');
}

function decodeForm(text: string): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  if (!text) return out;
  for (const pair of text.split('&')) {
    if (!pair) continue;
    const at = pair.indexOf('=');
    const key = decodeURIComponent((at < 0 ? pair : pair.slice(0, at)).replace(/\+/g, ' '));
    const value = at < 0 ? '' : decodeURIComponent(pair.slice(at + 1).replace(/\+/g, ' '));
    const existing = out[key];
    if (existing === undefined) out[key] = value;
    else out[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
  }
  return out;
}

function parseMultipart(raw: Buffer, contentType: string): { fields: Record<string, string>; file?: RecordedRequest['file'] } {
  const boundary = /boundary=(.+)$/.exec(contentType)?.[1];
  const fields: Record<string, string> = {};
  if (!boundary) return { fields };
  let file: RecordedRequest['file'];
  const marker = Buffer.from(`--${boundary}`);
  let at = raw.indexOf(marker);
  while (at >= 0) {
    const start = at + marker.length + 2;
    const next = raw.indexOf(marker, start);
    if (next < 0) break;
    const headEnd = raw.indexOf('\r\n\r\n', start);
    const head = raw.subarray(start, headEnd).toString('utf8');
    const content = raw.subarray(headEnd + 4, next - 2);
    const name = /name="([^"]+)"/.exec(head)?.[1] ?? '';
    const filename = /filename="([^"]+)"/.exec(head)?.[1];
    if (filename !== undefined) file = { field: name, filename, bytes: content.length, content: Buffer.from(content) };
    else fields[name] = content.toString('utf8');
    at = next;
  }
  return { fields, ...(file ? { file } : {}) };
}

function genericData(endpoint: CatalogEndpoint): unknown {
  switch (endpoint.returns.type) {
    case 'array':
      return [];
    case 'object':
      return {};
    case 'string':
      return 'ok';
    case 'integer':
      return 0;
    case 'boolean':
      return true;
    default:
      return null;
  }
}

/** What Proxmox itself refuses before running anything. */
function checkParams(endpoint: CatalogEndpoint, pathParams: Record<string, string>, given: Record<string, string | string[]>): Record<string, string> {
  const errors: Record<string, string> = {};
  const indexed = Object.keys(endpoint.params).filter((k) => k.endsWith('[n]')).map((k) => k.slice(0, -3));
  for (const [name, value] of Object.entries(given)) {
    const direct = endpoint.params[name];
    const isIndexed = indexed.some((base) => new RegExp(`^${base}\\d+$`).test(name));
    if (!direct && !isIndexed) {
      errors[name] = 'property is not defined in schema and the schema does not allow additional properties';
      continue;
    }
    if (!direct) continue;
    const values = Array.isArray(value) ? value : [value];
    if (values.length > 1 && direct.type !== 'array') errors[name] = 'type check failed: multiple values for a single property';
    for (const v of values) {
      if (direct.type === 'integer' && !/^-?\d+$/.test(v)) errors[name] = `type check ('integer') failed - got '${v}'`;
      if (direct.type === 'number' && !/^-?\d+(\.\d+)?$/.test(v)) errors[name] = `type check ('number') failed - got '${v}'`;
      if (direct.type === 'boolean' && !/^(0|1|true|false|yes|no|on|off)$/i.test(v)) errors[name] = `type check ('boolean') failed - got '${v}'`;
      if (direct.enum && direct.type === 'string' && !direct.enum.includes(v)) errors[name] = `value '${v}' does not have a value in the enumeration '${direct.enum.join(', ')}'`;
    }
  }
  for (const [name, param] of Object.entries(endpoint.params)) {
    if (param.optional || name.endsWith('[n]') || name in pathParams || name in given) continue;
    errors[name] = 'property is missing and it is not optional';
  }
  return errors;
}

export class FakePve {
  server?: http.Server;
  url = '';
  readonly requests: RecordedRequest[] = [];
  readonly nodes = new Map<string, { online: boolean; ip: string }>();
  readonly guests = new Map<number, FakeGuest>();
  readonly tasks = new Map<string, FakeTask>();
  readonly storages: Array<Record<string, unknown>> = [{ storage: 'local', type: 'dir', content: 'iso,vztmpl,backup', path: '/var/lib/vz' }];
  readonly volumes = new Map<string, Array<Record<string, unknown>>>([['local', [{ volid: 'local:iso/debian.iso', content: 'iso', size: 1024, format: 'iso' }]]]);
  readonly tickets = new Set<string>();
  /** Successful logins, to tell a renewal from a reused ticket. */
  logins = 0;
  private readonly csrf = new Map<string, string>();
  private readonly routes = new Map<string, FakeHandler>();
  private readonly failures = new Map<string, Array<Reply | typeof RESET>>();
  private counter = 0;

  constructor(private readonly options: FakeOptions = {}) {
    (options.nodes ?? ['pve1']).forEach((name, i) => this.nodes.set(name, { online: true, ip: `192.0.2.${i + 1}` }));
    for (const guest of options.guests ?? [{ vmid: 100, type: 'qemu', name: 'web' }, { vmid: 101, type: 'lxc', name: 'db' }]) this.addGuest(guest);
    this.installRoutes();
  }

  async start(): Promise<void> {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
      void this.handle(req, res).catch((err: Error) => {
        res.writeHead(599, 'fake-pve bug').end(JSON.stringify({ error: err.stack }));
      });
    };
    const { tls } = this.options;
    const server = tls ? https.createServer({ key: tls.key, cert: tls.cert }, handler) : http.createServer(handler);
    this.server = server;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    this.url = `${tls ? 'https' : 'http'}://127.0.0.1:${port}`;
  }

  async stop(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = undefined;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  addGuest(guest: Partial<FakeGuest> & { vmid: number }): FakeGuest {
    const full: FakeGuest = {
      type: 'qemu',
      node: [...this.nodes.keys()][0] ?? 'pve1',
      name: `guest${guest.vmid}`,
      status: 'running',
      config: {},
      snapshots: [],
      ...guest,
    };
    if (full.config.name === undefined && full.type === 'qemu') full.config.name = full.name;
    if (full.config.hostname === undefined && full.type === 'lxc') full.config.hostname = full.name;
    this.guests.set(full.vmid, full);
    return full;
  }

  /** Replaces or adds the handler of one method. Return a value for {data}, or a Reply. */
  on(method: HttpMethod, template: string, handler: FakeHandler): void {
    this.routes.set(`${method} ${template}`, handler);
  }

  /** The next calls of this method answer this instead. */
  failNext(method: HttpMethod, template: string, failure: Reply | typeof RESET, times = 1): void {
    const queue = this.failures.get(`${method} ${template}`) ?? [];
    for (let i = 0; i < times; i++) queue.push(failure);
    this.failures.set(`${method} ${template}`, queue);
  }

  setNodeOnline(node: string, online: boolean): void {
    const entry = this.nodes.get(node);
    if (entry) entry.online = online;
  }

  /** Every ticket stops working, as after two hours. */
  expireTickets(): void {
    this.tickets.clear();
    this.csrf.clear();
  }

  /** Requests that are not GET and not the login. */
  writes(): RecordedRequest[] {
    return this.requests.filter((r) => r.method !== 'GET' && r.path !== '/access/ticket');
  }

  find(method: string, template: string): RecordedRequest[] {
    return this.requests.filter((r) => r.method === method && r.template === template);
  }

  /** Starts a task. It stops after opts.polls status reads, with opts.exitstatus. */
  startTask(node: string, type: string, id: string, opts: { polls?: number; exitstatus?: string; log?: string[]; user?: string } = {}): string {
    this.counter++;
    const starttime = 1_700_000_000 + this.counter;
    const user = opts.user ?? FAKE_USER;
    const upid = `UPID:${node}:${hex(this.counter)}:${hex(this.counter * 7)}:${hex(starttime)}:${type}:${id}:${user}:`;
    this.tasks.set(upid, {
      upid,
      node,
      type,
      id,
      user,
      starttime,
      pollsLeft: opts.polls ?? this.options.taskPolls ?? 0,
      exitstatus: opts.exitstatus ?? 'OK',
      log: opts.log ?? [`starting ${type}`, 'TASK OK'],
      stopped: false,
    });
    return upid;
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks);
    const rawUrl = req.url ?? '/';
    const [pathPart, queryPart] = rawUrl.split('?', 2) as [string, string | undefined];
    const method = (req.method ?? 'GET') as HttpMethod;
    const contentType = String(req.headers['content-type'] ?? '');

    const send = (reply: Reply) => {
      res.writeHead(reply.status, reply.reason, { 'Content-Type': 'application/json;charset=UTF-8', ...reply.headers });
      res.end(typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body));
    };
    if (!pathPart.startsWith('/api2/json')) return send(new Reply(404, 'Not Found', {}, {}));

    const segments = pathPart.slice('/api2/json'.length).split('/').filter(Boolean).map(decodeURIComponent);
    const multipart = contentType.startsWith('multipart/form-data') ? parseMultipart(raw, contentType) : undefined;
    const body = multipart ? multipart.fields : contentType.includes('x-www-form-urlencoded') ? decodeForm(raw.toString('utf8')) : {};
    const query = decodeForm(queryPart ?? '');
    const match = matchPath(segments);
    const recorded: RecordedRequest = {
      method,
      path: `/${segments.join('/')}`,
      rawUrl,
      query,
      body,
      rawBody: raw.toString('utf8'),
      headers: req.headers,
      auth: 'none',
      pathParams: match?.pathParams ?? {},
      ...(match?.methods.has(method) ? { template: match.template } : {}),
      ...(multipart?.file ? { file: multipart.file } : {}),
    };
    this.requests.push(recorded);

    if (recorded.path === '/access/ticket' && method === 'POST') return send(this.login(body));

    const auth = this.authenticate(req, method);
    if (auth instanceof Reply) return send(auth);
    recorded.auth = auth;

    const endpoint = recorded.template ? findEndpoint(method, recorded.template) : undefined;
    if (!endpoint) return send(pveError(501, `Method '${method} ${recorded.path}' not implemented`));
    if (auth === 'token' && !endpoint.allowtoken) return send(pveError(403, 'Permission check failed: tokens are not allowed here'));

    const failure = this.failures.get(`${method} ${endpoint.path}`)?.shift();
    if (failure === RESET) {
      req.socket.destroy();
      return;
    }
    if (failure) return send(failure);

    const nodeParam = recorded.pathParams.node;
    if (nodeParam !== undefined && this.nodes.get(nodeParam)?.online === false && !endpoint.path.startsWith('/cluster')) {
      return send(new Reply(595, `Connection timed out`, { data: null }));
    }
    if (!this.options.lenient) {
      const given = method === 'POST' || method === 'PUT' ? body : query;
      const errors = checkParams(endpoint, recorded.pathParams, multipart?.file ? { ...given, [multipart.file.field]: multipart.file.filename } : given);
      if (Object.keys(errors).length > 0) return send(pveError(400, 'Parameter verification failed.', errors));
    }

    const route = this.routes.get(`${method} ${endpoint.path}`);
    if (!route) {
      if (this.options.permissive) return send(new Reply(200, 'OK', { data: genericData(endpoint) }));
      return send(pveError(501, `Method '${method} ${recorded.path}' not implemented`));
    }
    const result = await route(recorded, recorded.pathParams);
    if (result instanceof Reply) return send(result);
    send(new Reply(200, 'OK', { data: result ?? null }));
  }

  private login(body: Record<string, string | string[]>): Reply {
    const username = String(body.username ?? '');
    if (username !== FAKE_USER || body.password !== FAKE_PASSWORD) return pveError(401, 'authentication failure');
    this.counter++;
    const ticket = `PVE:${username}:${hex(1_700_000_000 + this.counter)}::c2lnbmF0dXJl+/==`;
    const csrf = `${hex(this.counter)}:csrf+token`;
    if (this.options.tfaUsers?.includes(username)) {
      return new Reply(200, 'OK', { data: { username, ticket: `PVE:!tfa!${ticket}`, CSRFPreventionToken: csrf, NeedTFA: 1 } });
    }
    this.tickets.add(ticket);
    this.csrf.set(ticket, csrf);
    this.logins++;
    return new Reply(200, 'OK', { data: { username, ticket, CSRFPreventionToken: csrf } });
  }

  private authenticate(req: http.IncomingMessage, method: string): 'token' | 'ticket' | Reply {
    const header = req.headers.authorization;
    if (header) {
      return header === `PVEAPIToken=${FAKE_TOKEN}` ? 'token' : pveError(401, 'authentication failure');
    }
    const cookie = /(?:^|;\s*)PVEAuthCookie=([^;]*)/.exec(String(req.headers.cookie ?? ''))?.[1];
    if (!cookie) return pveError(401, 'authentication failure');
    const ticket = decodeURIComponent(cookie);
    if (!this.tickets.has(ticket)) return pveError(401, 'authentication failure');
    if (method !== 'GET' && req.headers.csrfpreventiontoken !== this.csrf.get(ticket)) {
      return pveError(401, 'invalid csrf token');
    }
    return 'ticket';
  }

  private guestOr500(type: 'qemu' | 'lxc', params: Record<string, string>): FakeGuest | Reply {
    const guest = this.guests.get(Number(params.vmid));
    if (!guest || guest.type !== type || guest.node !== params.node) {
      const dir = type === 'qemu' ? 'qemu-server' : 'lxc';
      return pveError(500, `Configuration file 'nodes/${params.node}/${dir}/${params.vmid}.conf' does not exist`);
    }
    return guest;
  }

  private installRoutes(): void {
    this.on('GET', '/version', () => ({ version: '9.1.0', release: '9.1', repoid: 'fake' }));
    this.on('GET', '/nodes', () => [...this.nodes.entries()].map(([node, n]) => ({ node, status: n.online ? 'online' : 'offline', type: 'node', cpu: 0.1, maxcpu: 8, mem: 1024, maxmem: 8192 })));
    this.on('GET', '/nodes/{node}/status', () => ({ uptime: 1000, cpu: 0.1, memory: { total: 8192, used: 1024 }, pveversion: 'pve-manager/9.1.0' }));
    this.on('GET', '/nodes/{node}/version', () => ({ version: '9.1.0', release: '9.1', repoid: 'fake' }));
    this.on('GET', '/cluster/status', () => [
      { type: 'cluster', name: 'fake', quorate: 1, nodes: this.nodes.size, version: 3 },
      ...[...this.nodes.entries()].map(([name, n], i) => ({ type: 'node', name, ip: n.ip, online: n.online ? 1 : 0, local: i === 0 ? 1 : 0, nodeid: i + 1 })),
    ]);
    this.on('GET', '/cluster/nextid', () => {
      let id = 100;
      while (this.guests.has(id)) id++;
      return String(id);
    });
    this.on('GET', '/cluster/resources', (req) => {
      const guests = [...this.guests.values()].map((g) => ({
        id: `${g.type}/${g.vmid}`,
        type: g.type,
        vmid: g.vmid,
        node: g.node,
        name: g.name,
        status: g.status,
        ...(g.tags ? { tags: g.tags } : {}),
        ...(g.template ? { template: 1 } : {}),
      }));
      const nodes = [...this.nodes.entries()].map(([node, n]) => ({ id: `node/${node}`, type: 'node', node, status: n.online ? 'online' : 'offline' }));
      const storage = this.storages.map((s) => ({ id: `storage/pve1/${String(s.storage)}`, type: 'storage', storage: s.storage, node: [...this.nodes.keys()][0] }));
      const type = req.query.type;
      if (type === 'vm') return guests;
      if (type === 'node') return nodes;
      if (type === 'storage') return storage;
      return [...guests, ...nodes, ...storage];
    });

    const taskRow = (t: FakeTask) => ({ upid: t.upid, node: t.node, type: t.type, id: t.id, user: t.user, starttime: t.starttime, status: t.stopped ? t.exitstatus : 'running', ...(t.stopped ? { endtime: t.starttime + 1 } : {}) });
    this.on('GET', '/cluster/tasks', () => [...this.tasks.values()].map(taskRow));
    this.on('GET', '/nodes/{node}/tasks', (_req, p) => [...this.tasks.values()].filter((t) => t.node === p.node).map(taskRow));
    this.on('GET', '/nodes/{node}/tasks/{upid}/status', (_req, p) => {
      const task = this.tasks.get(p.upid!);
      if (!task) return pveError(500, `no such task ${p.upid}`);
      if (task.pollsLeft > 0) {
        task.pollsLeft--;
        return { upid: task.upid, node: task.node, type: task.type, id: task.id, user: task.user, starttime: task.starttime, status: 'running', pid: 1, pstart: 1 };
      }
      task.stopped = true;
      return { upid: task.upid, node: task.node, type: task.type, id: task.id, user: task.user, starttime: task.starttime, status: 'stopped', exitstatus: task.exitstatus, pid: 1, pstart: 1 };
    });
    this.on('GET', '/nodes/{node}/tasks/{upid}/log', (req, p) => {
      const task = this.tasks.get(p.upid!);
      if (!task) return pveError(500, `no such task ${p.upid}`);
      const start = Number(req.query.start ?? 0);
      const limit = Number(req.query.limit ?? 50);
      return task.log.slice(start, start + limit).map((t, i) => ({ n: start + i + 1, t }));
    });
    this.on('DELETE', '/nodes/{node}/tasks/{upid}', (_req, p) => {
      const task = this.tasks.get(p.upid!);
      if (task) {
        task.stopped = true;
        task.pollsLeft = 0;
        task.exitstatus = 'interrupted by signal';
      }
      return null;
    });

    for (const type of ['qemu', 'lxc'] as const) {
      const base = `/nodes/{node}/${type}`;
      const action = (name: string, apply: (g: FakeGuest, req: RecordedRequest) => void, needsRunning?: boolean) => {
        this.on('POST', `${base}/{vmid}/status/${name}`, (req, p) => {
          const guest = this.guestOr500(type, p);
          if (guest instanceof Reply) return guest;
          if (needsRunning && guest.status !== 'running') return pveError(500, `CT or VM ${guest.vmid} not running`);
          apply(guest, req);
          return this.startTask(p.node!, `${type === 'qemu' ? 'qm' : 'vz'}${name}`, String(guest.vmid));
        });
      };
      this.on('GET', base, (_req, p) => [...this.guests.values()].filter((g) => g.type === type && g.node === p.node).map((g) => ({ vmid: g.vmid, name: g.name, status: g.status, ...(g.tags ? { tags: g.tags } : {}) })));
      this.on('POST', base, (req, p) => {
        const vmid = Number(req.body.vmid);
        if (this.guests.has(vmid) && !req.body.force) return pveError(500, `VM ${vmid} already exists on node '${p.node}'`);
        const config: Record<string, unknown> = { ...req.body };
        delete config.vmid;
        delete config.force;
        delete config.start;
        const name = String(req.body.name ?? req.body.hostname ?? `guest${vmid}`);
        this.addGuest({ vmid, type, node: p.node!, name, status: req.body.start === '1' ? 'running' : 'stopped', config });
        return this.startTask(p.node!, type === 'qemu' ? 'qmcreate' : 'vzcreate', String(vmid));
      });
      this.on('GET', `${base}/{vmid}/config`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        return guest instanceof Reply ? guest : { ...guest.config, digest: 'abc123' };
      });
      const updateConfig: FakeHandler = (req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        Object.assign(guest.config, req.body);
        return null;
      };
      this.on('PUT', `${base}/{vmid}/config`, updateConfig);
      this.on('DELETE', `${base}/{vmid}`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        if (guest.status === 'running') return pveError(500, `VM ${guest.vmid} is running - destroy failed`);
        this.guests.delete(guest.vmid);
        return this.startTask(p.node!, type === 'qemu' ? 'qmdestroy' : 'vzdestroy', String(guest.vmid));
      });
      this.on('GET', `${base}/{vmid}/status/current`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        return guest instanceof Reply ? guest : { vmid: guest.vmid, name: guest.name, status: guest.status, type, uptime: guest.status === 'running' ? 100 : 0, cpus: 2, maxmem: 2048, mem: 512 };
      });
      action('start', (g) => (g.status = 'running'));
      action('stop', (g) => (g.status = 'stopped'));
      action('shutdown', (g) => (g.status = 'stopped'), true);
      action('reboot', () => undefined, true);
      action('suspend', (g) => (g.status = 'paused'), true);
      action('resume', (g) => (g.status = 'running'));
      this.on('POST', `${base}/{vmid}/clone`, (req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        const newid = Number(req.body.newid);
        this.addGuest({ vmid: newid, type, node: guest.node, name: String(req.body.name ?? req.body.hostname ?? `clone${newid}`), status: 'stopped', config: { ...guest.config } });
        return this.startTask(p.node!, type === 'qemu' ? 'qmclone' : 'vzclone', String(guest.vmid));
      });
      this.on('POST', `${base}/{vmid}/migrate`, (req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        const upid = this.startTask(p.node!, type === 'qemu' ? 'qmigrate' : 'vzmigrate', String(guest.vmid));
        guest.node = String(req.body.target);
        return upid;
      });
      this.on('GET', `${base}/{vmid}/snapshot`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        return guest instanceof Reply ? guest : [...guest.snapshots, { name: 'current', description: 'You are here!' }];
      });
      this.on('POST', `${base}/{vmid}/snapshot`, (req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        const name = String(req.body.snapname);
        if (guest.snapshots.some((s) => s.name === name)) return pveError(500, `snapshot name '${name}' already used`);
        guest.snapshots.push({ name, ...(req.body.description ? { description: String(req.body.description) } : {}) });
        return this.startTask(p.node!, type === 'qemu' ? 'qmsnapshot' : 'vzsnapshot', String(guest.vmid));
      });
      this.on('DELETE', `${base}/{vmid}/snapshot/{snapname}`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        guest.snapshots = guest.snapshots.filter((s) => s.name !== p.snapname);
        return this.startTask(p.node!, type === 'qemu' ? 'qmdelsnapshot' : 'vzdelsnapshot', String(guest.vmid));
      });
      this.on('POST', `${base}/{vmid}/snapshot/{snapname}/rollback`, (_req, p) => {
        const guest = this.guestOr500(type, p);
        if (guest instanceof Reply) return guest;
        if (!guest.snapshots.some((s) => s.name === p.snapname)) return pveError(500, `snapshot '${p.snapname}' does not exist`);
        return this.startTask(p.node!, type === 'qemu' ? 'qmrollback' : 'vzrollback', String(guest.vmid));
      });
    }
    this.on('POST', '/nodes/{node}/qemu/{vmid}/status/reset', (_req, p) => {
      const guest = this.guestOr500('qemu', p);
      return guest instanceof Reply ? guest : this.startTask(p.node!, 'qmreset', String(guest.vmid));
    });
    // The asynchronous variant answers with a task.
    this.on('POST', '/nodes/{node}/qemu/{vmid}/config', (req, p) => {
      const guest = this.guestOr500('qemu', p);
      if (guest instanceof Reply) return guest;
      Object.assign(guest.config, req.body);
      return this.startTask(p.node!, 'qmconfig', String(guest.vmid));
    });
    this.on('GET', '/nodes/{node}/lxc/{vmid}/interfaces', (_req, p) => {
      const guest = this.guestOr500('lxc', p);
      if (guest instanceof Reply) return guest;
      return [{ name: 'lo', inet: '127.0.0.1/8' }, { name: 'eth0', hwaddr: 'BC:24:11:00:00:01', inet: `${guest.ip ?? '10.0.0.5'}/24` }];
    });
    this.on('GET', '/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces', (_req, p) => {
      const guest = this.guestOr500('qemu', p);
      if (guest instanceof Reply) return guest;
      if (guest.agent === false) return pveError(500, 'QEMU guest agent is not running');
      return { result: [{ name: 'eth0', 'ip-addresses': [{ 'ip-address': guest.ip ?? '10.0.0.6', 'ip-address-type': 'ipv4', prefix: 24 }] }] };
    });
    this.on('POST', '/nodes/{node}/qemu/{vmid}/agent/ping', () => ({}));

    this.on('GET', '/storage', () => this.storages);
    this.on('GET', '/nodes/{node}/storage', () => this.storages.map((s) => ({ ...s, active: 1, enabled: 1, total: 1000, used: 100, avail: 900 })));
    this.on('GET', '/nodes/{node}/storage/{storage}/content', (_req, p) => this.volumes.get(p.storage!) ?? []);
    this.on('DELETE', '/nodes/{node}/storage/{storage}/content/{volume}', (_req, p) => {
      const list = this.volumes.get(p.storage!) ?? [];
      this.volumes.set(p.storage!, list.filter((v) => v.volid !== p.volume));
      return this.startTask(p.node!, 'imgdel', String(p.volume));
    });
    this.on('POST', '/nodes/{node}/storage/{storage}/upload', (req, p) => {
      if (!req.file) return pveError(400, 'Parameter verification failed.', { filename: 'missing file' });
      return this.startTask(p.node!, 'imgcopy', req.file.filename);
    });
    this.on('GET', '/access/users', () => [{ userid: FAKE_USER, enable: 1 }]);
    this.on('POST', '/access/users/{userid}/token/{tokenid}', (_req, p) => ({ 'full-tokenid': `${p.userid}!${p.tokenid}`, info: { privsep: 1 }, value: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }));
  }
}

/** Every catalog method, for tests that walk the whole API. */
export function allEndpoints(): CatalogEndpoint[] {
  return catalog.endpoints;
}
