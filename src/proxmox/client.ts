import { Buffer } from 'node:buffer';
import { createReadStream, statSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { basename } from 'node:path';
import type { Duplex } from 'node:stream';
import tls from 'node:tls';
import { findEndpoint, type HttpMethod } from '../catalog/index.js';
import type { InstanceConfig } from '../config.js';
import { ProxmoxError } from './errors.js';
import { encodePairs, flattenParams, type Params } from './params.js';
import { assertNotProtected, authorize, type Decision } from './policy.js';
import { assertNoRedactedValue, redactRequest, redactResponse, scrubText } from './redact.js';
import { DRY_RUN_UPID } from './tasks.js';

export type Method = HttpMethod;

export interface RequestOptions {
  /** Query string for GET and DELETE, form body for POST and PUT. */
  params?: Params;
  /** Fills {placeholders} in the path, encoded. The way to pass values such as local:iso/x.iso. */
  pathParams?: Record<string, string | number>;
  /** Set for read tools: anything that changes state is refused. */
  readOnly?: boolean;
  /** Record this write instead of sending it. */
  dryRun?: boolean;
  /** Filled with the requests a dry run would have sent. */
  dryRunLog?: DryRunEntry[];
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Keep secrets in the answer. Only honoured when the instance allows sensitive data. */
  includeSensitive?: boolean;
}

export type DryRunEntry =
  | { method: Method; path: string; params?: unknown; note?: string }
  | { ssh: { node: string; command?: string; access: 'read' | 'write'; stdin?: { bytes: number; sha256: string }; sftp?: string; path?: string } };

export interface WriteRecord {
  method?: Method;
  path?: string;
  params?: unknown;
  status: string;
  ssh?: unknown;
}

export interface UploadFile {
  localPath: string;
  filename?: string;
  /** Name of the file part in the form. */
  field?: string;
}

const MAX_RETRIES = 2;
const MAX_CONCURRENCY = 4;
const RETRYABLE_STATUS = new Set([502, 503, 504]);
const TLS_ERROR_CODES = /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY|HOSTNAME|ALTNAME|ERR_TLS/;
const MAX_RESPONSE_BYTES = 128 * 1024 * 1024;
/** A ticket lasts two hours: renewing well before that means no request ever meets a dead one. */
const TICKET_RENEW_MS = 90 * 60 * 1000;
const UPLOAD_TIMEOUT_MS = 60 * 60 * 1000;

interface RawResponse {
  status: number;
  reason: string;
  contentType: string;
  body: string;
}

interface Ticket {
  ticket: string;
  csrf: string;
  at: number;
}

interface WireRequest {
  method: Method;
  url: string;
  headers: Record<string, string>;
  body?: string;
  bodyStream?: () => NodeJS.ReadableStream;
  bodyPrefix?: Buffer;
  bodySuffix?: Buffer;
  timeoutMs: number;
  signal?: AbortSignal;
  /** Label for messages. */
  label: string;
}

/**
 * Connects, checks the pin, and only then hands the socket over: no request, and so no
 * credential, is ever written to a server that fails it. Node's checkServerIdentity is no use
 * here. It does not run when the chain fails to verify, which is the normal case for a
 * self-signed Proxmox certificate.
 */
class PinnedAgent extends https.Agent {
  constructor(
    options: https.AgentOptions,
    private readonly pin: string,
    private readonly label: string,
  ) {
    super(options);
  }

  override createConnection(options: http.ClientRequestArgs, callback?: (err: Error | null, stream: Duplex) => void): undefined {
    const socket = tls.connect({ ...(options as tls.ConnectionOptions), rejectUnauthorized: false });
    const onError = (err: Error) => callback?.(err, socket);
    socket.once('error', onError);
    socket.once('secureConnect', () => {
      socket.removeListener('error', onError);
      const seen = socket.getPeerCertificate().fingerprint256?.toUpperCase();
      if (seen !== this.pin) {
        socket.destroy();
        callback?.(new ProxmoxError('tls_error', `The TLS certificate of ${this.label} does not match PROXMOX_FINGERPRINT (it has ${seen ?? 'no fingerprint'}). Nothing was sent.`, {
          hint: 'Do not retry. Either the certificate was renewed, and the operator has to update the pin, or something is intercepting the connection.',
        }), socket);
        return;
      }
      callback?.(null, socket);
    });
    return undefined;
  }
}

/** Proxmox puts the real error in the reason phrase, and field errors in the body. */
function parseErrorBody(body: string): { message?: string; errors?: Record<string, string> } {
  try {
    const json = JSON.parse(body) as { message?: unknown; errors?: unknown };
    const out: { message?: string; errors?: Record<string, string> } = {};
    if (typeof json.message === 'string') out.message = scrubText(json.message).trim();
    if (json.errors && typeof json.errors === 'object') {
      out.errors = {};
      for (const [k, v] of Object.entries(json.errors)) out.errors[k] = scrubText(String(v)).trim();
    }
    return out;
  } catch {
    return {};
  }
}

export class ProxmoxClient {
  private readonly agents: { keepAlive: http.Agent; single: http.Agent };
  private readonly base: URL;
  private readonly tokenHeader?: string;
  private ticket?: Ticket;
  private ticketPromise?: Promise<Ticket>;
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(
    readonly config: InstanceConfig,
    private readonly unblocked: readonly string[] = [],
    private readonly onWrite?: (entry: WriteRecord) => void,
  ) {
    this.base = new URL(config.url);
    if (config.tokenId && config.tokenSecret) this.tokenHeader = `PVEAPIToken=${config.tokenId}=${config.tokenSecret}`;
    this.agents = { keepAlive: this.createAgent(true), single: this.createAgent(false) };
  }

  private createAgent(keepAlive: boolean): http.Agent {
    const options: https.AgentOptions = { keepAlive, maxSockets: MAX_CONCURRENCY };
    if (this.base.protocol !== 'https:') return new http.Agent(options);
    if (this.config.fingerprint) return new PinnedAgent(options, this.config.fingerprint, this.config.url);
    options.rejectUnauthorized = this.config.verifySsl;
    if (this.config.ca) options.ca = this.config.ca;
    return new https.Agent(options);
  }

  close(): void {
    this.agents.keepAlive.destroy();
    this.agents.single.destroy();
  }

  get usesToken(): boolean {
    return this.tokenHeader !== undefined;
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

  /** Everything before the first byte goes out: path, gates, token limits, protected guests, placeholders. */
  private prepare(method: Method, path: string, opts: RequestOptions): Decision {
    const decision = authorize(this.config, method, path, this.unblocked, {
      ...(opts.readOnly !== undefined ? { readOnly: opts.readOnly } : {}),
      ...(opts.dryRun !== undefined ? { dryRun: opts.dryRun } : {}),
      ...(opts.pathParams ? { pathParams: opts.pathParams } : {}),
      ...(opts.params ? { params: opts.params } : {}),
    });
    const endpoint = decision.template ? findEndpoint(method, decision.template) : undefined;
    if (endpoint && !endpoint.allowtoken && this.usesToken) {
      throw new ProxmoxError('forbidden', `${method} ${decision.template} does not accept API tokens: Proxmox only allows it with a password login.`, {
        hint: 'Do not retry with a token. A human can do this in the web interface, or the operator can run this server with PROXMOX_USERNAME and PROXMOX_PASSWORD.',
      });
    }
    assertNotProtected(this.config.protectedVmids, method, decision, opts.params);
    if (method !== 'GET') assertNoRedactedValue(opts.params, decision.path);
    return decision;
  }

  /** The chokepoint: every call to the Proxmox API goes through here and through the policy. */
  async request(method: Method, path: string, opts: RequestOptions = {}): Promise<unknown> {
    const decision = this.prepare(method, path, opts);

    if (method !== 'GET' && (opts.dryRun || this.config.dryRun)) return this.simulateWrite(method, decision, opts);

    const pairs = flattenParams(decision.template ?? decision.path, opts.params);
    const wire = this.buildRequest(method, decision, pairs, opts);
    let response: RawResponse;
    try {
      response = await this.sendAuthenticated(wire);
    } catch (err) {
      this.recordWrite(method, decision, opts.params, `error: ${(err as Error).message}`);
      throw err;
    }
    this.recordWrite(method, decision, opts.params, String(response.status));
    return this.parse(response, method, decision, opts);
  }

  /**
   * POST with a multipart body read from a local file, which is what storage upload takes. Never
   * retried, like any write. Fields come first: Proxmox reads them before spooling the file.
   */
  async upload(path: string, fields: Params, file: UploadFile, opts: RequestOptions = {}): Promise<unknown> {
    const method: Method = 'POST';
    const decision = this.prepare(method, path, { ...opts, params: fields });
    const fileName = file.filename ?? basename(file.localPath);
    const logged = { ...fields, filename: fileName };
    if (opts.dryRun || this.config.dryRun) return this.simulateWrite(method, decision, { ...opts, params: logged });

    const size = statSync(file.localPath).size;
    const boundary = `----pvemcp${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`;
    const safeName = fileName.replace(/["\r\n\\]/g, '_');
    let head = '';
    for (const [name, value] of flattenParams(decision.template ?? decision.path, fields)) {
      head += `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;
    }
    head += `--${boundary}\r\nContent-Disposition: form-data; name="${file.field ?? 'filename'}"; filename="${safeName}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    const prefix = Buffer.from(head, 'utf8');
    const suffix = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
    const wire: WireRequest = {
      method,
      url: this.urlFor(decision),
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': String(prefix.length + size + suffix.length) },
      bodyPrefix: prefix,
      bodySuffix: suffix,
      bodyStream: () => createReadStream(file.localPath),
      timeoutMs: opts.timeoutMs ?? UPLOAD_TIMEOUT_MS,
      ...(opts.signal ? { signal: opts.signal } : {}),
      label: `${method} ${decision.path}`,
    };
    let response: RawResponse;
    try {
      response = await this.sendAuthenticated(wire);
    } catch (err) {
      this.recordWrite(method, decision, logged, `error: ${(err as Error).message}`);
      throw err;
    }
    this.recordWrite(method, decision, logged, String(response.status));
    return this.parse(response, method, decision, opts);
  }

  private urlFor(decision: Decision): string {
    return `${this.base.origin}${this.base.pathname.replace(/\/$/, '')}/api2/json${decision.urlPath}`;
  }

  private buildRequest(method: Method, decision: Decision, pairs: Array<[string, string]>, opts: RequestOptions): WireRequest {
    const encoded = encodePairs(pairs);
    const wire: WireRequest = {
      method,
      url: this.urlFor(decision),
      headers: {},
      timeoutMs: opts.timeoutMs ?? this.config.timeoutMs,
      ...(opts.signal ? { signal: opts.signal } : {}),
      label: `${method} ${decision.path}`,
    };
    if (method === 'POST' || method === 'PUT') {
      wire.body = encoded;
      wire.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      wire.headers['Content-Length'] = String(Buffer.byteLength(encoded));
    } else if (encoded) {
      wire.url += `?${encoded}`;
    }
    return wire;
  }

  private simulateWrite(method: Method, decision: Decision, opts: RequestOptions): unknown {
    const params = opts.params && Object.keys(opts.params).length > 0 ? redactRequest(decision.path, opts.params) : undefined;
    opts.dryRunLog?.push({ method, path: decision.path, ...(params ? { params } : {}) });
    const endpoint = decision.template ? findEndpoint(method, decision.template) : undefined;
    // So that flows that go on to wait for a task still run: waitForTask knows this one.
    return endpoint?.returns.type === 'string' ? DRY_RUN_UPID : { dry_run: true };
  }

  private recordWrite(method: Method, decision: Decision, params: Params | undefined, status: string): void {
    if (method === 'GET') return;
    this.onWrite?.({ method, path: decision.path, ...(params ? { params: redactRequest(decision.path, params) } : {}), status: scrubText(status) });
  }

  private parse(response: RawResponse, method: Method, decision: Decision, opts: RequestOptions): unknown {
    if (response.status < 200 || response.status >= 300) this.throwForStatus(response, method, decision);
    const label = `${method} ${decision.path}`;
    if (/text\/html/i.test(response.contentType) || /^\s*<(!doctype|html)/i.test(response.body)) {
      throw new ProxmoxError('bad_response', `Proxmox answered ${label} with an HTML page instead of JSON.`, {
        hint: 'Check PROXMOX_URL: it should point at the Proxmox API, port 8006, without a reverse proxy login page in front.',
      });
    }
    const keepSecrets = this.config.allowSensitive && (opts.includeSensitive === true || decision.gate === 'sensitive' || decision.gate === 'console' || decision.returnsSecret);
    let json: { data?: unknown };
    try {
      json = response.body === '' ? {} : (JSON.parse(response.body) as { data?: unknown });
    } catch {
      // Downloads (task log, journal, report) can answer in plain text.
      if (method === 'GET') return keepSecrets ? response.body : scrubText(response.body);
      throw new ProxmoxError('bad_response', `Proxmox returned invalid JSON for ${label}.`);
    }
    if (json === null || typeof json !== 'object' || Array.isArray(json)) {
      throw new ProxmoxError('bad_response', `Proxmox returned an unexpected shape for ${label}: no data field.`);
    }
    const data = json.data ?? null;
    return keepSecrets ? data : redactResponse(decision.template ?? decision.path, data);
  }

  private throwForStatus(response: RawResponse, method: Method, decision: Decision): never {
    const { status } = response;
    const parsed = parseErrorBody(response.body);
    const reason = scrubText(response.reason ?? '').trim();
    const label = `${method} ${decision.path}`;
    const text = parsed.message ?? reason;
    const detail = text ? `: ${text}` : '';
    switch (status) {
      case 400:
        throw new ProxmoxError('validation_failed', `Proxmox rejected the parameters of ${label}${detail}`, {
          status,
          ...(parsed.errors ? { details: { fields: parsed.errors } } : {}),
          hint: 'Fix the fields named here. pve_api_describe gives the full parameter list of an endpoint.',
        });
      case 401:
        throw new ProxmoxError('auth_failed', `Proxmox rejected the credentials for ${label}${detail}`, {
          status,
          hint: 'Check the token or password, and that the user and token are enabled and not expired. Do not retry with the same credentials.',
        });
      case 403: {
        const permissions = decision.template ? findEndpoint(method, decision.template)?.permissions : undefined;
        throw new ProxmoxError('forbidden', `The API user has no permission for ${label}${detail}`, {
          status,
          hint: `The credentials are fine: this is a missing privilege. Do not retry.${permissions ? ` It needs: ${permissions}` : ''} A token with privilege separation needs its own ACL on top of the user's.`,
        });
      }
      case 404:
        throw new ProxmoxError('not_found', `${label} was not found${detail}`, { status, hint: 'The guest, node, storage or item may not exist. A list tool gives current ids.' });
      case 501:
        throw new ProxmoxError('not_supported', `This Proxmox version does not have ${label}${detail}`, { status, hint: 'Do not retry. The endpoint comes from a newer API schema. pve_get_version gives the version of this server.' });
      case 595:
      case 596:
        throw new ProxmoxError('node_unreachable', `The API could not reach the node for ${label}${detail}`, { status, hint: 'The node may be down or out of quorum. pve_list_nodes shows which nodes are online.' });
      default: {
        if (status === 500 && /\block|locked\b/i.test(text)) {
          throw new ProxmoxError('guest_locked', `The guest or its configuration is locked for ${label}${detail}`, {
            status,
            hint: 'Another task (backup, migration, snapshot) may hold the lock: wait for it, and look at pve_list_node_tasks. Do not remove a lock you did not create.',
          });
        }
        throw new ProxmoxError('upstream_error', `Proxmox answered ${label} with HTTP ${status}${detail}`, {
          status,
          ...(parsed.errors ? { details: { fields: parsed.errors } } : {}),
          ...(status >= 500 ? { hint: 'A server-side error. The node journal (pve_get_node_journal) may tell why.' } : {}),
        });
      }
    }
  }

  /** Adds credentials. With tickets, a 401 is safe to retry once: nothing was run. */
  private async sendAuthenticated(wire: WireRequest): Promise<RawResponse> {
    if (this.tokenHeader) {
      return this.send({ ...wire, headers: { ...wire.headers, Authorization: this.tokenHeader } });
    }
    const first = await this.send({ ...wire, headers: { ...wire.headers, ...this.ticketHeaders(await this.currentTicket(), wire.method) } });
    if (first.status !== 401) return first;
    this.ticket = undefined;
    return this.send({ ...wire, headers: { ...wire.headers, ...this.ticketHeaders(await this.currentTicket(), wire.method) } });
  }

  private ticketHeaders(ticket: Ticket, method: Method): Record<string, string> {
    return {
      Cookie: `PVEAuthCookie=${encodeURIComponent(ticket.ticket)}`,
      ...(method === 'GET' ? {} : { CSRFPreventionToken: ticket.csrf }),
    };
  }

  private currentTicket(): Promise<Ticket> {
    if (this.ticket && Date.now() - this.ticket.at < TICKET_RENEW_MS) return Promise.resolve(this.ticket);
    this.ticketPromise ??= this.login()
      .then((ticket) => {
        this.ticket = ticket;
        return ticket;
      })
      .finally(() => {
        this.ticketPromise = undefined;
      });
    return this.ticketPromise;
  }

  private async login(): Promise<Ticket> {
    const { username, password } = this.config;
    if (!username || !password) {
      throw new ProxmoxError('config_error', `Instance "${this.config.name}" has no credentials.`, { hint: 'Set PROXMOX_TOKEN, or PROXMOX_USERNAME and PROXMOX_PASSWORD.' });
    }
    const body = encodePairs([['username', username], ['password', password]]);
    const response = await this.send({
      method: 'POST',
      url: `${this.base.origin}${this.base.pathname.replace(/\/$/, '')}/api2/json/access/ticket`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(Buffer.byteLength(body)) },
      body,
      timeoutMs: this.config.timeoutMs,
      label: 'POST /access/ticket',
    });
    if (response.status === 401 || response.status === 403) {
      throw new ProxmoxError('auth_failed', `Proxmox refused the login of ${username}.`, {
        status: response.status,
        hint: 'Check PROXMOX_USERNAME (with its realm, such as root@pam) and PROXMOX_PASSWORD. Do not retry: repeated failures can lock the account.',
      });
    }
    if (response.status < 200 || response.status >= 300) {
      throw new ProxmoxError('upstream_error', `Login to Proxmox failed with HTTP ${response.status}: ${scrubText(response.reason ?? '')}`, { status: response.status });
    }
    let data: { ticket?: unknown; CSRFPreventionToken?: unknown; NeedTFA?: unknown } | undefined;
    try {
      data = (JSON.parse(response.body) as { data?: typeof data }).data;
    } catch {
      /* handled just below */
    }
    if (data?.NeedTFA) {
      throw new ProxmoxError('auth_failed', `The account ${username} requires two-factor authentication, which a password login here cannot complete.`, {
        hint: 'Use an API token instead (PROXMOX_TOKEN): tokens are not subject to TFA.',
      });
    }
    if (typeof data?.ticket !== 'string' || typeof data.CSRFPreventionToken !== 'string') {
      throw new ProxmoxError('bad_response', 'The login answer has no ticket.', { hint: 'Check PROXMOX_URL.' });
    }
    return { ticket: data.ticket, csrf: data.CSRFPreventionToken, at: Date.now() };
  }

  private async send(wire: WireRequest): Promise<RawResponse> {
    await this.acquire();
    try {
      // Only reads are retried: repeating a write that may have gone through is not safe.
      const attempts = wire.method === 'GET' ? MAX_RETRIES + 1 : 1;
      for (let attempt = 1; ; attempt++) {
        try {
          const response = await this.sendOnce(wire);
          if (attempt < attempts && RETRYABLE_STATUS.has(response.status)) {
            await delay(attempt * 300);
            continue;
          }
          return response;
        } catch (err) {
          const code = err instanceof ProxmoxError ? (err.details as { code?: string } | undefined)?.code : undefined;
          if (attempt >= attempts || code !== 'ECONNRESET') throw err;
          await delay(attempt * 300);
        }
      }
    } finally {
      this.release();
    }
  }

  private sendOnce(wire: WireRequest): Promise<RawResponse> {
    const headers: Record<string, string> = { Accept: 'application/json', ...wire.headers };
    const transport = this.base.protocol === 'https:' ? https : http;
    // A kept-alive socket may have died unnoticed, and a write cannot be retried: writes get a new one.
    const agent = wire.method === 'GET' ? this.agents.keepAlive : this.agents.single;

    return new Promise<RawResponse>((resolve, reject) => {
      const req = transport.request(wire.url, { method: wire.method, headers, agent, ...(wire.signal ? { signal: wire.signal } : {}) }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy(new ProxmoxError('bad_response', `The answer to ${wire.label} is larger than ${MAX_RESPONSE_BYTES / 1048576} MiB and was dropped.`));
            return;
          }
          chunks.push(c);
        });
        res.on('error', (e) => reject(this.networkError(e, wire.label)));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            reason: res.statusMessage ?? '',
            contentType: String(res.headers['content-type'] ?? ''),
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      });
      req.setTimeout(wire.timeoutMs, () => {
        req.destroy(new ProxmoxError('timeout', `Proxmox did not answer ${wire.label} within ${Math.round(wire.timeoutMs / 1000)} s.`, {
          hint: wire.method === 'GET' ? 'The node may be overloaded. Try a narrower request.' : 'The change may or may not have gone through: check the state before repeating it.',
        }));
      });
      req.on('error', (e) => reject(this.networkError(e, wire.label)));
      if (wire.bodyStream) {
        if (wire.bodyPrefix) req.write(wire.bodyPrefix);
        const stream = wire.bodyStream();
        stream.on('error', (e: Error) => req.destroy(e));
        stream.on('end', () => req.end(wire.bodySuffix));
        stream.pipe(req, { end: false });
        return;
      }
      if (wire.body !== undefined) req.write(wire.body);
      req.end();
    });
  }

  private networkError(err: Error & { code?: string }, label: string): ProxmoxError {
    if (err instanceof ProxmoxError) return err;
    const code = err.code ?? '';
    if (TLS_ERROR_CODES.test(code)) {
      return new ProxmoxError('tls_error', `The TLS certificate of ${this.config.url} was refused (${code}).`, {
        hint: 'Proxmox uses a self-signed certificate by default. Set PROXMOX_FINGERPRINT to its sha256 (pvenode cert info on the node shows it) or point PROXMOX_CA_FILE at the CA to keep verification on. PROXMOX_VERIFY_SSL=false is for a trusted network only.',
      });
    }
    return new ProxmoxError('unreachable', `Cannot reach Proxmox for ${label} (${code || err.message}).`, {
      hint: 'Check the URL and port (8006 by default), and that this host may reach it.',
      details: { code },
    });
  }

  private async acquire(): Promise<void> {
    if (this.active < MAX_CONCURRENCY) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve));
  }

  private release(): void {
    const next = this.waiting.shift();
    if (next) next();
    else this.active--;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
