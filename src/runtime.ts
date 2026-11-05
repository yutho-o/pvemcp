import { AsyncLocalStorage } from 'node:async_hooks';
import { appendFile, appendFileSync } from 'node:fs';
import type { InstanceConfig, ServerConfig } from './config.js';
import { ProxmoxClient, type WriteRecord } from './proxmox/client.js';
import { ProxmoxError } from './proxmox/errors.js';
import { NodeResolver } from './proxmox/nodes.js';
import { createSshTransport, type SshTransport, type SshTransportFactory } from './ssh/index.js';

export type { WriteRecord } from './proxmox/client.js';

export interface InstanceRuntime {
  config: InstanceConfig;
  client: ProxmoxClient;
  nodes: NodeResolver;
  /** Lazy: nothing connects, or is even set up, before the first SSH command. */
  ssh: () => SshTransport;
}

export interface RuntimeOptions {
  /** For tests, and for anything that wants its own transport. */
  sshTransport?: SshTransportFactory;
}

export type AuditEntry = Record<string, unknown>;
export type Notify = (level: 'info' | 'warning' | 'error', message: string) => void;
export type ShutdownHook = () => Promise<unknown> | unknown;

const SHUTDOWN_TIMEOUT_MS = 15_000;

/**
 * What outlives a single MCP connection: API clients, SSH connections and interactive
 * sessions. In HTTP mode each request has its own MCP server over this.
 */
export class Runtime {
  readonly instances = new Map<string, InstanceRuntime>();
  private readonly listeners = new Set<Notify>();
  private readonly writeScope = new AsyncLocalStorage<WriteRecord[]>();
  private readonly shared = new Map<string, unknown>();
  private readonly shutdownHooks = new Set<ShutdownHook>();
  private readonly transports = new Map<string, SshTransport>();

  constructor(
    readonly config: ServerConfig,
    options: RuntimeOptions = {},
  ) {
    if (config.auditLog) this.assertAuditWritable(config.auditLog);
    const factory = options.sshTransport ?? createSshTransport;
    for (const [name, instance] of config.instances) {
      const entry: { nodes?: NodeResolver } = {};
      const client = new ProxmoxClient(instance, config.unblocked, (record) => {
        entry.nodes?.invalidate();
        this.onWrite(name, record);
      });
      const apiHost = new URL(instance.url).hostname.replace(/^\[|\]$/g, '');
      const nodes = new NodeResolver(
        { get: (path, opts) => client.get(path, { ...opts, readOnly: true }) },
        { apiHost, sshNodes: instance.ssh.nodes, ...(instance.defaultNode ? { defaultNode: instance.defaultNode } : {}) },
      );
      entry.nodes = nodes;
      const ssh = () => {
        let transport = this.transports.get(name);
        if (!transport) {
          transport = factory(instance, nodes);
          this.transports.set(name, transport);
        }
        return transport;
      };
      this.instances.set(name, { config: instance, client, nodes, ssh });
    }
  }

  instance(name?: string): InstanceRuntime {
    const key = name ?? this.config.defaultInstance;
    const instance = this.instances.get(key);
    if (!instance) {
      throw new ProxmoxError('invalid_input', `Unknown instance "${key}".`, { hint: `Known instances: ${[...this.instances.keys()].join(', ')}` });
    }
    return instance;
  }

  /**
   * One value per key for the life of the server, for state that has to survive stateless HTTP
   * requests, such as SSH sessions. Use onShutdown to clean it up.
   */
  state<T>(key: string, create: () => T): T {
    if (!this.shared.has(key)) this.shared.set(key, create());
    return this.shared.get(key) as T;
  }

  onShutdown(hook: ShutdownHook): () => void {
    this.shutdownHooks.add(hook);
    return () => this.shutdownHooks.delete(hook);
  }

  addListener(listener: Notify): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Runs a tool while collecting the requests that change something, for the audit log. */
  collectWrites<T>(writes: WriteRecord[], run: () => Promise<T>): Promise<T> {
    return this.writeScope.run(writes, run);
  }

  /** What a tool is doing that is not an HTTP write: SSH commands. */
  recordWrite(instance: string, entry: WriteRecord): void {
    this.onWrite(instance, entry);
  }

  audit(entry: AuditEntry): void {
    if (!this.config.auditLog) return;
    appendFile(this.config.auditLog, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, (err) => {
      if (err) console.error(`[pvemcp] could not write the audit log: ${err.message}`);
    });
  }

  notify(level: 'info' | 'warning' | 'error', message: string): void {
    console.error(`[pvemcp] ${level}: ${message}`);
    for (const listener of this.listeners) listener(level, message);
  }

  async shutdown(): Promise<void> {
    const timeout = new Promise<void>((resolve) => setTimeout(resolve, SHUTDOWN_TIMEOUT_MS).unref());
    const closing = [...this.shutdownHooks].map(async (hook) => hook());
    for (const transport of this.transports.values()) closing.push(Promise.resolve().then(() => transport.close()));
    await Promise.race([Promise.allSettled(closing), timeout]);
    this.shutdownHooks.clear();
    this.transports.clear();
    for (const instance of this.instances.values()) instance.client.close();
  }

  private onWrite(instance: string, entry: WriteRecord): void {
    const scope = this.writeScope.getStore();
    if (scope) scope.push(entry);
    // Outside a tool call, this is something running on its own.
    else this.audit({ instance, tool: '(background)', writes: [entry] });
  }

  /** A log that cannot be written should stop the server now, not fail unnoticed later. */
  private assertAuditWritable(path: string): void {
    try {
      appendFileSync(path, '');
    } catch (err) {
      throw new ProxmoxError('config_error', `PROXMOX_AUDIT_LOG: cannot write to ${path}: ${(err as Error).message}`);
    }
  }
}
