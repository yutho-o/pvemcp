import { ProxmoxError } from './errors.js';
import type { TaskApi } from './tasks.js';

export type GuestType = 'qemu' | 'lxc';

export interface GuestLocation {
  vmid: number;
  node: string;
  type: GuestType;
  name?: string;
  status: string;
  template?: boolean;
  tags?: string;
}

export interface NodeResolverOptions {
  defaultNode?: string;
  /** Host of the API URL, the last resort when reaching a node by SSH. */
  apiHost: string;
  /** Node name to address, from PROXMOX_SSH_NODES. */
  sshNodes?: Readonly<Record<string, string>>;
  cacheMs?: number;
}

const GUEST_CACHE_MS = 10_000;

interface ResourceRow {
  type?: string;
  vmid?: number;
  node?: string;
  name?: string;
  status?: string;
  template?: number | boolean;
  tags?: string;
}

/** Finds where guests live, so that agents can speak in vmids and not have to know the node. */
export class NodeResolver {
  private guests?: { at: number; rows: Map<number, GuestLocation> };

  constructor(
    private readonly api: TaskApi,
    private readonly options: NodeResolverOptions,
  ) {}

  /** Called after every write: the guest may have moved, or may be gone. */
  invalidate(): void {
    this.guests = undefined;
  }

  async listGuests(): Promise<GuestLocation[]> {
    return [...(await this.guestMap()).values()];
  }

  private async guestMap(): Promise<Map<number, GuestLocation>> {
    const ttl = this.options.cacheMs ?? GUEST_CACHE_MS;
    if (this.guests && Date.now() - this.guests.at < ttl) return this.guests.rows;
    const rows = await this.api.get('/cluster/resources', { params: { type: 'vm' } });
    const map = new Map<number, GuestLocation>();
    for (const row of (Array.isArray(rows) ? rows : []) as ResourceRow[]) {
      if (typeof row.vmid !== 'number' || typeof row.node !== 'string') continue;
      map.set(row.vmid, {
        vmid: row.vmid,
        node: row.node,
        type: row.type === 'lxc' ? 'lxc' : 'qemu',
        status: row.status ?? 'unknown',
        ...(row.name ? { name: row.name } : {}),
        ...(row.template ? { template: true } : {}),
        ...(row.tags ? { tags: row.tags } : {}),
      });
    }
    this.guests = { at: Date.now(), rows: map };
    return map;
  }

  async resolveGuest(vmid: number): Promise<GuestLocation> {
    const cached = this.guests?.rows.get(vmid);
    const fresh = this.guests && Date.now() - this.guests.at < (this.options.cacheMs ?? GUEST_CACHE_MS);
    if (cached && fresh) return cached;
    // A miss in a live cache may just be a guest created a moment ago: look again.
    if (fresh) this.invalidate();
    const found = (await this.guestMap()).get(vmid);
    if (!found) {
      throw new ProxmoxError('not_found', `No guest with vmid ${vmid} in this cluster.`, { hint: 'pve_list_cluster_resources lists all guests. A token only sees the guests it has VM.Audit on.' });
    }
    return found;
  }

  async listNodes(): Promise<string[]> {
    const rows = await this.api.get('/nodes');
    return ((Array.isArray(rows) ? rows : []) as Array<{ node?: unknown }>).map((r) => r.node).filter((n): n is string => typeof n === 'string').sort();
  }

  /** PROXMOX_DEFAULT_NODE, else the only node there is. With several, an agent has to choose. */
  async defaultNode(): Promise<string> {
    if (this.options.defaultNode) return this.options.defaultNode;
    const nodes = await this.listNodes();
    if (nodes.length === 1) return nodes[0]!;
    if (nodes.length === 0) throw new ProxmoxError('not_found', 'This API token sees no node in the cluster.', { hint: 'It may lack Sys.Audit on /nodes. Give the node name explicitly, or set PROXMOX_DEFAULT_NODE.' });
    throw new ProxmoxError('invalid_input', `This cluster has several nodes, so "node" is required: ${nodes.join(', ')}.`, { hint: 'Pass node, or have the operator set PROXMOX_DEFAULT_NODE.', details: { nodes } });
  }

  /** PROXMOX_SSH_NODES, else the address the cluster reports, else the API host on a single node. */
  async sshHost(node: string): Promise<string> {
    const pinned = this.options.sshNodes?.[node];
    if (pinned) return pinned;
    const rows = await this.api.get('/cluster/status').catch(() => undefined);
    const entries = (Array.isArray(rows) ? rows : []) as Array<{ type?: string; name?: string; ip?: string }>;
    const entry = entries.find((r) => r.type === 'node' && r.name === node);
    if (entry?.ip) return entry.ip;
    const nodeCount = entries.filter((r) => r.type === 'node').length;
    if (nodeCount <= 1) return this.options.apiHost;
    throw new ProxmoxError('invalid_input', `No address known for node "${node}".`, { hint: 'The operator can set PROXMOX_SSH_NODES, such as pve1=10.0.0.1,pve2=10.0.0.2.' });
  }
}
