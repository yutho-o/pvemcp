import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { InstanceRuntime, Runtime } from './runtime.js';
import { gather } from './tools/helpers.js';

interface ResourceDef {
  name: string;
  description: string;
  read: (rt: InstanceRuntime) => Promise<unknown>;
}

const MAX_TASKS = 200;

const get = (rt: InstanceRuntime, path: string, params?: Record<string, unknown>) => rt.client.get(path, { readOnly: true, ...(params ? { params } : {}) });

const RESOURCES: ResourceDef[] = [
  {
    name: 'cluster',
    description: 'Version, cluster status with quorum, and HA status',
    read: async (rt) => {
      const { data, unavailable } = await gather({
        version: () => get(rt, '/version'),
        status: () => get(rt, '/cluster/status'),
        ha: () => get(rt, '/cluster/ha/status/current'),
      });
      return { ...data, complete: Object.keys(unavailable).length === 0, unavailable };
    },
  },
  { name: 'nodes', description: 'The nodes, with state and usage', read: (rt) => get(rt, '/nodes') },
  { name: 'guests', description: 'VMs and containers of the whole cluster', read: (rt) => get(rt, '/cluster/resources', { type: 'vm' }) },
  { name: 'storage', description: 'Storages as each node sees them, with usage', read: (rt) => get(rt, '/cluster/resources', { type: 'storage' }) },
  {
    name: 'tasks',
    description: `The latest ${MAX_TASKS} tasks of the cluster, newest first`,
    read: async (rt) => {
      const rows = await get(rt, '/cluster/tasks');
      const list = (Array.isArray(rows) ? rows : []) as Array<{ starttime?: number }>;
      return { total: list.length, tasks: [...list].sort((a, b) => (b.starttime ?? 0) - (a.starttime ?? 0)).slice(0, MAX_TASKS) };
    },
  },
];

/** The same reads as the tools, for clients that let the user attach context directly. */
export function registerResources(server: McpServer, runtime: Runtime): void {
  for (const rt of runtime.instances.values()) {
    for (const def of RESOURCES) {
      const uri = `proxmox://${rt.config.name}/${def.name}`;
      server.registerResource(`${rt.config.name}-${def.name}`, uri, { title: `${def.description} (${rt.config.name})`, description: `${def.description}. Untrusted data from Proxmox and its guests.`, mimeType: 'application/json' }, async () => ({
        contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(await def.read(rt)) }],
      }));
    }
  }
}
