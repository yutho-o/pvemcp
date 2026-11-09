import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { afterEach, describe, expect, it } from 'vitest';
import { catalog, findEndpoint, templateParams, type CatalogEndpoint, type CatalogParam } from './catalog.js';
import { FAKE_PASSWORD, FAKE_TOKEN, FAKE_USER } from './fake-pve.js';
import { ALL_GATES, closeAll, connect, listTools, spawnServer } from './harness.js';

afterEach(closeAll);

/** What cannot be a tool, and why: src/tools/endpoints.rs holds the same list. */
const EXCLUDED_ENDPOINTS: Readonly<Record<string, string>> = {
  'GET /nodes/{node}/vncwebsocket': 'Websocket console: a tool call cannot hold it.',
  'GET /nodes/{node}/qemu/{vmid}/vncwebsocket': 'Websocket console: a tool call cannot hold it.',
  'GET /nodes/{node}/lxc/{vmid}/vncwebsocket': 'Websocket console: a tool call cannot hold it.',
  'GET /nodes/{node}/qemu/{vmid}/mtunnelwebsocket': 'Migration tunnel, internal to remote_migrate.',
  'GET /nodes/{node}/lxc/{vmid}/mtunnelwebsocket': 'Migration tunnel, internal to remote_migrate.',
  'POST /nodes/{node}/qemu/{vmid}/mtunnel': 'Migration tunnel, internal to remote_migrate.',
  'POST /nodes/{node}/lxc/{vmid}/mtunnel': 'Migration tunnel, internal to remote_migrate.',
  'POST /nodes/{node}/execute': 'Runs a batch of API calls, which would bypass the policy.',
  'GET /access/ticket': 'Dummy endpoint for the login form: authentication is handled by the client.',
  'POST /access/ticket': 'Authentication is handled by the client.',
  'POST /access/openid/login': 'Interactive browser login.',
  'POST /nodes/{node}/storage/{storage}/upload': 'Needs a multipart body: pve_upload_to_storage is the tool for it.',
};
const UPLOAD_ENDPOINT = 'POST /nodes/{node}/storage/{storage}/upload';

/** One method of the API as pve_api_search describes it: the gate and tool the server gives it. */
interface ApiRow {
  method: string;
  path: string;
  gate: string;
  destructive?: boolean;
  domain: string;
  tool: string | null;
}

/** What the binary says of every API method and every tool, with every gate open. Read once. */
async function whatTheServerSays(): Promise<{ rows: ApiRow[]; tools: Tool[] }> {
  const { client } = await spawnServer({ PROXMOX_URL: 'https://127.0.0.1:8006', PROXMOX_TOKEN: FAKE_TOKEN, ...ALL_GATES });
  const rows: ApiRow[] = [];
  // "pve" is in the name of every tool, so it is in every haystack.
  for (let offset: number | undefined = 0; offset !== undefined; ) {
    const res = (await client.callTool({ name: 'pve_api_search', arguments: { query: 'pve', page_limit: 200, page_offset: offset } })) as { content: Array<{ text: string }> };
    const data = JSON.parse(res.content[0]!.text) as { rows: ApiRow[]; has_more: boolean; next_offset?: number };
    rows.push(...data.rows);
    offset = data.has_more ? data.next_offset : undefined;
  }
  const { tools } = await client.listTools();
  await client.close();
  return { rows, tools };
}

const announced = await whatTheServerSays();
const keyOf = (e: { method: string; path: string }) => `${e.method} ${e.path}`;
const rowOf = new Map(announced.rows.map((r) => [keyOf(r), r]));
function toolName(method: string, path: string): string {
  const tool = rowOf.get(`${method} ${path}`)?.tool;
  if (!tool) throw new Error(`No tool for ${method} ${path}`);
  return tool;
}
const generatedEndpoints = catalog.endpoints.filter((e) => !EXCLUDED_ENDPOINTS[keyOf(e)]);
/** The tools made from the catalog: one per method, and the upload. */
const generatedNames = new Set(announced.rows.flatMap((r) => (r.tool ? [r.tool] : [])));
const listed = new Map(announced.tools.map((t) => [t.name, t]));
const byList = new Map(listTools(ALL_GATES).map((t) => [t.name, t]));

describe('the catalog', () => {
  it('holds every method of the schema', () => {
    expect(catalog.endpoints).toHaveLength(680);
    expect(catalog.counts).toEqual({ total: 680, GET: 342, POST: 175, PUT: 84, DELETE: 79 });
    expect(new Set(catalog.endpoints.map(keyOf)).size).toBe(680);
    expect(catalog.source).toContain('apidoc.js');
    expect(catalog.schema_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('keeps property strings readable, and the facts established from the schema', () => {
    const create = findEndpoint('POST', '/nodes/{node}/qemu')!;
    expect(create.params['net[n]']!.propertyString).toBe(true);
    expect(create.params['net[n]']!.description).toContain('bridge=');
    expect(create.params.efidisk0).toBeDefined();
    expect(findEndpoint('PUT', '/access/password')!.allowtoken).toBe(false);
    expect(findEndpoint('GET', '/nodes/{node}/tasks/{upid}/log')!.download_allowed).toBe(true);
    // Placeholders the schema does not declare still come from the template.
    const undeclared = '/cluster/sdn/prefix-lists/{id}/entries/{url_seq}';
    expect(findEndpoint('PUT', undeclared)!.params.url_seq).toBeUndefined();
    expect(templateParams(undeclared)).toEqual(['id', 'url_seq']);
    expect(findEndpoint('POST', '/cluster/sdn/fabrics/fabric')!.params.protocol?.enum).toBeDefined();
  });
});

describe('coverage of the API', () => {
  it('gives every catalog method a tool, except the short explicit list', () => {
    expect(Object.keys(EXCLUDED_ENDPOINTS)).toHaveLength(12);
    for (const key of Object.keys(EXCLUDED_ENDPOINTS)) {
      const [method, path] = key.split(' ') as [string, string];
      expect(findEndpoint(method, path), key).toBeDefined();
      expect(EXCLUDED_ENDPOINTS[key]!.length, key).toBeGreaterThan(10);
    }
    expect(announced.rows).toHaveLength(680);
    expect(generatedEndpoints).toHaveLength(668);
    for (const e of generatedEndpoints) expect(listed.has(toolName(e.method, e.path)), keyOf(e)).toBe(true);
    // The server gives no tool to the excluded methods, other than the upload.
    for (const key of Object.keys(EXCLUDED_ENDPOINTS)) expect(rowOf.get(key)!.tool, key).toBe(key === UPLOAD_ENDPOINT ? 'pve_upload_to_storage' : null);
    expect(generatedNames.size).toBe(669);
  });

  it('leaves out only what the policy blocks, and the upload that has its own tool', () => {
    for (const key of Object.keys(EXCLUDED_ENDPOINTS)) expect(rowOf.get(key)!.gate, key).toBe(key === UPLOAD_ENDPOINT ? 'write' : 'blocked');
    expect(listed.has('pve_upload_to_storage')).toBe(true);
    expect(generatedEndpoints.filter((e) => rowOf.get(keyOf(e))!.gate === 'blocked').map(keyOf)).toEqual([]);
  });

  it('takes gate, destructiveness and read-only from the policy, for every tool', () => {
    for (const e of generatedEndpoints) {
      const row = rowOf.get(keyOf(e))!;
      const name = toolName(e.method, e.path);
      const tool = listed.get(name)!;
      expect(byList.get(name)!.gate, keyOf(e)).toBe(row.gate);
      expect(byList.get(name)!.domain, keyOf(e)).toBe(row.domain);
      // "Destructive." is the fact of the policy; "Destructive with some argument values" is another one.
      expect(/\bDestructive\.[\s\]]/.test(tool.description ?? ''), keyOf(e)).toBe(row.destructive === true);
      if (row.destructive) expect(tool.annotations?.destructiveHint, keyOf(e)).toBe(true);
      expect(tool.annotations?.readOnlyHint, keyOf(e)).toBe(e.method === 'GET');
      expect(tool.description, keyOf(e)).toContain(keyOf(e));
    }
  });
});

describe('tool names', () => {
  it('are unique across all tools, and fit the format', () => {
    const names = listTools(ALL_GATES).map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name).toMatch(/^pve_[a-z0-9_]{1,60}$/);
  });

  // That no override names a method that does not exist is checked in src/tools/naming.rs.

  it('read as intended on the examples of the design, and on what the rules would name badly', () => {
    const expected: Array<[string, string, string]> = [
      ['GET', '/nodes/{node}/qemu', 'pve_list_vms'],
      ['POST', '/nodes/{node}/qemu', 'pve_create_vm'],
      ['GET', '/nodes/{node}/lxc', 'pve_list_lxc'],
      ['GET', '/nodes/{node}/lxc/{vmid}/status/current', 'pve_get_lxc_status'],
      ['GET', '/nodes/{node}/qemu/{vmid}/config', 'pve_get_vm_config'],
      ['PUT', '/nodes/{node}/qemu/{vmid}/config', 'pve_update_vm_config'],
      ['POST', '/nodes/{node}/qemu/{vmid}/config', 'pve_update_vm_config_async'],
      ['GET', '/cluster/sdn/vnets', 'pve_list_sdn_vnets'],
      ['DELETE', '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}', 'pve_delete_vm_snapshot'],
      ['POST', '/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback', 'pve_rollback_vm_snapshot'],
      ['POST', '/nodes/{node}/lxc/{vmid}/status/start', 'pve_start_lxc'],
      ['POST', '/nodes/{node}/qemu/{vmid}/clone', 'pve_clone_vm'],
      ['POST', '/nodes/{node}/qemu/{vmid}/migrate', 'pve_migrate_vm'],
      ['GET', '/nodes/{node}/qemu/{vmid}/migrate', 'pve_check_vm_migration'],
      ['DELETE', '/nodes/{node}/tasks/{upid}', 'pve_stop_task'],
      ['GET', '/nodes/{node}/qemu/{vmid}', 'pve_index_vm'],
      ['POST', '/nodes/{node}/status', 'pve_reboot_or_shutdown_node'],
      ['PUT', '/nodes/{node}/network', 'pve_apply_network_changes'],
      ['DELETE', '/nodes/{node}/network', 'pve_revert_network_changes'],
      ['POST', '/nodes/{node}/vzdump', 'pve_run_backup'],
      ['GET', '/cluster/nextid', 'pve_get_next_vmid'],
      ['DELETE', '/cluster/config/nodes/{node}', 'pve_remove_cluster_node'],
      ['GET', '/access/domains', 'pve_list_realms'],
    ];
    for (const [method, path, name] of expected) expect(toolName(method, path), `${method} ${path}`).toBe(name);
  });
});

describe('generated input', () => {
  const schema = (name: string) => listed.get(name)!.inputSchema as { properties: Record<string, { description?: string }>; required?: string[] };
  const props = (name: string) => schema(name).properties;
  const optional = (name: string, arg: string) => {
    expect(props(name), `${name} ${arg}`).toHaveProperty([arg]);
    return !(schema(name).required ?? []).includes(arg);
  };

  it('leaves node out only where the server can find it', () => {
    expect(optional('pve_start_vm', 'node')).toBe(true);
    expect(optional('pve_start_vm', 'vmid')).toBe(false);
    expect(optional('pve_list_vms', 'node')).toBe(true);
    expect(optional('pve_get_node_status', 'node')).toBe(true);
    // Here it names the node to take out of the cluster: a default would be a disaster.
    expect(optional('pve_remove_cluster_node', 'node')).toBe(false);
    expect(optional('pve_add_cluster_node', 'node')).toBe(false);
  });

  it('keeps placeholders the schema does not declare', () => {
    expect(optional('pve_update_ha_rule', 'rule')).toBe(false);
    expect(optional('pve_update_sdn_prefix_list_entry', 'url_seq')).toBe(false);
  });

  it('names indexed params without the [n], and not over a plain one of the same name', () => {
    const vm = props('pve_create_vm');
    expect(optional('pve_create_vm', 'net')).toBe(true);
    expect(vm['net[n]']).toBeUndefined();
    expect(vm.net!.description).toContain('{"0": "virtio,bridge=vmbr0"}');
    expect(vm.numa).toBeDefined();
    expect(vm.numa_n).toBeDefined();
  });

  it('offers paging on lists only, and wait on what can start a task', () => {
    expect(props('pve_list_vms').page_limit).toBeDefined();
    expect(props('pve_list_node_tasks').page_offset).toBeDefined();
    expect(props('pve_get_vm_config').page_limit).toBeUndefined();
    expect(props('pve_start_vm').wait).toBeDefined();
    expect(props('pve_start_vm').wait_seconds).toBeDefined();
    expect(props('pve_update_vm_config').wait).toBeUndefined();
    expect(props('pve_list_vms').wait).toBeUndefined();
  });
});

describe('over a real MCP client', () => {
  it('lists every tool with a valid schema, and the hints of its policy', async () => {
    const { client } = await connect({ env: ALL_GATES });
    const { tools } = await client.listTools();
    const shown = new Map(tools.map((t) => [t.name, t]));
    expect(shown.size).toBe(tools.length);
    for (const name of generatedNames) expect(shown.has(name), name).toBe(true);

    const ajv = new AjvJsonSchemaValidator();
    for (const t of tools) {
      expect(t.inputSchema.type, t.name).toBe('object');
      expect(t.description?.length ?? 0, t.name).toBeGreaterThan(5);
      expect(t.title, t.name).toBeTruthy();
      for (const key of Object.keys(t.inputSchema.properties ?? {})) expect(key, t.name).toMatch(/^[a-zA-Z0-9_.-]{1,64}$/);
      for (const key of t.inputSchema.required ?? []) expect(t.inputSchema.properties, t.name).toHaveProperty([key]);
      expect(() => ajv.getValidator(t.inputSchema), t.name).not.toThrow();
    }

    for (const e of generatedEndpoints) {
      const t = shown.get(toolName(e.method, e.path))!;
      expect(t.annotations?.readOnlyHint, keyOf(e)).toBe(e.method === 'GET');
      expect('dry_run' in (t.inputSchema.properties ?? {}), keyOf(e)).toBe(e.method !== 'GET');
      if (rowOf.get(keyOf(e))!.destructive) expect(t.annotations?.destructiveHint, keyOf(e)).toBe(true);
    }
  });

  it('shows few tools by default: gates and toolsets hide the rest', async () => {
    const generated = (names: string[]) => names.filter((n) => generatedNames.has(n));
    const readOnly = await connect();
    const names = await readOnly.toolNames();
    // Counts of generated tools only, so that curated tools can come and go.
    expect(generated(names)).toHaveLength(215);
    expect(names).toContain('pve_mcp_info');
    expect(names).toContain('pve_list_vms');
    expect(names).toContain('pve_api_read');
    for (const hidden of ['pve_start_vm', 'pve_api_write', 'pve_list_sdn_vnets', 'pve_list_ceph_pools', 'pve_exec_in_vm', 'pve_read_vm_file']) expect(names).not.toContain(hidden);

    const writes = generated(await (await connect({ env: { PROXMOX_ALLOW_WRITES: 'true' } })).toolNames());
    expect(writes).toContain('pve_start_vm');
    expect(writes).not.toContain('pve_create_user');
    expect(writes).toHaveLength(323);

    const everything = generated(await (await connect({ env: ALL_GATES })).toolNames());
    expect(everything).toHaveLength(669);
  });

  it('filters by toolset, and refuses an unknown one', async () => {
    const vm = await connect({ env: { PROXMOX_TOOLSETS: 'vm' } });
    const names = await vm.toolNames();
    expect(names).toContain('pve_mcp_info');
    expect(names).toContain('pve_get_vm_config');
    expect(names).not.toContain('pve_list_lxc');
    expect(names).not.toContain('pve_list_nodes');
    // A guest's firewall belongs to the firewall domain, and is also needed by who manages VMs.
    expect(names).toContain('pve_list_vm_firewall_rules');

    await expect(connect({ env: { PROXMOX_TOOLSETS: 'nonsense' } })).rejects.toThrow(/unknown toolset/);
  });
});

/** A value the fake's checks accept, from what the catalog says of the parameter. */
function valueFor(name: string, param: CatalogParam | undefined, template: string): unknown {
  if (param?.enum) return param.type === 'integer' ? Number(param.enum[0]) : param.enum[0];
  if (name === 'node') return 'pve1';
  if (name === 'vmid') return template.includes('/lxc') ? 101 : 100;
  if (name === 'upid') return 'UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:';
  if (name === 'volume') return 'local:iso/debian.iso';
  if (name === 'cidr') return '10.0.0.0/24';
  if (!param) return 'x1';
  switch (param.type) {
    case 'boolean':
      return true;
    case 'integer':
    case 'number':
      return param.minimum ?? 1;
    case 'array':
      return ['x'];
    default:
      return 'x'.repeat(Math.max(param.minLength ?? 1, 2));
  }
}

describe('every method, end to end', () => {
  it('reaches the right endpoint with what its tool sends, including the methods that refuse tokens', async () => {
    // A password login: it can call everything, and checks the CSRF header on all writes.
    const { call, fake } = await connect({
      fake: { permissive: true },
      env: { ...ALL_GATES, PROXMOX_TOKEN: undefined, PROXMOX_USERNAME: FAKE_USER, PROXMOX_PASSWORD: FAKE_PASSWORD, PROXMOX_TASK_WAIT_SECONDS: '0' },
    });
    const failures: string[] = [];
    for (const e of generatedEndpoints as CatalogEndpoint[]) {
      const args: Record<string, unknown> = {};
      for (const p of templateParams(e.path)) args[p] = valueFor(p, e.params[p], e.path);
      for (const [name, param] of Object.entries(e.params)) {
        if (!param.optional && !name.endsWith('[n]') && !(name in args)) args[name] = valueFor(name, param, e.path);
      }
      const before = fake.find(e.method, e.path).length;
      const res = await call(toolName(e.method, e.path), args);
      const seen = fake.find(e.method, e.path);
      const reached = seen.length > before;
      // The fake models some guests' state, so an honest refusal from "Proxmox" is fine here.
      const refusedByUs = res.isError && !['upstream_error', 'task_failed', 'guest_locked'].includes(res.data.error_type);
      if (!reached || refusedByUs) failures.push(`${keyOf(e)}: ${res.text.slice(0, 200)}`);
      else if (templateParams(e.path).includes('node') && seen.at(-1)!.pathParams.node !== args.node) failures.push(`${keyOf(e)}: wrong node`);
    }
    expect(failures).toEqual([]);
  }, 120_000);
});
