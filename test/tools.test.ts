import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import { afterEach, describe, expect, it } from 'vitest';
import { catalog, findEndpoint, templateParams, type CatalogEndpoint, type CatalogParam } from '../src/catalog/index.js';
import { classify } from '../src/proxmox/policy.js';
import { isReadOnlyTool, type ToolDef } from '../src/tools/helpers.js';
import { allTools } from '../src/tools/index.js';
import { endpointTools, EXCLUDED_ENDPOINTS, UPLOAD_ENDPOINT } from '../src/tools/endpoints.js';
import { domainOf, OVERRIDES, toolName } from '../src/tools/naming.js';
import { FAKE_PASSWORD, FAKE_USER } from './fake-pve.js';
import { ALL_GATES, closeAll, connect } from './harness.js';

afterEach(closeAll);

const keyOf = (e: CatalogEndpoint) => `${e.method} ${e.path}`;
const generatedEndpoints = catalog.endpoints.filter((e) => !EXCLUDED_ENDPOINTS[keyOf(e)]);
const byName = new Map<string, ToolDef>(endpointTools().map((t) => [t.name, t]));

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
    expect(generatedEndpoints).toHaveLength(668);
    for (const e of generatedEndpoints) expect(byName.has(toolName(e.method, e.path)), keyOf(e)).toBe(true);
    expect(endpointTools()).toHaveLength(669);
  });

  it('leaves out only what the policy blocks, and the upload that has its own tool', () => {
    for (const key of Object.keys(EXCLUDED_ENDPOINTS)) {
      const [method, path] = key.split(' ') as [string, string];
      const values = Object.fromEntries(templateParams(path).map((n) => [n, 'x']));
      expect(classify(method, path, values).gate, key).toBe(key === UPLOAD_ENDPOINT ? 'write' : 'blocked');
    }
    expect(byName.has('pve_upload_to_storage')).toBe(true);
    expect(generatedEndpoints.filter((e) => classify(e.method, e.path, Object.fromEntries(templateParams(e.path).map((n) => [n, 'x']))).gate === 'blocked').map(keyOf)).toEqual([]);
  });

  it('takes gate, destructiveness and read-only from the policy, for every tool', () => {
    for (const e of generatedEndpoints) {
      const def = byName.get(toolName(e.method, e.path))!;
      const decision = classify(e.method, e.path, Object.fromEntries(templateParams(e.path).map((n) => [n, 'x'])));
      expect(decision.template, keyOf(e)).toBe(e.path);
      expect(def.gate, keyOf(e)).toBe(decision.gate);
      expect(def.destructive === true, keyOf(e)).toBe(decision.destructive);
      expect(isReadOnlyTool(def), keyOf(e)).toBe(e.method === 'GET');
      expect(def.description, keyOf(e)).toContain(keyOf(e));
      expect(def.domain, keyOf(e)).toBe(domainOf(e.path).domain);
    }
  });
});

describe('tool names', () => {
  it('are unique across all tools, and fit the format', () => {
    const tools = allTools(() => ({}));
    const names = tools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name).toMatch(/^pve_[a-z0-9_]{1,60}$/);
  });

  it('have no override for a method that does not exist', () => {
    for (const key of Object.keys(OVERRIDES)) {
      const [method, path] = key.split(' ') as [string, string];
      expect(findEndpoint(method, path), key).toBeDefined();
    }
  });

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
  const props = (name: string) => byName.get(name)!.input as unknown as Record<string, { isOptional(): boolean; description?: string }>;

  it('leaves node out only where the server can find it', () => {
    expect(props('pve_start_vm').node!.isOptional()).toBe(true);
    expect(props('pve_start_vm').vmid!.isOptional()).toBe(false);
    expect(props('pve_list_vms').node!.isOptional()).toBe(true);
    expect(props('pve_get_node_status').node!.isOptional()).toBe(true);
    // Here it names the node to take out of the cluster: a default would be a disaster.
    expect(props('pve_remove_cluster_node').node!.isOptional()).toBe(false);
    expect(props('pve_add_cluster_node').node!.isOptional()).toBe(false);
  });

  it('keeps placeholders the schema does not declare', () => {
    expect(props('pve_update_ha_rule').rule!.isOptional()).toBe(false);
    expect(props('pve_update_sdn_prefix_list_entry').url_seq!.isOptional()).toBe(false);
  });

  it('names indexed params without the [n], and not over a plain one of the same name', () => {
    const vm = props('pve_create_vm');
    expect(vm.net!.isOptional()).toBe(true);
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
    const listed = new Map(tools.map((t) => [t.name, t]));
    expect(listed.size).toBe(tools.length);
    for (const name of byName.keys()) expect(listed.has(name), name).toBe(true);

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
      const t = listed.get(toolName(e.method, e.path))!;
      expect(t.annotations?.readOnlyHint, keyOf(e)).toBe(e.method === 'GET');
      expect('dry_run' in (t.inputSchema.properties ?? {}), keyOf(e)).toBe(e.method !== 'GET');
      const decision = classify(e.method, e.path, Object.fromEntries(templateParams(e.path).map((n) => [n, 'x'])));
      if (decision.destructive) expect(t.annotations?.destructiveHint, keyOf(e)).toBe(true);
    }
  });

  it('shows few tools by default: gates and toolsets hide the rest', async () => {
    const generated = (names: string[]) => names.filter((n) => byName.has(n));
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
    for (const e of generatedEndpoints) {
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
