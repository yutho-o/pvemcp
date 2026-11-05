import { z } from 'zod';
import { catalog, templateParams, type CatalogEndpoint, type CatalogParam } from '../catalog/index.js';
import { ProxmoxError } from '../proxmox/errors.js';
import type { GuestLocation } from '../proxmox/nodes.js';
import { indexedName, isIndexedParam } from '../proxmox/params.js';
import { classify, describeHostAccess, destructiveArgs, hasDestructiveArgs, hostAccessArg, hostAccessParams, type Decision } from '../proxmox/policy.js';
import { redactRequest } from '../proxmox/redact.js';
import { resolveLocalPath } from '../proxmox/localpath.js';
import { asObject, mapOf, nodeName, pageRows, paging, tool, type ToolContext, type ToolDef } from './helpers.js';
import { domainOf, toolName } from './naming.js';

/**
 * Every API method becomes a tool, generated from the catalog at startup. What cannot be one
 * is listed here with the reason. Those methods stay reachable through pve_api_write only if
 * the operator lists them in PROXMOX_UNBLOCK, where the policy blocks them.
 */
export const EXCLUDED_ENDPOINTS: Readonly<Record<string, string>> = {
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

export const UPLOAD_ENDPOINT = 'POST /nodes/{node}/storage/{storage}/upload';

const PATH_VALUE_MAX = 512;
const RESERVED = new Set(['instance', 'dry_run', 'wait', 'wait_seconds', 'page_limit', 'page_offset']);
/** Arguments of the tool rather than of the API: never sent, even on an endpoint that does not use them. */
const SERVER_ARGS = new Set(['wait', 'wait_seconds', 'page_limit', 'page_offset']);

/**
 * PUT is idempotent on paper. These are not: the second call does something again or fails.
 * sendkey types twice, resize takes +1G, the others reload, order, add or delete.
 */
const NOT_IDEMPOTENT_PUT = /\/(?:sendkey|resize|wipedisk|unlink)$|^\/nodes\/\{node\}\/network$|^\/cluster\/sdn$|\/certificates\/acme\/certificate$|\/apt\/repositories$|^\/access\/users\/\{userid\}\/token\/\{tokenid\}$/;

/** What makes the node talk to something outside the cluster. */
const OPEN_WORLD = new RegExp(
  `^(?:${[
    '/nodes/\\{node\\}/storage/\\{storage\\}/(?:download-url|oci-registry-pull)',
    '/nodes/\\{node\\}/aplinfo',
    '/nodes/\\{node\\}/query-(?:url-metadata|oci-repo-tags)',
    '/nodes/\\{node\\}/scan/(?:cifs|iscsi|nfs|pbs)',
    '/nodes/\\{node\\}/apt/(?:update|changelog)',
    '/nodes/\\{node\\}/subscription',
    '/nodes/\\{node\\}/certificates/acme/certificate',
    '/nodes/\\{node\\}/(?:qemu|lxc)/\\{vmid\\}/remote_migrate',
    '/cluster/acme/(?:meta|tos|account(?:/\\{name\\})?)',
    '/cluster/notifications/targets/\\{name\\}/test',
    '/access/domains/\\{realm\\}/sync',
  ].join('|')})$`,
);

/*
 * What a caller may send for a value. Proxmox reads all of its parameters from text, so it takes
 * 1, "1", true, on and yes for a boolean, and "2048" and 2048 alike for a number or a string. An
 * agent that was told memory is a string must not be refused for writing 2048, and neither must one
 * that writes vmid: "100". Anything these do not recognise goes through as it is, and fails on the
 * schema behind them with a plain message.
 */
function toBoolean(value: unknown): unknown {
  if (value === 1) return true;
  if (value === 0) return false;
  if (typeof value !== 'string') return value;
  if (/^\s*(?:1|true|yes|on)\s*$/i.test(value)) return true;
  if (/^\s*(?:0|false|no|off)\s*$/i.test(value)) return false;
  return value;
}

function toNumber(value: unknown): unknown {
  if (typeof value !== 'string' || !/^\s*[+-]?\d+(?:\.\d+)?\s*$/.test(value)) return value;
  const n = Number(value);
  return Number.isSafeInteger(Math.trunc(n)) ? n : value;
}

function toText(value: unknown): unknown {
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? '1' : '0';
  return value;
}

/** Not .int(): that writes the limits of a double into the schema of every whole number of 680 tools. */
function wholeNumber(minimum?: number, maximum?: number): z.ZodType {
  let n = z.number();
  if (minimum !== undefined) n = n.min(minimum);
  if (maximum !== undefined) n = n.max(maximum);
  return n.refine(Number.isInteger, 'Expected a whole number').meta({ type: 'integer' });
}

function flexibleBoolean(): z.ZodType {
  return z.preprocess(toBoolean, z.boolean());
}

function flexibleWhole(minimum?: number, maximum?: number): z.ZodType {
  return z.preprocess(toNumber, wholeNumber(minimum, maximum));
}

const WAIT_ARGS = {
  wait: flexibleBoolean().optional().describe('If the call starts a task, wait for its end (default true). A failed task is reported as an error.'),
  wait_seconds: flexibleWhole(0, 3600).optional().describe('How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30). Past this it keeps running: see pve_wait_task.'),
};

function trimDescription(text: string | undefined, fallback: string): string {
  return text?.trim() || fallback;
}

/** Description of one parameter: the schema's text plus what zod cannot say. */
function paramDescription(apiName: string, param: CatalogParam): string {
  const parts = [trimDescription(param.description, apiName)];
  if (param.default !== undefined) parts.push(`Default: ${String(param.default)}.`);
  if (param.typetext && !param.propertyString && param.typetext.length <= 120) parts.push(`Format: ${param.typetext}.`);
  if (param.pattern) parts.push(`Pattern: ${param.pattern}`);
  if (param.requires) parts.push(`Needs ${param.requires}.`);
  if (param.instanceTypes) parts.push(`Only for ${param.typeProperty ?? 'type'}: ${param.instanceTypes.join(', ')}.`);
  return parts.join(' ');
}

function zodFor(apiName: string, param: CatalogParam): z.ZodType {
  const description = paramDescription(apiName, param);
  switch (param.type) {
    case 'boolean':
      return flexibleBoolean().describe(description);
    case 'integer':
    case 'number': {
      const allowed = param.enum ? ` One of: ${param.enum.join(', ')}.` : '';
      if (param.type === 'integer') return flexibleWhole(param.minimum, param.maximum).describe(`${description}${allowed}`);
      let n = z.number();
      if (param.minimum !== undefined) n = n.min(param.minimum);
      if (param.maximum !== undefined) n = n.max(param.maximum);
      return z.preprocess(toNumber, n).describe(`${description}${allowed}`);
    }
    case 'array': {
      const whole = param.items?.type === 'integer';
      const choices = param.items?.enum;
      const item = whole ? flexibleWhole() : z.preprocess(toText, choices && choices.length > 0 ? z.enum(choices as [string, ...string[]]) : z.string());
      // Sent as repeated parameters. A list of ids is often written 100,101, and a single value as such.
      const toArray = (value: unknown): unknown => {
        if (value === undefined || Array.isArray(value)) return value;
        return whole && typeof value === 'string' ? value.split(/[,;\s]+/).filter(Boolean) : [value];
      };
      return z.preprocess(toArray, z.array(item)).describe(description);
    }
    default: {
      if (param.enum && param.enum.length > 0) return z.preprocess(toText, z.enum(param.enum as [string, ...string[]])).describe(description);
      let s = z.string();
      if (param.minLength !== undefined) s = s.min(param.minLength);
      if (param.maxLength !== undefined) s = s.max(param.maxLength);
      return z.preprocess(toText, s).describe(description);
    }
  }
}

/**
 * Why a node may be left out, if it may. Only where it says which node should do the work: in
 * /cluster/config/nodes/{node} it names the node to add or remove, and a guess there could
 * take the wrong one out of the cluster.
 */
function optionalNode(name: string, template: string, pathNames: readonly string[]): string | undefined {
  if (name !== 'node' || !template.startsWith('/nodes/{node}')) return undefined;
  return pathNames.includes('vmid') ? 'Optional: found from the vmid when left out.' : 'Optional when there is a default node or only one node.';
}

function pathParamSchema(name: string, declared: CatalogParam | undefined, optionalBecause?: string): z.ZodType {
  if (name === 'node') {
    const schema = z.preprocess(toText, nodeName).describe(`The cluster node name.${optionalBecause ? ` ${optionalBecause}` : ''}`);
    return optionalBecause ? schema.optional() : schema;
  }
  if (declared?.type === 'integer') return flexibleWhole(declared.minimum, declared.maximum).describe(trimDescription(declared.description, name));
  if (declared?.enum && declared.enum.length > 0) return z.preprocess(toText, z.enum(declared.enum as [string, ...string[]])).describe(trimDescription(declared.description, name));
  const s = z.string().min(1).max(PATH_VALUE_MAX).regex(/^[^\u0000-\u001f]+$/, 'Control characters are not allowed');
  return z.preprocess(toText, s).describe(`${trimDescription(declared?.description, `The ${name} from the path.`)}${declared?.typetext && declared.typetext.length < 80 ? ` Format: ${declared.typetext}.` : ''}`);
}

interface GeneratedInput {
  input: Record<string, z.ZodType>;
  /** Tool argument name to API parameter, for those that differ. */
  indexed: Map<string, string>;
  pathNames: string[];
  paged: boolean;
  waits: boolean;
}

function buildInput(endpoint: CatalogEndpoint): GeneratedInput {
  const { method, path, params } = endpoint;
  const pathNames = templateParams(path);
  const input: Record<string, z.ZodType> = {};
  const indexed = new Map<string, string>();
  const names = new Set(Object.keys(params));

  for (const name of pathNames) {
    input[name] = pathParamSchema(name, params[name], optionalNode(name, path, pathNames));
  }
  for (const [apiName, param] of Object.entries(params)) {
    if (pathNames.includes(apiName)) continue;
    if (RESERVED.has(apiName)) throw new Error(`${method} ${path}: parameter ${apiName} collides with a server parameter.`);
    if (isIndexedParam(apiName)) {
      const name = indexedName(apiName, names);
      indexed.set(name, apiName);
      const example = apiName === 'net[n]' ? '{"0": "virtio,bridge=vmbr0"}' : '{"0": "..."}';
      input[name] = mapOf(z.preprocess(toText, z.string()), { pattern: /^\d+$/, message: 'Expected a number as the key, such as "0"' })
        .optional()
        .describe(`${trimDescription(param.description, apiName)} Numbered items, such as ${example}: key 0 is ${apiName.slice(0, -3)}0 in Proxmox, and ${apiName.slice(0, -3)}0 is also accepted as an argument.`);
      continue;
    }
    const schema = zodFor(apiName, param);
    input[apiName] = param.optional ? schema.optional() : schema;
  }

  // Also next to the native start and limit of some endpoints: an answer cut to size says to go on with page_offset.
  const paged = method === 'GET' && endpoint.returns.type === 'array';
  if (paged) Object.assign(input, { page_limit: z.preprocess(toNumber, paging.page_limit), page_offset: z.preprocess(toNumber, paging.page_offset) });
  const waits = method !== 'GET' && endpoint.returns.type === 'string';
  if (waits) Object.assign(input, WAIT_ARGS);
  return { input, indexed, pathNames, paged, waits };
}

function describeEndpoint(endpoint: CatalogEndpoint, decision: Decision, conditional: boolean): string {
  const facts: string[] = [`${endpoint.method} ${endpoint.path}`];
  if (endpoint.permissions) facts.push(`Needs: ${endpoint.permissions.length > 220 ? `${endpoint.permissions.slice(0, endpoint.permissions.lastIndexOf(' ', 220))} ...` : endpoint.permissions}`);
  if (/root@pam/.test(`${endpoint.description} ${endpoint.permissions ?? ''}`)) facts.push('Requires root@pam');
  if (decision.destructive) facts.push('Destructive');
  else if (conditional) facts.push('Destructive with some argument values');
  const hostAccess = hostAccessParams(endpoint.params, endpoint.method, endpoint.path);
  if (decision.gate === 'write' && hostAccess.length > 0) facts.push(`These reach the host itself and need PROXMOX_ALLOW_ELEVATED: ${hostAccess.join(', ')}`);
  if (endpoint.method === 'POST' && endpoint.path === '/nodes/{node}/lxc') facts.push('Pass unprivileged=1: left out, Proxmox creates a privileged container, which counts as host access');
  if (decision.returnsSecret) facts.push('The secret in the answer is only shown with PROXMOX_ALLOW_SENSITIVE=true: otherwise it is lost');
  return `${trimDescription(endpoint.description, endpoint.name)} [${facts.join('. ')}.]`;
}

function titleOf(name: string): string {
  const words = name.replace(/^pve_/, '').split('_');
  return words.map((w, i) => (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w)).join(' ');
}

function assertGuestType(endpoint: CatalogEndpoint, guest: GuestLocation): void {
  const wanted = endpoint.path.startsWith('/nodes/{node}/qemu') ? 'qemu' : endpoint.path.startsWith('/nodes/{node}/lxc') ? 'lxc' : undefined;
  if (wanted && wanted !== guest.type) {
    throw new ProxmoxError('invalid_input', `Guest ${guest.vmid} is ${guest.type === 'lxc' ? 'a container' : 'a VM'}, and this tool is for ${wanted === 'lxc' ? 'containers' : 'VMs'}.`, {
      hint: `Use the matching tool for ${guest.type === 'lxc' ? 'lxc' : 'vm'}.`,
    });
  }
}

async function resolveNode(endpoint: CatalogEndpoint, args: Record<string, unknown>, pathNames: string[], ctx: ToolContext): Promise<string | undefined> {
  if (!pathNames.includes('node')) return undefined;
  const given = args.node as string | undefined;
  if (!endpoint.path.startsWith('/nodes/{node}')) return given;
  if (typeof args.vmid === 'number' && pathNames.includes('vmid')) {
    if (given) return given;
    const guest = await ctx.nodes.resolveGuest(args.vmid);
    assertGuestType(endpoint, guest);
    return guest.node;
  }
  return given ?? ctx.nodes.defaultNode();
}

/** A spelling of an argument that differs only by dashes, underscores or case. */
function nearestArgument(key: string, known: Iterable<string>): string | undefined {
  const plain = (text: string) => text.replace(/[-_]/g, '').toLowerCase();
  for (const name of known) if (plain(name) === plain(key)) return name;
  return undefined;
}

/**
 * net0, or net[0], for the parameter net[n]: this is how Proxmox and all of its documentation write
 * them, so it is what an agent is going to send.
 */
function flatIndexedName(key: string, endpoint: CatalogEndpoint): string | undefined {
  const match = /^(.+?)\[?(\d+)\]?$/.exec(key);
  return match && `${match[1]}[n]` in endpoint.params ? `${match[1]}${match[2]}` : undefined;
}

function generate(endpoint: CatalogEndpoint): ToolDef {
  const { method, path } = endpoint;
  const { input, indexed, pathNames, paged, waits } = buildInput(endpoint);
  const name = toolName(method, path);
  // Path values are irrelevant to classification: every rule works on the template.
  const decision = classify(method, path, Object.fromEntries(pathNames.map((n) => [n, 'x'])));
  const { domain, also } = domainOf(path);
  const conditional = hasDestructiveArgs(endpoint.params, method, path);
  const known = new Set(Object.keys(input));

  /** The parameters of the API call, from the arguments of the tool. Refuses what it does not know. */
  const apiParams = (args: Record<string, unknown>): Record<string, unknown> => {
    const params: Record<string, unknown> = {};
    const unknown: string[] = [];
    for (const [key, value] of Object.entries(args)) {
      if (value === undefined || pathNames.includes(key) || SERVER_ARGS.has(key)) continue;
      const apiName = indexed.get(key);
      if (apiName) {
        // Spelled out here: numa[n] sits next to a plain numa on VM configs.
        for (const [index, item] of Object.entries(value as Record<string, string>)) params[`${apiName.slice(0, -3)}${index}`] = item;
      } else if (known.has(key)) {
        params[key] = value;
      } else {
        const wire = flatIndexedName(key, endpoint);
        if (!wire) {
          unknown.push(key);
        } else if (typeof value === 'object') {
          throw new ProxmoxError('invalid_input', `${name}: "${key}" takes a string, such as a property string: virtio,bridge=vmbr0.`);
        } else {
          params[wire] = toText(value);
        }
      }
    }
    if (unknown.length > 0) {
      const near = unknown.map((key) => [key, nearestArgument(key, known)] as const).filter(([, match]) => match);
      throw new ProxmoxError('invalid_input', `${name} has no argument ${unknown.map((k) => `"${k}"`).join(', ')}: nothing was sent.`, {
        hint: `${near.map(([key, match]) => `For "${key}", use "${match}". `).join('')}The schema of the tool lists its arguments.`,
      });
    }
    return params;
  };

  return {
    name,
    title: titleOf(name),
    description: describeEndpoint(endpoint, decision, conditional),
    domain,
    ...(also ? { also } : {}),
    gate: decision.gate,
    ...(decision.gate === 'write' && hostAccessParams(endpoint.params, method, path).length > 0
      ? {
          gateWhen: (args: Record<string, unknown>) => (hostAccessArg(method, path, args) ? ('elevated' as const) : undefined),
          gateNote: (args: Record<string, unknown>) => {
            const arg = hostAccessArg(method, path, args);
            return arg ? describeHostAccess(name, arg) : undefined;
          },
        }
      : {}),
    destructive: decision.destructive,
    ...(conditional ? { destructiveWhen: (args: Record<string, unknown>) => destructiveArgs(method, path, args) } : {}),
    readOnly: method === 'GET',
    idempotent: method === 'GET' || method === 'DELETE' || (method === 'PUT' && !NOT_IDEMPOTENT_PUT.test(path)),
    ...(OPEN_WORLD.test(path) ? { openWorld: true } : {}),
    acceptsExtraArgs: true,
    redactArgs: (args) => redactRequest(path, args),
    input,
    checkArgs: (args) => {
      apiParams(args);
    },
    handler: async (args, ctx) => {
      const pathParams: Record<string, string | number> = {};
      const node = await resolveNode(endpoint, args, pathNames, ctx);
      for (const p of pathNames) {
        const value = p === 'node' ? node : args[p];
        if (value === undefined) throw new ProxmoxError('invalid_input', `${name}: "${p}" is required.`);
        pathParams[p] = value as string | number;
      }
      const opts = { pathParams, params: apiParams(args) };
      const value = await ctx.api.request(method, path, opts);

      if (method === 'GET') {
        if (Array.isArray(value)) {
          const limit = paged ? (args.page_limit as number | undefined) : undefined;
          const offset = paged ? (args.page_offset as number | undefined) : undefined;
          return pageRows(value, limit, offset);
        }
        return asObject(value);
      }
      if (waits) {
        return ctx.tasks.finish(value, {
          ...(args.wait !== undefined ? { wait: args.wait as boolean } : {}),
          ...(args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds as number } : {}),
        });
      }
      return ctx.tasks.finish(value, { wait: false });
    },
  };
}

function uploadTool(): ToolDef {
  const path = '/nodes/{node}/storage/{storage}/upload';
  return tool({
    name: 'pve_upload_to_storage',
    title: 'Upload to storage',
    description: `Uploads a file from this server's PROXMOX_LOCAL_DIR to a storage: an ISO, a container template or a disk image to import. Refused when PROXMOX_LOCAL_DIR is not set, or when the file is outside it. [POST ${path}. Needs: Datastore.AllocateTemplate on /storage/{storage}.]`,
    domain: 'storage',
    gate: 'write',
    input: {
      node: nodeName.optional().describe('The cluster node name. Optional when there is a default node or only one node.'),
      storage: z.string().min(1).max(PATH_VALUE_MAX).describe('The storage identifier.'),
      content: z.enum(['iso', 'vztmpl', 'import']).describe('Content type of the file.'),
      local_path: z.string().min(1).max(4096).describe('The file, relative to PROXMOX_LOCAL_DIR.'),
      filename: z.string().min(1).max(255).optional().describe('Name to give the file on the storage. Default: its name here.'),
      checksum: z.string().max(512).optional().describe('Expected checksum of the file.'),
      'checksum-algorithm': z.enum(['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']).optional().describe('Algorithm of the checksum.'),
      wait: z.preprocess(toBoolean, z.boolean()).optional().describe('Wait for the task that imports the file (default true).'),
      wait_seconds: z.preprocess(toNumber, z.number().int().min(0).max(3600)).optional().describe('How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30).'),
    },
    handler: async (args, ctx) => {
      const localPath = resolveLocalPath(ctx.instance.localDir, args.local_path, { mustExist: true });
      const node = args.node ?? (await ctx.nodes.defaultNode());
      const fields: Record<string, unknown> = { content: args.content };
      if (args.checksum) fields.checksum = args.checksum;
      if (args['checksum-algorithm']) fields['checksum-algorithm'] = args['checksum-algorithm'];
      const value = await ctx.api.upload(path, fields, { localPath, ...(args.filename ? { filename: args.filename } : {}) }, { pathParams: { node, storage: args.storage } });
      return ctx.tasks.finish(value, {
        ...(args.wait !== undefined ? { wait: args.wait } : {}),
        ...(args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds } : {}),
      });
    },
  });
}

let generated: ToolDef[] | undefined;

/** Built once: in HTTP mode each request has its own server over the same definitions. */
export function endpointTools(): ToolDef[] {
  generated ??= [...catalog.endpoints.filter((e) => !EXCLUDED_ENDPOINTS[`${e.method} ${e.path}`]).map(generate), uploadTool()];
  return generated;
}
