import { z } from 'zod';
import { catalog, findEndpoint, matchPath, type CatalogEndpoint } from '../catalog/index.js';
import { ProxmoxError } from '../proxmox/errors.js';
import { classify, normalizePath } from '../proxmox/policy.js';
import { redactRequest } from '../proxmox/redact.js';
import { asObject, looseObject, mapOf, pageRows, tool, type ToolDef } from './helpers.js';
import { EXCLUDED_ENDPOINTS, UPLOAD_ENDPOINT } from './endpoints.js';
import { domainOf, toolName } from './naming.js';

const path = z
  .string()
  .min(1)
  .max(4096)
  .describe('API path, without /api2/json, such as /nodes/pve1/qemu/100/config. It may also be a template with {placeholders}, filled from path_params.');

const pathParams = mapOf(z.union([z.string(), z.number()]))
  .optional()
  .describe('Values for {placeholders} in the path. The way to pass a value holding a slash, such as a volume id: path /nodes/pve1/storage/local/content/{volume}, path_params {"volume": "local:iso/x.iso"}.');

const params = looseObject({}).optional().describe('Parameters. Booleans become 1/0, arrays repeat the key, and {"0": "..."} under net becomes net0.');

function placeholderValues(template: string): Record<string, string> {
  return Object.fromEntries([...template.matchAll(/\{([^}]+)\}/g)].map((m) => [m[1]!, 'x']));
}

function summary(e: CatalogEndpoint): Record<string, unknown> {
  const decision = classify(e.method, e.path, placeholderValues(e.path));
  const excluded = EXCLUDED_ENDPOINTS[`${e.method} ${e.path}`];
  return {
    method: e.method,
    path: e.path,
    description: e.description,
    gate: decision.gate,
    ...(decision.destructive ? { destructive: true } : {}),
    domain: domainOf(e.path).domain,
    tool: `${e.method} ${e.path}` === UPLOAD_ENDPOINT ? 'pve_upload_to_storage' : excluded ? null : toolName(e.method, e.path),
  };
}

export function apiTools(): ToolDef[] {
  return [
    tool({
      name: 'pve_api_search',
      title: 'Search the Proxmox API',
      description: `Searches the catalog of ${catalog.endpoints.length} Proxmox API methods: path, description and parameter names. Each result gives the tool that calls it, and the gate this server applies. Every method has its own tool, but tool lists are filtered by PROXMOX_TOOLSETS and by what the instance allows: a result whose tool is not in your list can still be called with pve_api_read or pve_api_write, under the same policy.`,
      domain: 'api',
      gate: 'read',
      idempotent: true,
      input: {
        query: z.string().min(2).max(200).describe('Words that must all appear, such as "lxc snapshot" or "firewall ipset".'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).optional().describe('Only this HTTP method.'),
        page_limit: z.number().int().min(1).max(200).optional().describe('Results per page (default 30).'),
        page_offset: z.number().int().min(0).optional().describe('Results to skip. Use next_offset from the previous page.'),
      },
      handler: async (args) => {
        const words = args.query.toLowerCase().split(/\s+/).filter(Boolean);
        const hits = catalog.endpoints.filter((e) => {
          if (args.method && e.method !== args.method) return false;
          const haystack = `${e.method} ${e.path} ${e.description} ${Object.keys(e.params).join(' ')} ${toolName(e.method, e.path)}`.toLowerCase();
          return words.every((w) => haystack.includes(w));
        });
        return pageRows(hits.map(summary), args.page_limit ?? 30, args.page_offset);
      },
    }),
    tool({
      name: 'pve_api_describe',
      title: 'Describe an API method',
      description: 'Gives everything known about one API method: all parameters with types and allowed values, privileges needed, what it returns, the gate this server applies and the tool that calls it. Use this before a call that failed validation, or to build a property string such as net0.',
      domain: 'api',
      gate: 'read',
      idempotent: true,
      input: {
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE']).describe('HTTP method.'),
        path: z.string().min(1).max(4096).describe('The template (/nodes/{node}/qemu), or a concrete path (/nodes/pve1/qemu).'),
      },
      handler: async (args) => {
        const endpoint = findEndpoint(args.method, args.path) ?? (() => {
          const template = args.path.includes('{') ? undefined : matchPath(normalizePath(args.path))?.template;
          return template ? findEndpoint(args.method, template) : undefined;
        })();
        if (!endpoint) {
          throw new ProxmoxError('not_found', `${args.method} ${args.path} is not in the API catalog.`, { hint: 'pve_api_search finds methods by keyword.' });
        }
        return {
          ...summary(endpoint),
          name: endpoint.name,
          permissions: endpoint.permissions ?? null,
          allow_token: endpoint.allowtoken,
          returns: endpoint.returns,
          params: endpoint.params,
        };
      },
    }),
    tool({
      name: 'pve_api_read',
      title: 'Read any API path',
      description: 'Calls any GET method by path, under the same policy as the dedicated tools: gate read, or sensitive when that is allowed. For what is not in your tool list. A path that is not in the catalog counts as sensitive. Secrets are redacted.',
      domain: 'api',
      gate: 'read',
      idempotent: true,
      input: {
        path,
        path_params: pathParams,
        params,
        page_limit: z.number().int().min(1).max(10_000).optional().describe('Rows per page, when the answer is a list.'),
        page_offset: z.number().int().min(0).optional().describe('Rows to skip. Use next_offset from the previous page.'),
      },
      handler: async (args, ctx) => {
        const decision = classify('GET', args.path, args.path_params);
        if (decision.gate !== 'read' && decision.gate !== 'sensitive' && decision.gate !== 'blocked') {
          throw new ProxmoxError('not_read_only', `pve_api_read only takes methods of gate read or sensitive, and GET ${decision.path} has gate ${decision.gate}.`, {
            hint: 'Use its dedicated tool: pve_api_describe gives the name.',
          });
        }
        const value = await ctx.api.get(args.path, {
          ...(args.path_params ? { pathParams: args.path_params } : {}),
          ...(args.params ? { params: args.params } : {}),
        });
        return Array.isArray(value) ? pageRows(value, args.page_limit, args.page_offset) : asObject(value);
      },
    }),
    tool({
      name: 'pve_api_write',
      title: 'Write to any API path',
      description: 'Calls any POST, PUT or DELETE method by path, for what is not in your tool list. The same policy applies: the gate of the method is checked, including elevated, guest_exec and console, and blocked endpoints stay blocked. A path that is not in the catalog counts as elevated. A task id in the answer is waited for. Prefer a dedicated tool whenever one exists.',
      domain: 'api',
      gate: 'write',
      destructive: true,
      input: {
        method: z.enum(['POST', 'PUT', 'DELETE']).describe('HTTP method.'),
        path,
        path_params: pathParams,
        params,
        wait: z.boolean().optional().describe('If the call starts a task, wait for its end (default true).'),
        wait_seconds: z.number().int().min(0).max(3600).optional().describe('How long to wait for the task. Default: PROXMOX_TASK_WAIT_SECONDS (30).'),
      },
      redactArgs: (args) => (args.params ? { ...args, params: redactRequest(String(args.path), args.params) } : args),
      confirmation: (args) => `Call ${args.method} ${args.path} on Proxmox, with ${JSON.stringify(Object.keys(args.params ?? {}))}?`,
      handler: async (args, ctx) => {
        const value = await ctx.api.request(args.method, args.path, {
          ...(args.path_params ? { pathParams: args.path_params } : {}),
          ...(args.params ? { params: args.params } : {}),
        });
        return ctx.tasks.finish(value, {
          ...(args.wait !== undefined ? { wait: args.wait } : {}),
          ...(args.wait_seconds !== undefined ? { waitSeconds: args.wait_seconds } : {}),
        });
      },
    }),
  ];
}
