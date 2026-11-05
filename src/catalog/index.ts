import catalogFile from './endpoints.json' with { type: 'json' };

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface CatalogParam {
  type: string;
  description?: string;
  optional?: boolean;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  typetext?: string;
  format?: string;
  /** The value is a Proxmox property string (key=value,...); the description lists its keys. */
  propertyString?: boolean;
  items?: { type: string; format?: string; enum?: string[] };
  requires?: string;
  instanceTypes?: string[];
  typeProperty?: string;
}

export interface CatalogReturns {
  type: string;
  description?: string;
  properties?: string[];
  itemProperties?: string[];
  links?: boolean;
}

export interface CatalogEndpoint {
  method: HttpMethod;
  path: string;
  name: string;
  description: string;
  allowtoken: boolean;
  params: Record<string, CatalogParam>;
  returns: CatalogReturns;
  protected?: boolean;
  proxyto?: string;
  expose_credentials?: boolean;
  download_allowed?: boolean;
  permissions?: string;
}

export interface Catalog {
  source: string;
  /** When the schema was published or fetched. */
  schema_date: string;
  schema_sha256: string;
  counts: Record<string, number>;
  endpoints: CatalogEndpoint[];
}

export const catalog = catalogFile as unknown as Catalog;

interface TrieNode {
  literal: Map<string, TrieNode>;
  /** Placeholder name to child. Several names can share a position: /x/{a} and /x/{b}/y. */
  placeholder?: { names: Set<string>; node: TrieNode };
  /** The template that ends at this node, with its methods. */
  template?: string;
  methods?: Map<HttpMethod, CatalogEndpoint>;
}

function newNode(): TrieNode {
  return { literal: new Map() };
}

function placeholderName(segment: string): string | undefined {
  return /^\{(.+)\}$/.exec(segment)?.[1];
}

const root = newNode();
const byKey = new Map<string, CatalogEndpoint>();
for (const endpoint of catalog.endpoints) {
  byKey.set(`${endpoint.method} ${endpoint.path}`, endpoint);
  let node = root;
  for (const segment of endpoint.path.split('/').filter(Boolean)) {
    const name = placeholderName(segment);
    if (name) {
      node.placeholder ??= { names: new Set(), node: newNode() };
      node.placeholder.names.add(name);
      node = node.placeholder.node;
    } else {
      let next = node.literal.get(segment);
      if (!next) {
        next = newNode();
        node.literal.set(segment, next);
      }
      node = next;
    }
  }
  node.template = endpoint.path;
  node.methods ??= new Map();
  node.methods.set(endpoint.method, endpoint);
}

export function findEndpoint(method: string, template: string): CatalogEndpoint | undefined {
  return byKey.get(`${method} ${template}`);
}

export interface PathMatch {
  template: string;
  pathParams: Record<string, string>;
  methods: Map<HttpMethod, CatalogEndpoint>;
}

/** Literal segments win over placeholders, with backtracking: the API router does the same. */
export function matchPath(segments: readonly string[]): PathMatch | undefined {
  const walk = (node: TrieNode, index: number): TrieNode | undefined => {
    if (index === segments.length) return node.template ? node : undefined;
    const literal = node.literal.get(segments[index]!);
    if (literal) {
      const found = walk(literal, index + 1);
      if (found) return found;
    }
    return node.placeholder ? walk(node.placeholder.node, index + 1) : undefined;
  };
  const end = walk(root, 0);
  if (!end?.template || !end.methods) return undefined;
  const pathParams: Record<string, string> = {};
  end.template
    .split('/')
    .filter(Boolean)
    .forEach((segment, i) => {
      const name = placeholderName(segment);
      if (name) pathParams[name] = segments[i]!;
    });
  return { template: end.template, pathParams, methods: end.methods };
}

/** Path parameter names, always from the template: the schema does not declare them all. */
export function templateParams(template: string): string[] {
  return template
    .split('/')
    .map(placeholderName)
    .filter((n): n is string => n !== undefined);
}
