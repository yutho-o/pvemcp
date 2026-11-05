#!/usr/bin/env node
/**
 * Generates src/catalog/endpoints.json from the official Proxmox VE API schema, which is
 * published as a JSON array inside a JavaScript file (apidoc.js).
 *
 *   node scripts/build-catalog.mjs                # download from pve.proxmox.com
 *   node scripts/build-catalog.mjs --from FILE    # use a local apidoc.js
 *
 * The file is parsed, never evaluated: it is code from the network, and only the array
 * after "const apiSchema = " is of any use here.
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outFile = join(root, 'src', 'catalog', 'endpoints.json');
const SOURCE_URL = 'https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js';
const MARKER = 'const apiSchema = ';
const MAX_DESCRIPTION = 400;
const MAX_METHOD_DESCRIPTION = 500;
const MAX_FORMAT_SUMMARY = 1500;

/**
 * Where the schema's own text is wrong or empty. An agent picks a tool by this text, and "Add a
 * fabric" on a DELETE reads as the opposite of what it does.
 */
const DESCRIPTION_FIXES = {
  'DELETE /cluster/sdn/fabrics/fabric/{id}': 'Delete a fabric.',
  'GET /cluster/sdn/fabrics/fabric/{id}': 'Get a fabric.',
  'GET /cluster/sdn/fabrics/fabric': 'List the fabrics.',
  'GET /cluster/sdn/fabrics/all': 'List all fabrics and their nodes.',
  'GET /cluster/sdn/fabrics/node': 'List the nodes of all fabrics.',
  'GET /cluster/sdn/fabrics/node/{fabric_id}': 'List the nodes of a fabric.',
  'DELETE /cluster/sdn/fabrics/node/{fabric_id}/{node_id}': 'Delete a node from a fabric.',
  'PUT /access/tfa/{userid}/{id}': 'Update a TFA entry of a user.',
  'GET /access/tfa/{userid}': 'List the TFA entries of a user.',
  'GET /cluster/acme': 'Directory index of the ACME endpoints.',
  'GET /nodes/{node}/certificates': 'Directory index of the certificate endpoints.',
  'GET /nodes/{node}/disks': 'Directory index of the disk endpoints.',
  'POST /nodes/{node}/termproxy': 'Creates a terminal proxy on the node.',
  'GET /nodes/{node}/qemu/{vmid}/snapshot/{snapname}': 'Directory index of one snapshot.',
  'GET /nodes/{node}/lxc/{vmid}/snapshot/{snapname}': 'Directory index of one snapshot.',
  'GET /nodes/{node}/tasks/{upid}': 'Directory index of one task.',
  'GET /nodes/{node}/storage/{storage}': 'Directory index of one storage on this node.',
  'GET /nodes/{node}/sdn/vnets/{vnet}': 'Directory index of one VNet on this node.',
};

function extractSchema(text) {
  const at = text.indexOf(MARKER);
  if (at < 0) throw new Error(`"${MARKER}" not found: this does not look like apidoc.js.`);
  const start = at + MARKER.length;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') {
      depth--;
      if (depth === 0) return JSON.parse(text.slice(start, i + 1));
    }
  }
  throw new Error('The schema array never closes.');
}

function trim(text, max) {
  if (typeof text !== 'string') return undefined;
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= max) return clean;
  const cut = clean.slice(0, max);
  // End on a sentence or a word: half a word reads like a bug in the tool.
  const stop = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('; '));
  return `${stop > max * 0.6 ? cut.slice(0, stop + 1) : cut.slice(0, cut.lastIndexOf(' '))} ...`;
}

/**
 * net[n] and friends: their format is an object describing a Proxmox property string. Entries
 * with an alias are other spellings of a real key (virtio=<mac>, bps_rd_length): listed, they
 * read as required keys with no type, and push the real ones past the size limit.
 */
function summarizeFormat(format) {
  const entries = Object.entries(format)
    .filter(([, spec]) => !spec.alias)
    .sort(([a, x], [b, y]) => {
      // The default key goes first: it is the one that may be written without its name.
      const dx = x?.default_key ? 0 : 1;
      const dy = y?.default_key ? 0 : 1;
      return dx - dy || a.localeCompare(b);
    });
  const parts = entries.map(([name, spec]) => {
    const required = spec.optional ? '' : '*';
    let kind = spec.type ?? 'string';
    if (Array.isArray(spec.enum)) kind = spec.enum.join('|');
    else if (typeof spec.format === 'string') kind = spec.format;
    else if (typeof spec.format_description === 'string') kind = spec.format_description;
    return `${name}${required}=<${kind}>`;
  });
  const text = parts.join(' ');
  const body = text.length <= MAX_FORMAT_SUMMARY ? text : `${text.slice(0, text.lastIndexOf(' ', MAX_FORMAT_SUMMARY))} ...`;
  const firstNameOptional = entries.some(([, spec]) => spec.default_key);
  return `(key=value,...; * required${firstNameOptional ? '; the name of the first key can be left out' : ''}): ${body}`;
}

/** The schema writes some bounds as text ("minimum": "0"), which zod and JSON Schema take for no bound at all. */
function asNumber(value) {
  if (typeof value === 'number') return value;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function formatNote(spec) {
  if (spec.format && typeof spec.format === 'object') return `Property string ${summarizeFormat(spec.format)}`;
  if (spec.items?.format && typeof spec.items.format === 'object') return `Each item is a property string ${summarizeFormat(spec.items.format)}`;
  return undefined;
}

function compactParam(spec, variants) {
  const out = { type: spec.type ?? 'string' };
  let description = trim(spec.description, MAX_DESCRIPTION) ?? '';
  if (spec.format && typeof spec.format === 'object') out.propertyString = true;
  else if (typeof spec.format === 'string') out.format = spec.format;
  const notes = [];
  if (variants) {
    for (const v of variants) {
      const note = formatNote(v);
      if (note) notes.push(`For ${(v['instance-types'] ?? []).join(', ')}: ${note}`);
    }
  } else {
    const note = formatNote(spec);
    if (note) notes.push(note);
  }
  description = [description, ...notes].filter(Boolean).join(' ');
  if (description) out.description = description;
  if (spec.optional && spec.optional !== '0') out.optional = true;
  for (const key of ['default', 'enum', 'pattern', 'typetext', 'requires']) {
    if (spec[key] !== undefined) out[key] = spec[key];
  }
  for (const key of ['minimum', 'maximum', 'minLength', 'maxLength']) {
    const n = asNumber(spec[key]);
    if (n !== undefined) out[key] = n;
  }
  if (out.typetext === `<${out.type}>`) delete out.typetext;
  if (typeof out.pattern === 'string' && out.pattern.length > 200) delete out.pattern;
  if (spec.type === 'array') {
    const items = spec.items && typeof spec.items === 'object' ? spec.items : {};
    out.items = {
      type: items.type ?? 'string',
      ...(typeof items.format === 'string' ? { format: items.format } : {}),
      ...(Array.isArray(items.enum) ? { enum: items.enum } : {}),
    };
  }
  if (spec['instance-types']) out.instanceTypes = [...spec['instance-types']].sort();
  if (spec['type-property']) out.typeProperty = spec['type-property'];
  return out;
}

/** A property defined per instance type: one definition, plus what differs between the types. */
function mergeOneOf(spec) {
  const variants = spec.oneOf ?? [];
  const merged = { ...variants[0], ...spec, oneOf: undefined };
  const types = new Set();
  let optional = true;
  for (const v of variants) {
    for (const t of v['instance-types'] ?? []) types.add(t);
    if (!v.optional) optional = false;
  }
  if (types.size > 0) merged['instance-types'] = [...types];
  merged.optional = spec.optional ?? optional;
  if (!merged.description) merged.description = variants.find((v) => v.description)?.description;
  return { merged, variants };
}

/** Flattens parameters.properties, plus allOf/oneOf groups. Variant-specific params can never be required. */
function collectParams(parameters) {
  const out = new Map();
  const add = (name, spec, instanceType, variantCount) => {
    const { merged: flat, variants } = spec.oneOf ? mergeOneOf(spec) : { merged: spec };
    const existing = out.get(name);
    if (existing) {
      if (instanceType) existing.seen.add(instanceType);
      existing.required &&= !flat.optional;
      return;
    }
    out.set(name, { spec: flat, variants, seen: new Set(instanceType ? [instanceType] : []), required: !flat.optional, variantCount });
  };
  const walk = (group) => {
    for (const [name, spec] of Object.entries(group.properties ?? {})) add(name, spec);
    for (const part of group.allOf ?? []) walk(part);
    // The field that selects the variant is not among their properties: without it, POST /cluster/ha/rules could not be called.
    if (group['type-property'] && group['type-property-schema']) add(group['type-property'], group['type-property-schema']);
    const variants = group.oneOf ?? [];
    for (const variant of variants) {
      for (const [name, spec] of Object.entries(variant.properties ?? {})) add(name, spec, variant['instance-type'], variants.length);
    }
  };
  walk(parameters ?? {});

  const params = {};
  for (const name of [...out.keys()].sort()) {
    const { spec, variants, seen, required, variantCount } = out.get(name);
    const compact = compactParam(spec, variants);
    if (seen.size > 0) {
      compact.instanceTypes = [...seen].sort();
      // Present in only some variants: it cannot be required of everyone.
      if (!required || seen.size < variantCount) compact.optional = true;
      else delete compact.optional;
    }
    params[name] = compact;
  }
  return params;
}

/** ["and", ["perm", "/", ["Sys.Audit"]], ...] as text an agent can pass on to the operator. */
function describeCheck(check) {
  if (!Array.isArray(check)) return String(check);
  const [op, ...rest] = check;
  if (op === 'perm') {
    const [path, privs, ...opts] = rest;
    const any = opts.includes('any') ? ' (any of)' : '';
    return `${(privs ?? []).join(', ')}${any} on ${path}`;
  }
  if (op === 'and' || op === 'or') return `(${rest.map(describeCheck).join(` ${op} `)})`;
  if (op === 'admin') return 'administrator';
  if (op === 'userid-group') return `${(rest[0] ?? []).join(', ')} on the user's group`;
  if (op === 'userid-param') return `the user given in the parameters (${rest.join(' ')})`;
  return [op, ...rest.map((r) => (typeof r === 'string' ? r : JSON.stringify(r)))].join(' ');
}

function compactPermissions(permissions) {
  if (!permissions || Object.keys(permissions).length === 0) return undefined;
  const parts = [];
  if (permissions.check) parts.push(describeCheck(permissions.check));
  if (permissions.description) parts.push(trim(permissions.description, 300));
  if (permissions.user && !permissions.check) {
    if (permissions.user === 'all') parts.push(permissions.description ? '' : 'any authenticated user');
    else if (permissions.user === 'world') parts.push('no authentication needed');
    else parts.push(`user ${permissions.user}`);
  }
  const text = parts.filter(Boolean).join('. ');
  return text || undefined;
}

function compactReturns(returns) {
  if (!returns) return { type: 'null' };
  const out = { type: returns.type ?? 'null' };
  const description = trim(returns.description, 200);
  if (description) out.description = description;
  if (returns.properties) out.properties = Object.keys(returns.properties).sort();
  if (returns.items?.properties) out.itemProperties = Object.keys(returns.items.properties).sort();
  if (returns.links) out.links = true;
  return out;
}

function flatten(schema) {
  const methods = [];
  const walk = (nodes) => {
    for (const node of nodes) {
      for (const [method, info] of Object.entries(node.info ?? {})) {
        const entry = {
          method,
          path: node.path,
          name: info.name,
          description: DESCRIPTION_FIXES[`${method} ${node.path}`] ?? trim(info.description, MAX_METHOD_DESCRIPTION) ?? '',
          allowtoken: info.allowtoken !== 0,
          params: collectParams(info.parameters),
          returns: compactReturns(info.returns),
        };
        if (info.protected) entry.protected = true;
        if (info.proxyto) entry.proxyto = info.proxyto;
        if (info.expose_credentials) entry.expose_credentials = true;
        if (info.download_allowed) entry.download_allowed = true;
        const permissions = compactPermissions(info.permissions);
        if (permissions) entry.permissions = permissions;
        methods.push(entry);
      }
      if (node.children) walk(node.children);
    }
  };
  walk(schema);
  const order = { GET: 0, POST: 1, PUT: 2, DELETE: 3 };
  return methods.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : order[a.method] - order[b.method]));
}

async function main() {
  const fromAt = process.argv.indexOf('--from');
  let text;
  let source;
  // When the schema was published or fetched, never when this ran: the same input gives the same file.
  let date;
  if (fromAt >= 0) {
    const file = process.argv[fromAt + 1];
    if (!file) throw new Error('--from needs a file.');
    text = readFileSync(file, 'utf8');
    source = 'pve-docs api-viewer apidoc.js (local copy)';
    date = statSync(file).mtime;
  } else {
    const res = await fetch(SOURCE_URL, { headers: { 'User-Agent': 'pvemcp-catalog-builder' } });
    if (!res.ok) throw new Error(`${SOURCE_URL}: HTTP ${res.status}`);
    text = await res.text();
    source = SOURCE_URL;
    date = new Date(res.headers.get('last-modified') ?? Date.now());
  }
  const endpoints = flatten(extractSchema(text));
  const byMethod = {};
  for (const e of endpoints) byMethod[e.method] = (byMethod[e.method] ?? 0) + 1;
  const catalog = {
    source,
    schema_date: date.toISOString().slice(0, 10),
    // Stays stable across identical inputs, so that rebuilding produces no diff.
    schema_sha256: await sha256(text),
    counts: { total: endpoints.length, ...byMethod },
    endpoints,
  };
  mkdirSync(dirname(outFile), { recursive: true });
  const json = `${JSON.stringify(catalog)}\n`;
  writeFileSync(outFile, json);
  console.error(`${outFile}: ${endpoints.length} methods ${JSON.stringify(byMethod)}, ${(json.length / 1048576).toFixed(2)} MiB`);
}

async function sha256(text) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text).digest('hex');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
