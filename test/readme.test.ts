import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ALL_GATES, listTools, type Env } from './harness.js';

/** What the README claims in numbers and names, against the binary: it must not drift. */
const ROOT = join(import.meta.dirname, '..');
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

type Tool = ReturnType<typeof listTools>[number];

/** The cells of the README table row that starts with this. */
function row(first: string): string[] {
  const line = readme.split('\n').find((l) => l.startsWith(`| ${first} |`));
  if (!line) throw new Error(`No row for ${first} in the README.`);
  return line.split('|').slice(2, -1).map((c) => c.trim());
}

function isReadOnlyDomainTool(t: Tool): boolean {
  // The GET half of guest_exec counts with its gate in the README, as the gate table shows it.
  return t.gate === 'read' || t.gate === 'sensitive' || t.gate === 'ssh_read';
}

describe('README', () => {
  const all = listTools(ALL_GATES);

  it('gives the real number of tools per domain', () => {
    const domains = [...new Set(all.map((t) => t.domain))];
    expect(domains.length).toBeGreaterThan(5);
    for (const domain of domains) {
      const tools = all.filter((t) => t.domain === domain);
      const [read, write] = row(`\`${domain}\``);
      expect(Number(read), `${domain}: read`).toBe(tools.filter(isReadOnlyDomainTool).length);
      expect(Number(write), `${domain}: write`).toBe(tools.filter((t) => !isReadOnlyDomainTool(t)).length);
    }
  });

  it('gives the real number of tools per gate', () => {
    for (const gate of ['read', 'sensitive', 'write', 'elevated', 'guest_exec', 'console', 'ssh_read', 'ssh_write']) {
      expect(Number(row(`\`${gate}\``)[0]), gate).toBe(all.filter((t) => t.gate === gate).length);
    }
    expect(readme).toContain(`Soit ${all.length} outils au total`);
  });

  it('gives the real number of tools per configuration', () => {
    const flags: Env = { ...ALL_GATES };
    delete flags.PROXMOX_TOOLSETS;
    const ssh = { PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_PASSWORD: 'x' };
    const cases: Array<[string, Env]> = [
      ['Lecture seule, défaut', {}],
      ['Écritures, domaines par défaut', { PROXMOX_ALLOW_WRITES: 'true' }],
      ['Toutes les options, domaines par défaut', flags],
      ['Toutes les options, `PROXMOX_TOOLSETS=all`', ALL_GATES],
      ['`api,ssh`, `ALLOW_SSH` seul', { ...ssh, PROXMOX_TOOLSETS: 'api,ssh' }],
      ['`api,ssh`, toutes les options', { ...ALL_GATES, PROXMOX_TOOLSETS: 'api,ssh' }],
      ['`workflows,api`, lecture seule', { PROXMOX_TOOLSETS: 'workflows,api' }],
    ];
    for (const [name, env] of cases) expect(Number(row(name)[0]), name).toBe(listTools(env).length);
  });

  it('documents every variable the code reads', () => {
    const source = (dir: string): string =>
      readdirSync(dir, { withFileTypes: true })
        .map((e) => (e.isDirectory() ? source(join(dir, e.name)) : e.name.endsWith('.rs') ? readFileSync(join(dir, e.name), 'utf8') : ''))
        .join('\n');
    const names = new Set(source(join(ROOT, 'src')).match(/\bPROXMOX_[A-Z_]+\b/g));
    names.delete('PROXMOX_MASK'); // A constant: the mask Proxmox shows instead of a secret.
    expect(names.size).toBeGreaterThan(40);
    for (const name of names) expect(readme, name).toContain(name);
  });

  it('names only tools that exist', () => {
    const known = new Set(all.map((t) => t.name));
    for (const name of new Set(readme.match(/\bpve_[a-z0-9_]+\b/g))) expect(known.has(name), name).toBe(true);
  });

  it('says it was tested against fakes, and gives no false promise on elicitation', () => {
    expect(readme).toMatch(/n'a jamais parlé à un vrai Proxmox/);
    expect(readme).toMatch(/Si le client ne le sait pas, rien n'est demandé/);
  });
});

// examples/instances.json loading moved to src/config.rs (the_instances_example_loads_as_it_is).
describe('examples', () => {
  it('mcp.json is valid and starts the built binary', () => {
    const mcp = JSON.parse(readFileSync(join(ROOT, 'examples', 'mcp.json'), 'utf8')) as { mcpServers: Record<string, { command: string; args?: string[]; env: Env }> };
    const proxmox = mcp.mcpServers.proxmox!;
    expect(proxmox.command).toMatch(/pvemcp(?:\.exe)?$/);
    expect(proxmox.command).not.toMatch(/\bnode\b/);
    expect(proxmox.env.PROXMOX_URL).toBeTruthy();
    expect(JSON.stringify(mcp)).not.toMatch(/ALLOW_(?:WRITES|SSH|ELEVATED)/);
  });
});

describe('.gitignore', () => {
  const ignore = readFileSync(join(ROOT, '.gitignore'), 'utf8').split(/\r?\n/);

  it('covers the secrets and keeps the examples', () => {
    for (const pattern of ['.env', 'instances.json', '*.token', '*.pem', '*.key', 'known_hosts', '*.jsonl', '.mcp.json']) expect(ignore, pattern).toContain(pattern);
    expect(ignore).toContain('!examples/instances.json');
  });
});
