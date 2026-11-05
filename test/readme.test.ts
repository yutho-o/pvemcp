import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig, type Env } from '../src/config.js';
import { Runtime } from '../src/runtime.js';
import { visibleTools } from '../src/server.js';
import { DOMAINS, type ToolDef } from '../src/tools/helpers.js';
import { ALL_GATES } from './harness.js';

/** What the README claims in numbers and names, against the code: it must not drift. */
const ROOT = join(import.meta.dirname, '..');
const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
const BASE: Env = { PROXMOX_URL: 'https://pve:8006', PROXMOX_TOKEN: 'a@pam!b=c' };

function list(env: Env) {
  const runtime = new Runtime(loadConfig({ ...BASE, ...env }));
  return visibleTools(runtime);
}

/** The cells of the README table row that starts with this. */
function row(first: string): string[] {
  const line = readme.split('\n').find((l) => l.startsWith(`| ${first} |`));
  if (!line) throw new Error(`No row for ${first} in the README.`);
  return line.split('|').slice(2, -1).map((c) => c.trim());
}

describe('README', () => {
  const all = list(ALL_GATES);

  it('gives the real number of tools per domain', () => {
    for (const domain of DOMAINS) {
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
    const flags = { ...ALL_GATES } as Record<string, string | undefined>;
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
    for (const [name, env] of cases) expect(Number(row(name)[0]), name).toBe(list(env).length);
  });

  it('documents every variable the code reads', () => {
    const source = (dir: string): string =>
      readdirSync(dir, { withFileTypes: true })
        .map((e) => (e.isDirectory() ? source(join(dir, e.name)) : e.name.endsWith('.ts') ? readFileSync(join(dir, e.name), 'utf8') : ''))
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

function isReadOnlyDomainTool(t: ToolDef): boolean {
  // The GET half of guest_exec counts with its gate in the README, as the gate table shows it.
  return t.gate === 'read' || t.gate === 'sensitive' || t.gate === 'ssh_read';
}

describe('examples', () => {
  it('instances.json loads as it is, and every ${VARIABLE} is expanded, nested ones too', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pvemcp-examples-'));
    try {
      const key = join(dir, 'key');
      writeFileSync(key, 'unused');
      const pin = `SHA256:${'A'.repeat(43)}`;
      const config = loadConfig({
        PROXMOX_CONFIG: join(ROOT, 'examples', 'instances.json'),
        PVE_LAB_TOKEN: 'mcp@pve!pvemcp=secret',
        PVE_LAB_FINGERPRINT: 'AA:'.repeat(31) + 'AA',
        PVE_LAB_LOCAL_DIR: dir,
        PVE_LAB_SSH_KEY_FILE: key,
        PVE1_HOST_KEY: pin,
        PVE_PROD_TOKEN_SECRET: 'secret',
      });
      expect([...config.instances.keys()]).toEqual(['lab', 'prod']);
      expect(config.defaultInstance).toBe('lab');
      const lab = config.instances.get('lab')!;
      expect(lab.allowSsh).toBe(true);
      expect(lab.ssh.fingerprints.pve1).toBe(pin);
      expect(lab.ssh.nodes.pve2).toBe('10.0.0.12');
      const prod = config.instances.get('prod')!;
      expect(prod.allowWrites).toBe(false);
      expect(prod.dryRun).toBe(true);
      expect([...prod.protectedVmids]).toEqual([100, 101]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('mcp.json is valid and starts the built server', () => {
    const mcp = JSON.parse(readFileSync(join(ROOT, 'examples', 'mcp.json'), 'utf8')) as { mcpServers: Record<string, { command: string; args: string[]; env: Env }> };
    expect(mcp.mcpServers.proxmox!.command).toBe('node');
    expect(mcp.mcpServers.proxmox!.args[0]).toMatch(/dist\/index\.js$/);
    expect(mcp.mcpServers.proxmox!.env.PROXMOX_URL).toBeTruthy();
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
