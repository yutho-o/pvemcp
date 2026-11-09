// Dumps what the TypeScript server announces, as a reference for the Rust port.
import { writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { loadConfig } from '../dist/config.js';
import { Runtime } from '../dist/runtime.js';
import { createServer } from '../dist/server.js';

const base = { PROXMOX_URL: 'https://127.0.0.1:8006', PROXMOX_TOKEN: 'mcp@pve!test=00000000-0000-0000-0000-000000000000' };
const configs = {
  default: {},
  all: { PROXMOX_ALLOW_WRITES: 'true', PROXMOX_ALLOW_ELEVATED: 'true', PROXMOX_ALLOW_GUEST_EXEC: 'true', PROXMOX_ALLOW_SENSITIVE: 'true', PROXMOX_ALLOW_SSH: 'true', PROXMOX_SSH_PASSWORD: 'x', PROXMOX_TOOLSETS: 'all' },
  writes: { PROXMOX_ALLOW_WRITES: 'true' },
};
for (const [name, env] of Object.entries(configs)) {
  const runtime = new Runtime(loadConfig({ ...base, ...env }));
  const server = createServer(runtime);
  const client = new Client({ name: 'dump', version: '1' }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  const tools = (await client.listTools()).tools;
  const prompts = (await client.listPrompts()).prompts;
  const resources = (await client.listResources()).resources;
  writeFileSync(new URL(`./${name}.tools.json`, import.meta.url), JSON.stringify(tools, null, 1));
  writeFileSync(new URL(`./${name}.prompts.json`, import.meta.url), JSON.stringify(prompts, null, 1));
  writeFileSync(new URL(`./${name}.resources.json`, import.meta.url), JSON.stringify(resources, null, 1));
  writeFileSync(new URL(`./${name}.instructions.txt`, import.meta.url), client.getInstructions() ?? '');
  writeFileSync(new URL(`./${name}.server.json`, import.meta.url), JSON.stringify({ version: client.getServerVersion(), capabilities: client.getServerCapabilities() }, null, 1));
  console.log(name, tools.length);
  await client.close(); await server.close(); await runtime.shutdown();
}
