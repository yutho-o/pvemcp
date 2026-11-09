import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { FAKE_TOKEN, FakePve, type FakeOptions } from './fake-pve.js';

export type Env = Record<string, string | undefined>;

/** The Rust binary under test: PVEMCP_BIN, else the release build, else the debug build. */
export function binary(): string {
  if (process.env.PVEMCP_BIN) return process.env.PVEMCP_BIN;
  const exe = process.platform === 'win32' ? 'pvemcp.exe' : 'pvemcp';
  const root = join(import.meta.dirname, '..', 'target');
  for (const build of ['release', 'debug']) {
    const path = join(root, build, exe);
    if (existsSync(path)) return path;
  }
  throw new Error('No pvemcp binary: run cargo build first, or set PVEMCP_BIN.');
}

/** What pvemcp --list-tools prints for this environment: every tool it would show, with its domain and gate. */
export function listTools(env: Env): Array<{ domain: string; gate: string; name: string }> {
  const run = spawnSync(binary(), ['--list-tools'], { env: { ...getDefaultEnvironment(), PROXMOX_URL: 'https://127.0.0.1:8006', PROXMOX_TOKEN: FAKE_TOKEN, ...env }, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`pvemcp --list-tools failed: ${run.stderr}`);
  return run.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [domain, gate, name] = line.split('\t') as [string, string, string];
      return { domain, gate, name };
    });
}

/** Everything the last connect() calls set up. Call closeAll() in afterEach. */
const cleanups: Array<() => Promise<unknown> | unknown> = [];

export async function closeAll(): Promise<void> {
  for (const cleanup of cleanups.splice(0)) {
    try {
      await cleanup();
    } catch {
      /* already gone */
    }
  }
}

export interface Harness {
  fake: FakePve;
  client: Client;
  /** What the server wrote on stderr so far. */
  stderr: () => string;
  /** Calls a tool through a real MCP client. data is the parsed JSON text of the answer. */
  call: (name: string, args?: Record<string, unknown>) => Promise<{ data: Record<string, any>; isError: boolean; text: string }>;
  toolNames: () => Promise<string[]>;
}

export interface ConnectOptions {
  /** An already started fake, or options to start one. */
  fake?: FakePve | FakeOptions;
  env?: Env;
  /** Makes the client advertise elicitation and answer with this. */
  onElicit?: (message: string) => { action: 'accept' | 'decline' | 'cancel'; content?: Record<string, unknown> };
}

/** Starts the binary over stdio with this environment, and connects a real MCP client to it. */
export async function spawnServer(env: Env, onElicit?: ConnectOptions['onElicit']): Promise<{ client: Client; stderr: () => string }> {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (v !== undefined) clean[k] = v;
  const transport = new StdioClientTransport({ command: binary(), args: [], env: clean, stderr: 'pipe' });
  let errors = '';
  transport.stderr?.on('data', (chunk: Buffer) => {
    errors += chunk.toString();
  });
  const client = new Client({ name: 'test', version: '1' }, { capabilities: onElicit ? { elicitation: { form: {} } } : {} });
  if (onElicit) client.setRequestHandler(ElicitRequestSchema, (req) => onElicit(req.params.message));
  try {
    await client.connect(transport);
  } catch (err) {
    throw new Error(`${(err as Error).message}\n${errors}`);
  }
  cleanups.push(() => client.close());
  return { client, stderr: () => errors };
}

/** Fake Proxmox, the real server binary, and a real MCP client over stdio. */
export async function connect(opts: ConnectOptions = {}): Promise<Harness> {
  let fake: FakePve;
  if (opts.fake instanceof FakePve) {
    fake = opts.fake;
  } else {
    fake = new FakePve(opts.fake);
    await fake.start();
  }
  const { client, stderr } = await spawnServer({ PROXMOX_URL: fake.url, PROXMOX_TOKEN: FAKE_TOKEN, ...opts.env }, opts.onElicit);
  cleanups.push(() => fake.stop());
  return {
    fake,
    client,
    stderr,
    call: async (name, args = {}) => {
      const res = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
      const text = res.content[0]!.text;
      let data: Record<string, any>;
      try {
        data = JSON.parse(text);
      } catch {
        // Argument validation answers in plain text.
        data = { text };
      }
      return { data, isError: res.isError === true, text };
    },
    toolNames: async () => (await client.listTools()).tools.map((t) => t.name),
  };
}

/** A write-enabled configuration, to spread into env. */
export const WRITES: Env = { PROXMOX_ALLOW_WRITES: 'true' };
/** Every gate open. */
export const ALL_GATES: Env = {
  PROXMOX_ALLOW_WRITES: 'true',
  PROXMOX_ALLOW_ELEVATED: 'true',
  PROXMOX_ALLOW_GUEST_EXEC: 'true',
  PROXMOX_ALLOW_SENSITIVE: 'true',
  PROXMOX_ALLOW_SSH: 'true',
  // SSH refuses to start without a credential. Nothing connects unless a test gives a host.
  PROXMOX_SSH_PASSWORD: 'unused',
  PROXMOX_TOOLSETS: 'all',
};
