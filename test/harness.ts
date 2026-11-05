import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadConfig, type Env } from '../src/config.js';
import { Runtime, type RuntimeOptions } from '../src/runtime.js';
import { createServer } from '../src/server.js';
import { FAKE_TOKEN, FakePve, type FakeOptions } from './fake-pve.js';

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
  runtime: Runtime;
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
  runtime?: RuntimeOptions;
}

/** Fake Proxmox, real runtime, real MCP server and client over an in-memory transport. */
export async function connect(opts: ConnectOptions = {}): Promise<Harness> {
  let fake: FakePve;
  if (opts.fake instanceof FakePve) {
    fake = opts.fake;
  } else {
    fake = new FakePve(opts.fake);
    await fake.start();
  }
  const runtime = new Runtime(loadConfig({ PROXMOX_URL: fake.url, PROXMOX_TOKEN: FAKE_TOKEN, ...opts.env }), opts.runtime);
  const server = createServer(runtime);
  const client = new Client({ name: 'test', version: '1' }, { capabilities: opts.onElicit ? { elicitation: { form: {} } } : {} });
  if (opts.onElicit) {
    const handler = opts.onElicit;
    client.setRequestHandler(ElicitRequestSchema, (req) => handler(req.params.message));
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  cleanups.push(() => client.close(), () => server.close(), () => runtime.shutdown(), () => fake.stop());
  return {
    fake,
    client,
    runtime,
    call: async (name, args = {}) => {
      const res = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
      const text = res.content[0]!.text;
      let data: Record<string, any>;
      try {
        data = JSON.parse(text);
      } catch {
        // Argument validation by the SDK answers in plain text.
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
  // SSH refuses to start without a credential. Nothing connects unless a test gives a transport.
  PROXMOX_SSH_PASSWORD: 'unused',
  PROXMOX_TOOLSETS: 'all',
};
