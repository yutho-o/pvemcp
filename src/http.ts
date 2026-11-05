import { timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { isIP } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ProxmoxError } from './proxmox/errors.js';
import type { Runtime } from './runtime.js';
import { createServer } from './server.js';

export interface HttpOptions {
  host: string;
  port: number;
  /** Bearer token. Required unless the server only listens on the loopback interface. */
  token?: string;
  /** Extra values accepted in the Host header, for a reverse proxy. */
  allowedHosts?: string[];
}

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '::1' || host.startsWith('127.');
}

function tokenMatches(header: string | undefined, token: string): boolean {
  const given = Buffer.from(header ?? '');
  const wanted = Buffer.from(`Bearer ${token}`);
  return given.length === wanted.length && timingSafeEqual(given, wanted);
}

/**
 * Streamable HTTP without sessions: each request gets its own MCP server over the shared
 * runtime, which holds the API clients and the SSH sessions. Without a session there is
 * nobody to ask, so elicitation does not apply: the client has to rely on the destructive
 * annotation of the tools.
 */
export function startHttp(runtime: Runtime, options: HttpOptions): Promise<http.Server> {
  const { host, token } = options;
  if (!token && !isLoopback(host)) {
    throw new ProxmoxError('config_error', `Refusing to listen on ${host} without a token: anyone on the network could drive the cluster.`, {
      hint: 'Set PROXMOX_MCP_TOKEN, or listen on 127.0.0.1.',
    });
  }

  const allowed = new Set<string>(options.allowedHosts ?? []);
  const server = http.createServer((req, res) => {
    const deny = (status: number, message: string) => {
      res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: message }));
    };
    // A web page can make a browser call a local address: checking Host stops DNS rebinding.
    if (!allowed.has(req.headers.host ?? '')) return deny(403, 'Host not allowed. See PROXMOX_MCP_ALLOWED_HOSTS.');
    if (token && !tokenMatches(req.headers.authorization, token)) return deny(401, 'Invalid or missing bearer token.');
    // Not new URL(): it throws on "//", and an uncaught error here would stop the process.
    if ((req.url ?? '/').split('?')[0] !== '/mcp') return deny(404, 'Not found. The endpoint is /mcp.');
    if (req.method !== 'POST') return deny(405, 'This server keeps no session: only POST is supported.');

    const mcp = createServer(runtime);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void mcp.close();
    });
    mcp
      .connect(transport)
      .then(() => transport.handleRequest(req, res))
      .catch((err: Error) => {
        console.error(`[pvemcp] request failed: ${err.message}`);
        if (!res.headersSent) deny(500, 'Internal error.');
      });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, host, () => {
      const { port } = server.address() as AddressInfo;
      const shown = isIP(host) === 6 ? `[${host}]` : host;
      for (const name of [shown, 'localhost', '127.0.0.1', '[::1]']) {
        if (name === shown || isLoopback(host)) allowed.add(`${name}:${port}`);
      }
      console.error(`[pvemcp] listening on http://${shown}:${port}/mcp`);
      resolve(server);
    });
  });
}
