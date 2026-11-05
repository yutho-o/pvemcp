import { tool, type ToolDef } from './helpers.js';

export function infoTools(info: () => Record<string, unknown>): ToolDef[] {
  return [
    tool({
      name: 'pve_mcp_info',
      title: 'About this server',
      description: 'Says what this server allows, per cluster: read-only or not, elevated changes, guest execution, SSH, sensitive data, dry run, protected guests, which toolsets are loaded and how many tools. Call this first.',
      domain: 'api',
      gate: 'read',
      idempotent: true,
      input: {},
      handler: async () => info(),
    }),
  ];
}
