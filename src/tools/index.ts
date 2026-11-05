import { apiTools } from './api.js';
import { endpointTools } from './endpoints.js';
import type { ToolDef } from './helpers.js';
import { infoTools } from './info.js';
import { sshGuestTools } from './ssh-guest.js';
import { sshLxcTools } from './ssh-lxc.js';
import { sshNodeTools } from './ssh-node.js';
import { sshSessionTools } from './ssh-session.js';
import { workflowTools } from './workflows.js';

/** Every tool: one per API method, then what the API alone does not offer. */
export function allTools(info: () => Record<string, unknown>): ToolDef[] {
  return [
    ...infoTools(info),
    ...workflowTools(),
    ...endpointTools(),
    ...sshNodeTools(),
    ...sshLxcTools(),
    ...sshGuestTools(),
    ...sshSessionTools(),
    ...apiTools(),
  ];
}
