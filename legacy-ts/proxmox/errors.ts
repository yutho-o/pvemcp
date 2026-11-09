export type ErrorType =
  // Refused by this server's own policy.
  | 'write_disabled'
  | 'elevated_disabled'
  | 'guest_exec_disabled'
  | 'sensitive_disabled'
  | 'ssh_disabled'
  | 'blocked_endpoint'
  | 'not_read_only'
  | 'protected_guest'
  | 'invalid_path'
  | 'invalid_input'
  | 'config_error'
  | 'user_cancelled'
  | 'local_path_refused'
  // Answers from Proxmox.
  | 'validation_failed'
  | 'auth_failed'
  | 'forbidden'
  | 'not_found'
  | 'not_supported'
  | 'guest_locked'
  | 'upstream_error'
  | 'node_unreachable'
  | 'bad_response'
  // Transport.
  | 'tls_error'
  | 'unreachable'
  | 'timeout'
  // Tasks.
  | 'task_failed'
  | 'task_timeout'
  // SSH.
  | 'host_key_unknown'
  | 'host_key_mismatch'
  | 'ssh_auth_failed'
  | 'ssh_unreachable'
  | 'ssh_timeout'
  | 'ssh_output_too_large'
  | 'guest_not_running';

/**
 * Every failure carries a type and, where it helps, a hint telling the agent what
 * to do next (and just as importantly what not to retry).
 */
export class ProxmoxError extends Error {
  constructor(
    readonly type: ErrorType,
    message: string,
    readonly options: { hint?: string; status?: number; details?: unknown } = {},
  ) {
    super(message);
    this.name = 'ProxmoxError';
  }

  get status(): number | undefined {
    return this.options.status;
  }

  get hint(): string | undefined {
    return this.options.hint;
  }

  get details(): unknown {
    return this.options.details;
  }

  toJSON(): Record<string, unknown> {
    return {
      error: this.message,
      error_type: this.type,
      ...(this.options.status !== undefined ? { http_status: this.options.status } : {}),
      ...(this.options.hint ? { hint: this.options.hint } : {}),
      ...(this.options.details !== undefined ? { details: this.options.details } : {}),
    };
  }
}
