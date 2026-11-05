import { ProxmoxError } from './errors.js';

export const REDACTED = '[REDACTED]';
/** What Proxmox itself shows instead of cipassword and the like. */
const PROXMOX_MASK = '**********';

const EXACT = new Set([
  'password',
  'secret',
  'key',
  'keys',
  'keyring',
  'ticket',
  'csrfpreventiontoken',
  'token',
  'cookie',
  'authorization',
  'cert',
  'certkey',
  'recovery',
  'otp',
  'totp',
]);

const SUBSTRINGS = ['password', 'passwd', 'passphrase', 'secret', 'credential', 'private_key', 'privatekey', 'private-key', 'authkey', 'auth_key', 'apikey', 'api_key', 'api-key', 'hmac', 'ticket', 'csrf', 'bindpw', 'lock-token', 'lock_token', 'encryption-key', 'encryption_key', 'client-key', 'client_key', 'psk', 'otel-headers'];

/** Keys that match a pattern above but hold nothing secret. Agents need these. */
const NOT_SECRET = new Set([
  'tokenid',
  'full-tokenid',
  'token-coefficient',
  'tokens',
  'sshkeys',
  'ssh-public-keys',
  'pubkey',
  'public_key',
  'public-key',
  'publickey',
  'fingerprint',
  'keyboard',
  'verify-certificate',
  'generate-password',
  'passwordauth',
  'hostkey',
  'host_key',
]);

export function isSensitiveKey(key: string): boolean {
  // Capitalised, this is the name of an APT repository option: {"Key": "Types", "Values": [...]}.
  if (key === 'Key') return false;
  const k = key.toLowerCase();
  if (NOT_SECRET.has(k)) return false;
  if (EXACT.has(k)) return true;
  if (SUBSTRINGS.some((s) => k.includes(s))) return true;
  return (k.endsWith('_key') || k.endsWith('-key')) && !k.includes('pub') && !k.includes('host');
}

const PEM_PRIVATE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;
/* eslint-disable-next-line no-control-regex */
const ANSI = /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\)|[@-Z\\^_])/g;
/* eslint-disable-next-line no-control-regex */
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\u009F]/g;
/** http://user:password@proxy: /cluster/options and storage URLs can hold this. */
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/:@]+:[^\s/@]+@/gi;
/** An API token as an Authorization header writes it, or the cookie of a login: task logs and error texts can quote them. */
const AUTH_HEADER = /\b(PVEAPIToken=|PVEAuthCookie=)[^\s;"',]+/g;
/** PVE:root@pam:65A1B2C3::signature, and PVEVNC:65A1B2C3::signature for a console. */
const PVE_TICKET = /\bPVE[A-Z]*:[^\s"',;]*::[A-Za-z0-9+/=_-]+/g;

/**
 * Removes key material from any free text and strips escape sequences and control characters:
 * logs, guest names and command output can carry attacker-chosen bytes.
 */
export function scrubText(text: string): string {
  return text
    .replace(PEM_PRIVATE, REDACTED)
    .replace(URL_CREDENTIALS, `$1${REDACTED}@`)
    .replace(AUTH_HEADER, `$1${REDACTED}`)
    .replace(PVE_TICKET, REDACTED)
    .replace(ANSI, '')
    .replace(CONTROL_CHARS, '');
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return true;
  if (Array.isArray(value)) return value.length === 0;
  return typeof value === 'object' && Object.keys(value).length === 0;
}

const NOTHING_KEPT: ReadonlySet<string> = new Set();
const WEBHOOK = /^\/cluster\/notifications\/endpoints\/webhook(?:\/|$)/;
const CONFIG_ROWS = /^\/nodes\/[^/]+\/(?:qemu|lxc)\/[^/]+\/pending$|^\/nodes\/[^/]+\/qemu\/[^/]+\/cloudinit$/;

export function redactJson<T>(value: T, keep: ReadonlySet<string> = NOTHING_KEPT): T {
  if (typeof value === 'string') return scrubText(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactJson(v, keep)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = !keep.has(k) && isSensitiveKey(k) && !isEmpty(v) ? REDACTED : redactJson(v, keep);
    }
    return out as T;
  }
  return value;
}

/**
 * Fields whose name says nothing, but whose content is a secret on this path:
 * a plugin's "data" holds DNS API credentials, a new token's "value" is the token itself.
 */
const PATH_RULES: Array<{ pattern: RegExp; keys: string[] }> = [
  { pattern: /^\/cluster\/acme\/plugins(?:\/|$)/, keys: ['data'] },
  { pattern: /^\/access\/users\/[^/]+\/token\/[^/]+$/, keys: ['value'] },
  { pattern: /^\/cluster\/config\/join$/, keys: ['corosync_authkey'] },
  { pattern: /^\/nodes\/[^/]+\/ceph\//, keys: ['keyring'] },
  { pattern: WEBHOOK, keys: ['header', 'body'] },
  { pattern: /^\/nodes\/[^/]+\/subscription$/, keys: ['signature'] },
];

/**
 * Fields whose name looks secret, but that are something else on this path, where masking them makes the
 * answer useless. "key" in the rows of pending changes is the name of the setting: {key: "cores", value: 4}.
 * "token" in the corosync configuration is a timeout.
 */
const KEEP_RULES: Array<{ pattern: RegExp; keys: ReadonlySet<string> }> = [
  { pattern: CONFIG_ROWS, keys: new Set(['key']) },
  { pattern: /^\/nodes\/[^/]+\/storage\/[^/]+\/import-metadata$/, keys: new Set(['key']) },
  { pattern: /^\/cluster\/config\/totem$/, keys: new Set(['token']) },
];

/** In these rows the setting is named by "key": cipassword must not show because it is called "value" there. */
function maskConfigRows(rows: unknown): unknown {
  if (!Array.isArray(rows)) return rows;
  return rows.map((row: unknown) => {
    if (!row || typeof row !== 'object') return row;
    const { key } = row as { key?: unknown };
    if (typeof key !== 'string' || !isSensitiveKey(key)) return row;
    const out: Record<string, unknown> = { ...row };
    for (const field of ['value', 'pending']) if (!isEmpty(out[field])) out[field] = REDACTED;
    return out;
  });
}

/** The address stays, for a human to recognise it. Its path is the credential on most chat services. */
function maskUrlPath(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.replace(/^([a-z][a-z0-9+.-]*:\/\/[^/?#]+)[/?#].*$/i, `$1/${REDACTED}`);
}

function maskWebhookUrls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(maskWebhookUrls);
  if (value && typeof value === 'object') {
    const row = value as Record<string, unknown>;
    return 'url' in row ? { ...row, url: maskUrlPath(row.url) } : value;
  }
  return value;
}

function maskKeys(value: unknown, keys: readonly string[]): unknown {
  if (Array.isArray(value)) return value.map((v) => maskKeys(v, keys));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = keys.includes(k) && !isEmpty(v) ? REDACTED : maskKeys(v, keys);
    return out;
  }
  return value;
}

/** Key-based redaction plus the rules for this path, given as a template or a concrete path. */
export function redactResponse<T>(path: string, value: T): T {
  const keep = KEEP_RULES.find((rule) => rule.pattern.test(path))?.keys ?? NOTHING_KEPT;
  let out: unknown = redactJson(value, keep);
  if (CONFIG_ROWS.test(path)) out = maskConfigRows(out);
  if (WEBHOOK.test(path)) out = maskWebhookUrls(out);
  for (const rule of PATH_RULES) {
    if (rule.pattern.test(path)) out = maskKeys(out, rule.keys);
  }
  return out as T;
}

/**
 * Parameters of a write that hold what they should not show in the audit log or a dry run, though their
 * name says nothing. Only on these paths: "content" elsewhere is a list of content types, useful to see.
 */
const REQUEST_RULES: Array<{ pattern: RegExp; keys: string[] }> = [
  { pattern: /^\/cluster\/acme\/plugins(?:\/|$)/, keys: ['data'] },
  { pattern: /^\/nodes\/[^/]+\/qemu\/[^/]+\/agent\/file-write$/, keys: ['content'] },
  { pattern: /^\/nodes\/[^/]+\/qemu\/[^/]+\/agent\/exec$/, keys: ['input-data'] },
  { pattern: /^\/access\/tfa\/[^/]+(?:\/[^/]+)?$/, keys: ['value'] },
  { pattern: WEBHOOK, keys: ['header', 'body'] },
];

/** What a write sent, as it may be logged or shown back. Takes a template or a concrete path. */
export function redactRequest<T>(path: string, params: T): T {
  let out: unknown = redactJson(params);
  if (WEBHOOK.test(path)) out = maskWebhookUrls(out);
  for (const rule of REQUEST_RULES) {
    if (rule.pattern.test(path)) out = maskKeys(out, rule.keys);
  }
  return out as T;
}

/** A placeholder written back as a real value would overwrite the secret it stands for. */
export function assertNoRedactedValue(value: unknown, path: string): void {
  if (typeof value === 'string') {
    if (value.includes(REDACTED) || value.includes(PROXMOX_MASK)) {
      throw new ProxmoxError('invalid_input', `The request to ${path} contains a redaction placeholder (${value.includes(REDACTED) ? REDACTED : PROXMOX_MASK}), which would overwrite a real secret.`, {
        hint: 'Leave the field out to keep its current value.',
      });
    }
    return;
  }
  if (Array.isArray(value)) value.forEach((v) => assertNoRedactedValue(v, path));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => assertNoRedactedValue(v, path));
}
