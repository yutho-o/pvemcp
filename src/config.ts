import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ProxmoxError } from './proxmox/errors.js';

export type HostKeyPolicy = 'strict' | 'accept-new' | 'off';

export interface SshConfig {
  user: string;
  port: number;
  keyFile?: string;
  keyPassphrase?: string;
  password?: string;
  /** Socket path, or "pageant". */
  agent?: string;
  /** Node name to host. */
  nodes: Record<string, string>;
  /** Prefixes commands with sudo -n when the user is not root. */
  sudo: boolean;
  knownHosts: string;
  hostKeyPolicy: HostKeyPolicy;
  /** Node name to pinned SHA256:... fingerprint. */
  fingerprints: Record<string, string>;
  timeoutMs: number;
  maxOutputBytes: number;
  guestUser?: string;
  guestKeyFile?: string;
  guestPassword?: string;
}

export interface InstanceConfig {
  name: string;
  /** Base URL without trailing slash and without /api2/json. The port is always there. */
  url: string;
  /** user@realm!tokenid */
  tokenId?: string;
  tokenSecret?: string;
  username?: string;
  password?: string;
  verifySsl: boolean;
  /** PEM bundle to trust, for a self-signed certificate with verification kept on. */
  ca?: string;
  /** sha256 of the server certificate, upper-case hex with colons. */
  fingerprint?: string;
  allowWrites: boolean;
  allowElevated: boolean;
  allowGuestExec: boolean;
  allowSsh: boolean;
  allowSensitive: boolean;
  dryRun: boolean;
  defaultNode?: string;
  protectedVmids: Set<number>;
  description?: string;
  timeoutMs: number;
  /** Root for local file transfers. None means they are refused. */
  localDir?: string;
  ssh: SshConfig;
}

export interface ServerConfig {
  instances: Map<string, InstanceConfig>;
  defaultInstance: string;
  /** null means the default toolsets. */
  toolsets: Set<string> | null;
  taskWaitSeconds: number;
  auditLog?: string;
  /** Endpoints the operator explicitly removed from the blocklist, as "METHOD /template" or "/template". */
  unblocked: string[];
  elicit: boolean;
  maxResponseChars: number;
}

export type Env = Record<string, string | undefined>;

const INSTANCE_NAME = /^[A-Za-z0-9_-]{1,32}$/;
const TRUE_VALUES = new Set(['true', '1', 'yes', 'on']);
const FALSE_VALUES = new Set(['false', '0', 'no', 'off', '']);
const FULL_TOKEN = /^([^\s@!=]+@[^\s@!=]+![A-Za-z][A-Za-z0-9._-]*)=(\S+)$/;
const TOKEN_ID = /^[^\s@!=]+@[^\s@!=]+![A-Za-z][A-Za-z0-9._-]*$/;
const HOST_KEY_POLICIES = new Set<string>(['strict', 'accept-new', 'off']);
const NODE_NAME = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;

function configError(message: string, hint?: string): ProxmoxError {
  return new ProxmoxError('config_error', message, hint ? { hint } : {});
}

/** A typo in a safety flag must stop the server, not silently fall back to a default. */
function parseBool(name: string, value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  const v = String(value).trim().toLowerCase();
  if (TRUE_VALUES.has(v)) return true;
  if (FALSE_VALUES.has(v)) return false;
  throw configError(`${name}: "${String(value)}" is not a boolean (use true or false).`);
}

function parseInteger(name: string, value: unknown, fallback: number, min: number, max: number): number {
  if (value === undefined || value === null || value === '') return fallback;
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw configError(`${name}: "${String(value)}" must be an integer between ${min} and ${max}.`);
  }
  return n;
}

function normalizeUrl(raw: string, label: string): string {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw configError(`${label}: "${raw}" is not a valid URL.`, 'Example: https://192.168.1.10:8006');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw configError(`${label}: only http and https URLs are supported.`);
  if (url.username || url.password) throw configError(`${label}: do not put credentials in the URL.`);
  // URL drops :443 on https, so "no port given" has to be read from the text itself.
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(withScheme)?.[1] ?? '';
  const hasPort = /(?:\]|^[^[\]]*):\d+$/.test(authority);
  const host = hasPort ? authority : `${url.hostname}:8006`;
  const path = url.pathname.replace(/\/+$/, '').replace(/\/api2(?:\/json)?$/, '');
  return `${url.protocol}//${host}${path}`;
}

/** sha256 of a certificate, as Proxmox and openssl show it. */
export function normalizeFingerprint(raw: string, label: string): string {
  const hex = raw.trim().replace(/^sha256[:=]/i, '').replace(/:/g, '').toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(hex)) {
    throw configError(`${label}: expected a sha256 fingerprint (64 hex digits, colons allowed).`, 'On the node, pvenode cert info shows it. The web interface has it under Node > System > Certificates.');
  }
  return hex.match(/.{2}/g)!.join(':');
}

interface Credentials {
  token?: string;
  tokenId?: string;
  tokenSecret?: string;
  username?: string;
  password?: string;
}

/** key=value lines, or a single user@realm!id=secret line. */
function readCredentialsFile(path: string): Credentials {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw configError(`Cannot read credentials file ${path}: ${(err as Error).message}`);
  }
  const out: Credentials = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (FULL_TOKEN.test(line)) {
      out.token = line;
      continue;
    }
    const m = /^(token|token_id|token_secret|username|password)\s*=\s*(.+)$/.exec(line);
    if (m?.[1] === 'token') out.token = m[2];
    if (m?.[1] === 'token_id') out.tokenId = m[2];
    if (m?.[1] === 'token_secret') out.tokenSecret = m[2];
    if (m?.[1] === 'username') out.username = m[2];
    if (m?.[1] === 'password') out.password = m[2];
  }
  return out;
}

function readTextFile(path: string, label: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    throw configError(`Cannot read ${label} ${path}: ${(err as Error).message}`);
  }
}

/** Expands ${VAR} so instances.json never has to hold a secret in clear text. */
function expand(value: unknown, env: Env, where: string): unknown {
  if (Array.isArray(value)) return value.map((v) => expand(v, env, where));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expand(v, env, where)]));
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name: string) => {
    const v = env[name];
    if (v === undefined) throw configError(`${where}: environment variable ${name} is not set.`);
    return v;
  });
}

function expandHome(path: string): string {
  return path === '~' ? homedir() : path.startsWith('~/') || path.startsWith('~\\') ? join(homedir(), path.slice(2)) : path;
}

/** JSON object, or a=1,b=2. Values may hold "=": an SSH fingerprint in base64 can. */
export function parseMap(name: string, value: unknown): Record<string, string> {
  if (value === undefined || value === null || value === '') return {};
  const out: Record<string, string> = {};
  const put = (k: string, v: unknown) => {
    if (typeof v !== 'string' || v === '' || !NODE_NAME.test(k)) throw configError(`${name}: invalid entry "${k}".`, 'Use JSON or name=value,name=value.');
    out[k] = v;
  };
  if (typeof value === 'object' && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) put(k, v);
    return out;
  }
  if (typeof value !== 'string') throw configError(`${name}: expected an object or name=value,name=value.`);
  const text = value.trim();
  if (text.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw configError(`${name}: invalid JSON: ${(err as Error).message}`);
    }
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) put(k, v);
    return out;
  }
  for (const item of text.split(',')) {
    const at = item.indexOf('=');
    if (at <= 0) throw configError(`${name}: "${item}" is not name=value.`);
    put(item.slice(0, at).trim(), item.slice(at + 1).trim());
  }
  return out;
}

function parseVmids(name: string, value: unknown): Set<number> {
  if (value === undefined || value === null || value === '') return new Set();
  const items = Array.isArray(value) ? value : String(value).split(',').map((s) => s.trim()).filter(Boolean);
  const out = new Set<number>();
  for (const item of items) {
    const n = Number(item);
    if (!Number.isInteger(n) || n < 1 || n > 999_999_999) throw configError(`${name}: "${String(item)}" is not a vmid.`);
    out.add(n);
  }
  return out;
}

interface RawSsh {
  user?: unknown;
  port?: unknown;
  key_file?: unknown;
  key_passphrase?: unknown;
  password?: unknown;
  agent?: unknown;
  nodes?: unknown;
  sudo?: unknown;
  known_hosts?: unknown;
  host_key_policy?: unknown;
  fingerprints?: unknown;
  timeout_seconds?: unknown;
  max_output_bytes?: unknown;
  guest_user?: unknown;
  guest_key_file?: unknown;
  guest_password?: unknown;
}

interface RawInstance {
  url?: unknown;
  token?: unknown;
  token_id?: unknown;
  token_secret?: unknown;
  credentials_file?: unknown;
  username?: unknown;
  password?: unknown;
  verify_ssl?: unknown;
  ca_file?: unknown;
  fingerprint?: unknown;
  allow_writes?: unknown;
  allow_elevated?: unknown;
  allow_guest_exec?: unknown;
  allow_ssh?: unknown;
  allow_sensitive?: unknown;
  dry_run?: unknown;
  default_node?: unknown;
  protected_vmids?: unknown;
  description?: unknown;
  timeout_seconds?: unknown;
  local_dir?: unknown;
  ssh?: RawSsh;
}

interface Defaults {
  allowWrites: boolean;
  allowElevated: boolean;
  allowGuestExec: boolean;
  allowSsh: boolean;
  allowSensitive: boolean;
  dryRun: boolean;
  verifySsl: boolean;
  timeoutMs: number;
  defaultNode?: string;
  protectedVmids: Set<number>;
  localDir?: string;
  ca?: string;
  fingerprint?: string;
  ssh: RawSsh;
}

/** What was read from the environment, already expanded: the instance values override it. */
function sshFromEnv(env: Env): RawSsh {
  return {
    user: env.PROXMOX_SSH_USER,
    port: env.PROXMOX_SSH_PORT,
    key_file: env.PROXMOX_SSH_KEY_FILE,
    key_passphrase: env.PROXMOX_SSH_KEY_PASSPHRASE,
    password: env.PROXMOX_SSH_PASSWORD,
    agent: env.PROXMOX_SSH_AGENT,
    nodes: env.PROXMOX_SSH_NODES,
    sudo: env.PROXMOX_SSH_SUDO,
    known_hosts: env.PROXMOX_SSH_KNOWN_HOSTS,
    host_key_policy: env.PROXMOX_SSH_HOST_KEY_POLICY,
    fingerprints: env.PROXMOX_SSH_FINGERPRINTS,
    timeout_seconds: env.PROXMOX_SSH_TIMEOUT_SECONDS,
    max_output_bytes: env.PROXMOX_SSH_MAX_OUTPUT_BYTES,
    guest_user: env.PROXMOX_GUEST_SSH_USER,
    guest_key_file: env.PROXMOX_GUEST_SSH_KEY_FILE,
    guest_password: env.PROXMOX_GUEST_SSH_PASSWORD,
  };
}

function buildSsh(where: string, rawInstance: RawSsh | undefined, defaults: RawSsh, env: Env | null, allowSsh: boolean): SshConfig {
  const merged: RawSsh = { ...defaults };
  for (const [k, v] of Object.entries(rawInstance ?? {})) {
    if (v !== undefined) (merged as Record<string, unknown>)[k] = env ? expand(v, env, where) : v;
  }
  const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : undefined);
  const policy = str(merged.host_key_policy) ?? 'strict';
  if (!HOST_KEY_POLICIES.has(policy)) {
    throw configError(`${where} host_key_policy: "${policy}" must be strict, accept-new or off.`);
  }
  const ssh: SshConfig = {
    user: str(merged.user) ?? 'root',
    port: parseInteger(`${where} ssh port`, merged.port, 22, 1, 65_535),
    nodes: parseMap(`${where} ssh nodes`, merged.nodes),
    sudo: parseBool(`${where} ssh sudo`, merged.sudo, false),
    knownHosts: expandHome(str(merged.known_hosts) ?? join(homedir(), '.ssh', 'known_hosts')),
    hostKeyPolicy: policy as HostKeyPolicy,
    fingerprints: parseMap(`${where} ssh fingerprints`, merged.fingerprints),
    timeoutMs: parseInteger(`${where} ssh timeout_seconds`, merged.timeout_seconds, 120, 1, 86_400) * 1000,
    maxOutputBytes: parseInteger(`${where} ssh max_output_bytes`, merged.max_output_bytes, 1_048_576, 1024, 1_073_741_824),
  };
  for (const [node, fingerprint] of Object.entries(ssh.fingerprints)) {
    if (!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(fingerprint)) {
      throw configError(`${where} ssh fingerprints: "${fingerprint}" for ${node} is not a SHA256:... fingerprint.`, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub shows it.');
    }
  }
  const keyFile = str(merged.key_file);
  if (keyFile) ssh.keyFile = expandHome(keyFile);
  const passphrase = str(merged.key_passphrase);
  if (passphrase) ssh.keyPassphrase = passphrase;
  const password = str(merged.password);
  if (password) ssh.password = password;
  const agent = str(merged.agent);
  if (agent) ssh.agent = agent;
  const guestUser = str(merged.guest_user);
  if (guestUser) ssh.guestUser = guestUser;
  const guestKey = str(merged.guest_key_file);
  if (guestKey) ssh.guestKeyFile = expandHome(guestKey);
  const guestPassword = str(merged.guest_password);
  if (guestPassword) ssh.guestPassword = guestPassword;

  // Only when SSH is on: a stale path is no reason to stop a server that will never use it.
  if (allowSsh) {
    if (ssh.keyFile) readTextFile(ssh.keyFile, `${where} SSH key file`);
    if (ssh.guestKeyFile) readTextFile(ssh.guestKeyFile, `${where} guest SSH key file`);
    if (!ssh.keyFile && !ssh.password && !ssh.agent) {
      throw configError(`${where}: PROXMOX_ALLOW_SSH is on, but no SSH credential is set.`, 'Set PROXMOX_SSH_KEY_FILE, PROXMOX_SSH_AGENT or PROXMOX_SSH_PASSWORD.');
    }
  }
  return ssh;
}

/** Env is null when the values already come from the environment: they are not templates. */
function buildInstance(name: string, raw: RawInstance, env: Env | null, defaults: Defaults): InstanceConfig {
  if (!INSTANCE_NAME.test(name)) {
    throw configError(`Invalid instance name "${name}": use letters, digits, - and _ (32 characters at most).`);
  }
  const where = `instance "${name}"`;
  const value = (v: unknown) => (env ? expand(v, env, where) : v);
  const str = (v: unknown) => {
    const expanded = value(v);
    return typeof expanded === 'string' && expanded !== '' ? expanded : undefined;
  };
  const urlRaw = str(raw.url);
  if (!urlRaw) throw configError(`${where}: url is required.`);

  const file = str(raw.credentials_file);
  const fromFile: Credentials = file ? readCredentialsFile(file) : {};
  const token = str(raw.token) ?? (!str(raw.token_id) ? fromFile.token : undefined);
  let tokenId = str(raw.token_id) ?? fromFile.tokenId;
  let tokenSecret = str(raw.token_secret) ?? fromFile.tokenSecret;
  if (token) {
    const m = FULL_TOKEN.exec(token.replace(/^PVEAPIToken=/, ''));
    if (!m) throw configError(`${where}: the token must look like user@realm!tokenid=secret.`);
    tokenId = m[1];
    tokenSecret = m[2];
  }
  if ((tokenId && !tokenSecret) || (!tokenId && tokenSecret)) {
    throw configError(`${where}: a token needs both its id and its secret.`, 'PROXMOX_TOKEN_ID is user@realm!tokenid, PROXMOX_TOKEN_SECRET is the UUID.');
  }
  if (tokenId && !TOKEN_ID.test(tokenId)) throw configError(`${where}: the token id must look like user@realm!tokenid.`);
  const username = str(raw.username) ?? fromFile.username;
  const password = str(raw.password) ?? fromFile.password;
  if (!tokenId) {
    if (!username || !password) {
      throw configError(`${where}: no credentials.`, 'Set PROXMOX_TOKEN (recommended), PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET, PROXMOX_CREDENTIALS_FILE, or PROXMOX_USERNAME and PROXMOX_PASSWORD.');
    }
    if (!username.includes('@')) throw configError(`${where}: the username needs its realm, such as root@pam.`);
  }

  const allowSsh = parseBool(`${where} allow_ssh`, value(raw.allow_ssh), defaults.allowSsh);
  const instance: InstanceConfig = {
    name,
    url: normalizeUrl(urlRaw, where),
    verifySsl: parseBool(`${where} verify_ssl`, value(raw.verify_ssl), defaults.verifySsl),
    allowWrites: parseBool(`${where} allow_writes`, value(raw.allow_writes), defaults.allowWrites),
    allowElevated: parseBool(`${where} allow_elevated`, value(raw.allow_elevated), defaults.allowElevated),
    allowGuestExec: parseBool(`${where} allow_guest_exec`, value(raw.allow_guest_exec), defaults.allowGuestExec),
    allowSsh,
    allowSensitive: parseBool(`${where} allow_sensitive`, value(raw.allow_sensitive), defaults.allowSensitive),
    dryRun: parseBool(`${where} dry_run`, value(raw.dry_run), defaults.dryRun),
    protectedVmids: raw.protected_vmids !== undefined ? parseVmids(`${where} protected_vmids`, value(raw.protected_vmids)) : defaults.protectedVmids,
    timeoutMs: raw.timeout_seconds === undefined ? defaults.timeoutMs : parseInteger(`${where} timeout_seconds`, value(raw.timeout_seconds), 30, 1, 3600) * 1000,
    ssh: buildSsh(where, raw.ssh, defaults.ssh, env, allowSsh),
  };
  if (tokenId && tokenSecret) {
    instance.tokenId = tokenId;
    instance.tokenSecret = tokenSecret;
  } else {
    instance.username = username!;
    instance.password = password!;
  }
  const caFile = str(raw.ca_file);
  const ca = caFile ? readTextFile(caFile, 'CA file') : defaults.ca;
  if (ca) instance.ca = ca;
  const fingerprint = str(raw.fingerprint);
  if (fingerprint) instance.fingerprint = normalizeFingerprint(fingerprint, `${where} fingerprint`);
  else if (defaults.fingerprint) instance.fingerprint = defaults.fingerprint;
  const description = str(raw.description);
  if (description) instance.description = description;
  const defaultNode = str(raw.default_node) ?? defaults.defaultNode;
  if (defaultNode) {
    if (!NODE_NAME.test(defaultNode)) throw configError(`${where}: "${defaultNode}" is not a node name.`);
    instance.defaultNode = defaultNode;
  }
  const localDir = str(raw.local_dir) ?? defaults.localDir;
  if (localDir) instance.localDir = expandHome(localDir);
  return instance;
}

export function loadConfig(env: Env = process.env): ServerConfig {
  const defaults: Defaults = {
    allowWrites: parseBool('PROXMOX_ALLOW_WRITES', env.PROXMOX_ALLOW_WRITES, false),
    allowElevated: parseBool('PROXMOX_ALLOW_ELEVATED', env.PROXMOX_ALLOW_ELEVATED, false),
    allowGuestExec: parseBool('PROXMOX_ALLOW_GUEST_EXEC', env.PROXMOX_ALLOW_GUEST_EXEC, false),
    allowSsh: parseBool('PROXMOX_ALLOW_SSH', env.PROXMOX_ALLOW_SSH, false),
    allowSensitive: parseBool('PROXMOX_ALLOW_SENSITIVE', env.PROXMOX_ALLOW_SENSITIVE, false),
    dryRun: parseBool('PROXMOX_DRY_RUN', env.PROXMOX_DRY_RUN, false),
    verifySsl: parseBool('PROXMOX_VERIFY_SSL', env.PROXMOX_VERIFY_SSL, true),
    timeoutMs: parseInteger('PROXMOX_TIMEOUT_SECONDS', env.PROXMOX_TIMEOUT_SECONDS, 30, 1, 3600) * 1000,
    protectedVmids: parseVmids('PROXMOX_PROTECTED_VMIDS', env.PROXMOX_PROTECTED_VMIDS),
    ssh: sshFromEnv(env),
  };
  if (env.PROXMOX_DEFAULT_NODE) defaults.defaultNode = env.PROXMOX_DEFAULT_NODE;
  if (env.PROXMOX_LOCAL_DIR) defaults.localDir = env.PROXMOX_LOCAL_DIR;
  if (env.PROXMOX_CA_FILE) defaults.ca = readTextFile(env.PROXMOX_CA_FILE, 'PROXMOX_CA_FILE');
  if (env.PROXMOX_FINGERPRINT) defaults.fingerprint = normalizeFingerprint(env.PROXMOX_FINGERPRINT, 'PROXMOX_FINGERPRINT');

  const instances = new Map<string, InstanceConfig>();
  let defaultInstance: string | undefined;

  if (env.PROXMOX_CONFIG) {
    let parsed: { default?: unknown; instances?: Record<string, RawInstance> };
    try {
      parsed = JSON.parse(readFileSync(env.PROXMOX_CONFIG, 'utf8'));
    } catch (err) {
      throw configError(`Cannot read PROXMOX_CONFIG (${env.PROXMOX_CONFIG}): ${(err as Error).message}`);
    }
    for (const [name, raw] of Object.entries(parsed.instances ?? {})) {
      instances.set(name, buildInstance(name, raw, env, defaults));
    }
    if (instances.size === 0) throw configError('PROXMOX_CONFIG defines no instances.');
    if (typeof parsed.default === 'string') {
      if (!instances.has(parsed.default)) throw configError(`Default instance "${parsed.default}" is not defined.`);
      defaultInstance = parsed.default;
    }
  } else {
    if (!env.PROXMOX_URL) {
      throw configError('PROXMOX_URL is not set.', 'Set PROXMOX_URL and PROXMOX_TOKEN, or PROXMOX_CONFIG for several clusters.');
    }
    instances.set(
      'default',
      buildInstance(
        'default',
        {
          url: env.PROXMOX_URL,
          token: env.PROXMOX_TOKEN,
          token_id: env.PROXMOX_TOKEN_ID,
          token_secret: env.PROXMOX_TOKEN_SECRET,
          credentials_file: env.PROXMOX_CREDENTIALS_FILE,
          username: env.PROXMOX_USERNAME,
          password: env.PROXMOX_PASSWORD,
        },
        null,
        defaults,
      ),
    );
  }

  const toolsets = env.PROXMOX_TOOLSETS
    ? new Set(
        env.PROXMOX_TOOLSETS.split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      )
    : null;

  const config: ServerConfig = {
    instances,
    defaultInstance: defaultInstance ?? [...instances.keys()][0]!,
    toolsets,
    taskWaitSeconds: parseInteger('PROXMOX_TASK_WAIT_SECONDS', env.PROXMOX_TASK_WAIT_SECONDS, 30, 0, 3600),
    unblocked: (env.PROXMOX_UNBLOCK ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    elicit: parseBool('PROXMOX_ELICIT', env.PROXMOX_ELICIT, true),
    maxResponseChars: parseInteger('PROXMOX_MAX_RESPONSE_CHARS', env.PROXMOX_MAX_RESPONSE_CHARS, 120_000, 2_000, 5_000_000),
  };
  if (env.PROXMOX_AUDIT_LOG) config.auditLog = env.PROXMOX_AUDIT_LOG;
  return config;
}
