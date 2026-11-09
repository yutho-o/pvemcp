import { createHash, createHmac } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { HostKeyPolicy } from '../config.js';
import { ProxmoxError } from '../proxmox/errors.js';

export interface KnownHostEntry {
  marker?: 'revoked' | 'cert-authority';
  /** The host field as written: a comma list, patterns, or one |1|salt|hash. */
  hosts: string;
  keyType: string;
  key: Buffer;
}

export interface HostKeyInfo {
  type: string;
  fingerprint: string;
}

/** Ignores what it cannot read: a bad line must not make the other entries count for less. */
export function parseKnownHosts(text: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const fields = line.split(/\s+/);
    let marker: KnownHostEntry['marker'];
    if (fields[0]!.startsWith('@')) {
      const name = fields.shift()!;
      if (name !== '@revoked' && name !== '@cert-authority') continue;
      marker = name === '@revoked' ? 'revoked' : 'cert-authority';
    }
    const [hosts, keyType, encoded] = fields;
    if (!hosts || !keyType || !encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) continue;
    const key = Buffer.from(encoded, 'base64');
    if (key.length === 0) continue;
    entries.push({ ...(marker ? { marker } : {}), hosts, keyType, key });
  }
  return entries;
}

/** The name known_hosts uses: the host alone on port 22, [host]:port otherwise. */
export function knownHostsName(host: string, port: number): string {
  const lower = host.toLowerCase();
  return port === 22 ? lower : `[${lower}]:${port}`;
}

function globMatches(pattern: string, name: string): boolean {
  const body = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${body}$`, 'i').test(name);
}

function hashedMatches(field: string, name: string): boolean {
  const parts = field.split('|');
  if (parts.length !== 4 || parts[1] !== '1') return false;
  const expected = Buffer.from(parts[3]!, 'base64');
  const actual = createHmac('sha1', Buffer.from(parts[2]!, 'base64')).update(name).digest();
  return expected.length === actual.length && expected.equals(actual);
}

/** Same rules as OpenSSH: any matching negated pattern excludes the host, whatever else matches. */
export function hostFieldMatches(field: string, name: string): boolean {
  if (field.startsWith('|')) return hashedMatches(field, name);
  let matched = false;
  for (const pattern of field.split(',')) {
    if (pattern.startsWith('!')) {
      if (globMatches(pattern.slice(1), name)) return false;
    } else if (globMatches(pattern, name)) {
      matched = true;
    }
  }
  return matched;
}

export function fingerprintOf(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
}

/** The algorithm name at the start of an SSH public key blob. */
export function keyTypeOf(key: Buffer): string {
  if (key.length < 4) return 'unknown';
  const length = key.readUInt32BE(0);
  return length > 0 && 4 + length <= key.length ? key.toString('latin1', 4, 4 + length) : 'unknown';
}

export function normalizeFingerprint(value: string): string {
  return value.trim().replace(/=+$/, '');
}

/** Public key lines to blobs: "ssh-ed25519 AAAA... comment", as in ssh_host_*_key.pub. */
export function parsePublicKeyLines(text: string): Buffer[] {
  const keys: Buffer[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^([a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(?:\s|$)/.exec(line.trim());
    if (!match) continue;
    const key = Buffer.from(match[2]!, 'base64');
    if (keyTypeOf(key) === match[1]) keys.push(key);
  }
  return keys;
}

export type KnownHostStatus = 'known' | 'revoked' | 'changed' | 'other-type' | 'unknown';

export function checkKnownHosts(entries: readonly KnownHostEntry[], name: string, key: Buffer): { status: KnownHostStatus; expected: string[] } {
  const type = keyTypeOf(key);
  const forHost = entries.filter((e) => e.marker !== 'cert-authority' && hostFieldMatches(e.hosts, name));
  // Revocation goes by the key itself, and comes before any entry that would accept it.
  if (forHost.some((e) => e.marker === 'revoked' && e.key.equals(key))) return { status: 'revoked', expected: [] };
  const plain = forHost.filter((e) => e.marker !== 'revoked');
  if (plain.some((e) => e.key.equals(key))) return { status: 'known', expected: [] };
  const sameType = plain.filter((e) => keyTypeOf(e.key) === type);
  if (sameType.length > 0) return { status: 'changed', expected: sameType.map((e) => fingerprintOf(e.key)) };
  if (plain.length > 0) return { status: 'other-type', expected: plain.map((e) => fingerprintOf(e.key)) };
  return { status: 'unknown', expected: [] };
}

/** What every host key check needs to know. */
export interface HostKeyCheck {
  /** For messages: node pve1, guest 101. */
  label: string;
  host: string;
  port: number;
  policy: HostKeyPolicy;
  knownHostsFile: string;
  /** SHA256:... set by the operator or given on the call. */
  pinned?: string;
  /** The keys the host must present, read through a path already authenticated. */
  allowedKeys?: readonly Buffer[];
}

function readEntries(file: string): KnownHostEntry[] {
  try {
    return parseKnownHosts(readFileSync(file, 'utf8'));
  } catch {
    // Unreadable means nothing is known, and an unknown host is refused.
    return [];
  }
}

const VERIFY_HINT = 'Do not retry until a human has compared this fingerprint with the one on the host itself, from its console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. The operator can then pin it with PROXMOX_SSH_FINGERPRINTS or add it to known_hosts.';

function mismatch(check: HostKeyCheck, key: Buffer, why: string, expected?: string[]): ProxmoxError {
  return new ProxmoxError('host_key_mismatch', `The host key of ${check.label} (${check.host}:${check.port}) ${why}: nothing was sent to it.`, {
    hint: 'This can be a reinstalled host or someone in the middle. Do not retry. A human has to check the host, and update what is known about it.',
    details: { presented: fingerprintOf(key), key_type: keyTypeOf(key), ...(expected?.length ? { expected } : {}) },
  });
}

function unknown(check: HostKeyCheck, key: Buffer, why: string, hint = VERIFY_HINT, expected?: string[]): ProxmoxError {
  return new ProxmoxError('host_key_unknown', `The host key of ${check.label} (${check.host}:${check.port}) ${why}: nothing was sent to it.`, {
    hint,
    details: { fingerprint: fingerprintOf(key), key_type: keyTypeOf(key), ...(expected?.length ? { known_with_other_types: expected } : {}) },
  });
}

function appendEntry(file: string, name: string, key: Buffer): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  let prefix = '';
  try {
    const current = readFileSync(file, 'utf8');
    if (current.length > 0 && !current.endsWith('\n')) prefix = '\n';
  } catch {
    /* a new file */
  }
  appendFileSync(file, `${prefix}${name} ${keyTypeOf(key)} ${key.toString('base64')}\n`, { mode: 0o600 });
}

/**
 * The verdict on a key presented by a host. Throws unless it is accepted, and nothing is
 * sent before this has run: the handshake stops here, ahead of authentication.
 *
 * A revoked key and a pin that does not match are refused even under policy off: those are
 * explicit statements by the operator, and off only waives what is not stated anywhere.
 */
export function verifyHostKey(check: HostKeyCheck, key: Buffer): HostKeyInfo {
  const info = { type: keyTypeOf(key), fingerprint: fingerprintOf(key) };
  const name = knownHostsName(check.host, check.port);
  const known = checkKnownHosts(readEntries(check.knownHostsFile), name, key);
  if (known.status === 'revoked') throw mismatch(check, key, 'is marked @revoked in known_hosts');

  if (check.pinned !== undefined && normalizeFingerprint(check.pinned) !== info.fingerprint) {
    throw mismatch(check, key, 'does not match the pinned fingerprint', [check.pinned]);
  }
  if (check.allowedKeys) {
    if (check.allowedKeys.some((k) => k.equals(key))) return info;
    throw mismatch(check, key, 'is not one of the keys found inside the guest', check.allowedKeys.map(fingerprintOf));
  }
  if (check.pinned !== undefined || check.policy === 'off') return info;

  switch (known.status) {
    case 'known':
      return info;
    case 'changed':
      throw mismatch(check, key, 'differs from the one in known_hosts', known.expected);
    case 'other-type':
      // An attacker could offer another key type to look new: this is never trusted on first use.
      throw unknown(check, key, 'is of a type that known_hosts does not list for this host', `known_hosts has other types of key for this host. ${VERIFY_HINT}`, known.expected);
    default:
      break;
  }
  if (check.policy !== 'accept-new') throw unknown(check, key, 'is not in known_hosts');
  try {
    appendEntry(check.knownHostsFile, name, key);
  } catch (err) {
    throw unknown(check, key, `could not be recorded in ${check.knownHostsFile} (${(err as Error).message})`);
  }
  return info;
}

/** What ssh2 offers when nothing is known about the host, in its own default order. */
const DEFAULT_HOST_KEY_ALGORITHMS = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'];

/**
 * Asks first for the key types already known for this host, as OpenSSH does. Otherwise a host
 * recorded with its RSA key would present ed25519 and look unknown.
 */
export function hostKeyAlgorithms(check: HostKeyCheck): string[] | undefined {
  const name = knownHostsName(check.host, check.port);
  const keys = check.allowedKeys ?? readEntries(check.knownHostsFile).filter((e) => !e.marker && hostFieldMatches(e.hosts, name)).map((e) => e.key);
  const preferred: string[] = [];
  for (const key of keys) {
    const type = keyTypeOf(key);
    for (const algorithm of type === 'ssh-rsa' ? ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'] : [type]) {
      if (DEFAULT_HOST_KEY_ALGORITHMS.includes(algorithm) && !preferred.includes(algorithm)) preferred.push(algorithm);
    }
  }
  if (preferred.length === 0) return undefined;
  return [...preferred, ...DEFAULT_HOST_KEY_ALGORITHMS.filter((a) => !preferred.includes(a))];
}
