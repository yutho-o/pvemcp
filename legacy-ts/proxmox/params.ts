import { ProxmoxError } from './errors.js';

export type ParamValue = string | number | boolean | null | undefined | ParamValue[] | { [index: string]: ParamValue };
export type Params = Record<string, unknown>;

const QEMU_PATH = /\/qemu(?:\/|$)/;

/**
 * qemu-server stores sshkeys URL-encoded and checks that they are on the way in, so the value
 * must be encoded once more on top of the form encoding, with %20 (never +) for spaces.
 * LXC ssh-public-keys has no such quirk.
 *
 * A value read back from a VM config is already encoded: it has no space, a real key always does.
 */
export function encodeSshKeys(value: string): string {
  if (/^[A-Za-z0-9%._~-]*$/.test(value) && value.includes('%')) return value;
  return encodeURIComponent(value);
}

function scalar(name: string, value: unknown): string {
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  throw new ProxmoxError('invalid_input', `Parameter "${name}" has an unsupported value (${typeof value}).`);
}

/**
 * Flattens tool-level parameters to the name=value pairs Proxmox takes. Booleans become 1/0,
 * arrays repeat the key, and { "0": "a", "1": "b" } under net becomes net0=a and net1=b.
 * Undefined and null are left out.
 */
export function flattenParams(path: string, params: Params | undefined): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [name, value] of Object.entries(params ?? {})) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) out.push([name, scalar(name, item)]);
      }
      continue;
    }
    if (typeof value === 'object') {
      for (const [index, item] of Object.entries(value as Record<string, unknown>)) {
        if (!/^\d+$/.test(index)) {
          throw new ProxmoxError('invalid_input', `Parameter "${name}" takes numeric indexes such as {"0": "..."}, not "${index}".`);
        }
        if (item !== undefined && item !== null) out.push([`${name}${index}`, scalar(`${name}${index}`, item)]);
      }
      continue;
    }
    if (name === 'sshkeys' && typeof value === 'string' && QEMU_PATH.test(path)) {
      out.push([name, encodeSshKeys(value)]);
      continue;
    }
    out.push([name, scalar(name, value)]);
  }
  return out;
}

/** Spaces go out as %20: URLSearchParams would write +, which sshkeys cannot have. */
export function encodePairs(pairs: ReadonlyArray<readonly [string, string]>): string {
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
}

/** Tool parameter name to API name. "numa[n]" lives next to a plain "numa" on VM configs. */
export function indexedName(apiName: string, taken: { has(name: string): boolean }): string {
  const base = apiName.slice(0, -3);
  return taken.has(base) ? `${base}_n` : base;
}

export function isIndexedParam(apiName: string): boolean {
  return apiName.endsWith('[n]');
}
