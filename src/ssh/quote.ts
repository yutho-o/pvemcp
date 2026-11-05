import { ProxmoxError } from '../proxmox/errors.js';

/**
 * Quotes a value for a POSIX shell: inside single quotes nothing is special but the quote
 * itself. NUL cannot be in an argument at all, and silently truncating at one would run
 * something other than what was asked.
 */
export function shQuote(value: string | number): string {
  const text = String(value);
  if (text.includes('\0')) throw new ProxmoxError('invalid_input', 'A shell argument holds a NUL character.');
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

/** Text the sh tag inserts as it is. For operators and fragments written in the code, never for input. */
export class ShellRaw {
  constructor(readonly text: string) {}
}

export function shRaw(text: string): ShellRaw {
  return new ShellRaw(text);
}

/**
 * Tagged template for shell text: every interpolation is quoted, an array becomes several
 * quoted words, and a ShellRaw (such as the result of another sh`...` wrapped in shRaw) goes in as is.
 *
 *   sh`pct exec ${vmid} -- cat ${path}`
 */
export function sh(strings: TemplateStringsArray, ...values: Array<string | number | ShellRaw | ReadonlyArray<string | number>>): string {
  let out = strings[0]!;
  values.forEach((value, i) => {
    if (value instanceof ShellRaw) out += value.text;
    else if (Array.isArray(value)) out += (value as ReadonlyArray<string | number>).map(shQuote).join(' ');
    else out += shQuote(value as string | number);
    out += strings[i + 1]!;
  });
  return out;
}
