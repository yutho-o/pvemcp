import { lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { ProxmoxError } from './errors.js';

function refuse(message: string, hint?: string): ProxmoxError {
  return new ProxmoxError('local_path_refused', message, hint ? { hint } : {});
}

const DEVICE_NAME = /^(?:con|conin\$|conout\$|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?$/i;

/**
 * What Windows reads differently from what a path check sees: a device name opens the device
 * wherever it is, "file:stream" is a hidden stream of another file, and trailing dots and spaces
 * are dropped, so that "a.txt." is a.txt.
 */
function assertPlainWindowsPath(path: string, display: string): void {
  if (process.platform !== 'win32') return;
  const parts = path.replace(/^[a-zA-Z]:/, '').split(/[\\/]/).filter(Boolean);
  for (const part of parts) {
    if (DEVICE_NAME.test(part) || part.includes(':') || (part !== '.' && part !== '..' && /[. ]$/.test(part))) {
      throw refuse(`The local path ${display} holds a name that Windows treats specially ("${part}").`);
    }
  }
}

/**
 * Files on the machine running this server are only reachable under PROXMOX_LOCAL_DIR, and an
 * agent must not be able to leave it. Links are resolved first: a symlink inside the
 * directory pointing at ~/.ssh is outside. For a file about to be written, the parent counts.
 */
export function resolveLocalPath(localDir: string | undefined, path: string, opts: { mustExist: boolean }): string {
  if (!localDir) {
    throw refuse('Local file transfers are off on this server.', 'Do not retry. The operator can set PROXMOX_LOCAL_DIR to a directory reserved for transfers.');
  }
  if (path === '' || path.includes('\0')) throw refuse('The local path is empty or holds a NUL character.');
  assertPlainWindowsPath(path, path);
  let root: string;
  try {
    root = realpathSync(localDir);
  } catch (err) {
    throw refuse(`PROXMOX_LOCAL_DIR (${localDir}) cannot be read: ${(err as Error).message}`);
  }
  const candidate = isAbsolute(path) ? resolve(path) : resolve(root, path);
  let real: string;
  try {
    real = opts.mustExist ? realpathSync(candidate) : join(realpathSync(dirname(candidate)), basename(candidate));
  } catch (err) {
    throw refuse(`The local path ${path} cannot be read: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}.`, `Paths are relative to PROXMOX_LOCAL_DIR (${localDir}).`);
  }
  if (!opts.mustExist) {
    // The target itself may be an existing link pointing elsewhere.
    try {
      real = realpathSync(real);
    } catch {
      // Not there yet, or a link to something not there yet: writing through that one would land outside.
      let dangling = false;
      try {
        dangling = lstatSync(real).isSymbolicLink();
      } catch {
        /* does not exist: the parent was checked above */
      }
      if (dangling) throw refuse(`The local path ${path} is a link to a file that does not exist.`, 'Do not retry with another route to the same file.');
    }
  }
  const rel = relative(root, real);
  if (rel === '' || rel === '..' || rel.startsWith(`..${'/'}`) || rel.startsWith(`..${'\\'}`) || isAbsolute(rel)) {
    throw refuse(`The local path ${path} is outside PROXMOX_LOCAL_DIR.`, 'Do not retry with another route to the same file. Move the file there, or ask the operator.');
  }
  return real;
}
