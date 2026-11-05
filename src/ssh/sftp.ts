import type { Attributes, SFTPWrapper, Stats } from 'ssh2';
import { ProxmoxError } from '../proxmox/errors.js';
import type { SftpSession, SftpStat } from './index.js';

const NO_SUCH_FILE = 2;
const PERMISSION_DENIED = 3;

function mapError(err: Error & { code?: unknown }, operation: string, path: string): ProxmoxError {
  if (err.code === NO_SUCH_FILE) return new ProxmoxError('not_found', `SFTP ${operation}: ${path} does not exist.`);
  if (err.code === PERMISSION_DENIED) return new ProxmoxError('forbidden', `SFTP ${operation}: permission denied on ${path}.`, { hint: 'SFTP runs as the SSH user, without sudo.' });
  return new ProxmoxError('upstream_error', `SFTP ${operation} on ${path} failed: ${err.message}`);
}

function toStat(attrs: Stats | Attributes): SftpStat {
  const mode = attrs.mode ?? 0;
  const kind = mode & 0o170000;
  return { size: attrs.size ?? 0, mode: mode & 0o7777, mtime: attrs.mtime ?? 0, isDirectory: kind === 0o040000, isFile: kind === 0o100000 };
}

/** Promises over the callbacks of ssh2, with the timeout it does not have by itself. */
export function wrapSftp(raw: SFTPWrapper, timeoutMs: number, onClose: () => void): SftpSession {
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try {
      raw.end();
    } catch {
      /* already gone */
    }
    onClose();
  };
  raw.on('close', close);
  raw.on('error', () => undefined);

  const call = <T>(operation: string, path: string, run: (done: (err?: Error | null, value?: T) => void) => void, limitMs = timeoutMs): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      if (closed) return reject(new ProxmoxError('ssh_unreachable', `SFTP ${operation} on ${path}: the channel is closed.`));
      const timer = setTimeout(() => {
        reject(new ProxmoxError('ssh_timeout', `SFTP ${operation} on ${path} did not finish within ${Math.round(limitMs / 1000)}s.`, { hint: 'A partial file may be left behind. A longer timeout_seconds may be needed for a large file.' }));
        close();
      }, limitMs);
      timer.unref();
      try {
        run((err, value) => {
          clearTimeout(timer);
          if (err) reject(mapError(err, operation, path));
          else resolve(value as T);
        });
      } catch (err) {
        clearTimeout(timer);
        reject(mapError(err as Error, operation, path));
      }
    });

  return {
    readFile: (path) => call<Buffer>('read', path, (done) => raw.readFile(path, (err, data) => done(err, data))),
    writeFile: (path, data, opts) => call<void>('write', path, (done) => raw.writeFile(path, data, opts?.mode !== undefined ? { mode: opts.mode } : {}, (err) => done(err))),
    fastPut: (local, remote, opts) => call<void>('upload', remote, (done) => raw.fastPut(local, remote, opts?.mode !== undefined ? { mode: opts.mode } : {}, (err) => done(err)), opts?.timeoutMs),
    fastGet: (remote, local, opts) => call<void>('download', remote, (done) => raw.fastGet(remote, local, (err) => done(err)), opts?.timeoutMs),
    stat: (path) => call<Stats>('stat', path, (done) => raw.stat(path, (err, stats) => done(err, stats))).then(toStat),
    readdir: (path) =>
      call<Array<{ filename: string; attrs: Attributes }>>('readdir', path, (done) => raw.readdir(path, (err, list) => done(err, list))).then((list) => list.map((e) => ({ name: e.filename, stat: toStat(e.attrs) }))),
    unlink: (path) => call<void>('unlink', path, (done) => raw.unlink(path, (err) => done(err))),
    rename: (from, to) => call<void>('rename', from, (done) => raw.rename(from, to, (err) => done(err))),
    chmod: (path, mode) => call<void>('chmod', path, (done) => raw.chmod(path, mode, (err) => done(err))),
    close,
  };
}
