import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, sep } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { FakeSsh, ShellSandbox } from './fake-ssh.js';
import { closeSsh, connectSsh, POSIX_SHELL, tempDir, type SshHarness } from './ssh-harness.js';

/**
 * What a tool can reach on this machine: only PROXMOX_LOCAL_DIR. Transfers are driven through a
 * real MCP client and a real SFTP session, so a refusal is one that happens before anything
 * leaves or lands, and an allowed path is one that really works.
 */

const IS_WINDOWS = process.platform === 'win32';

/** A directory link that needs no privilege on Windows, and is a plain symlink elsewhere. */
function linkDir(target: string, path: string): void {
  symlinkSync(target, path, IS_WINDOWS ? 'junction' : 'dir');
}

/** File symlinks need a privilege on Windows: false when this account does not have it. */
function tryLinkFile(target: string, path: string): boolean {
  try {
    symlinkSync(target, path, 'file');
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EPERM') return false;
    throw err;
  }
}

function expectRefused(res: { isError: boolean; data: { error_type?: string } }): void {
  expect(res.isError).toBe(true);
  expect(res.data.error_type).toBe('local_path_refused');
}

describe.skipIf(!POSIX_SHELL)('transfers through the tools', () => {
  let sandbox: ShellSandbox;
  let server: FakeSsh;
  let h: SshHarness;
  let outside: string;
  const download = (local_path: string, extra: Record<string, unknown> = {}) => h.call('pve_ssh_download', { node: 'pve1', path: '/tmp/remote.txt', local_path, ...extra });
  const upload = (local_path: string, path = '/tmp/stolen.txt') => h.call('pve_ssh_upload', { node: 'pve1', local_path, path });

  beforeAll(async () => {
    sandbox = new ShellSandbox(POSIX_SHELL!);
    server = new FakeSsh({ sandbox });
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
    sandbox.remove();
  });
  beforeEach(async () => {
    sandbox.write('/tmp/remote.txt', 'remote content');
    rmSync(sandbox.file('/tmp/stolen.txt'), { force: true });
    outside = tempDir();
    writeFileSync(join(outside, 'secret.txt'), 'outside content');
    h = await connectSsh({ server });
  });
  afterEach(closeSsh);

  describe('within the directory', () => {
    it('uploads by relative path, and the content arrives', async () => {
      writeFileSync(join(h.localDir, 'in.txt'), 'to send');
      const res = await upload('in.txt', '/tmp/uploaded.txt');
      expect(res.isError).toBe(false);
      expect(res.data).toMatchObject({ path: '/tmp/uploaded.txt', bytes: 7 });
      expect(sandbox.read('/tmp/uploaded.txt')).toBe('to send');
    });

    it('uploads by absolute path inside it', async () => {
      const file = join(h.localDir, 'abs.txt');
      writeFileSync(file, 'x');
      expect((await upload(file, '/tmp/abs.txt')).isError).toBe(false);
      expect(sandbox.exists('/tmp/abs.txt')).toBe(true);
    });

    it('downloads into an existing subdirectory, and leaves no partial file', async () => {
      mkdirSync(join(h.localDir, 'sub'));
      const res = await download(join('sub', 'out.txt'));
      expect(res.isError).toBe(false);
      expect(res.data.bytes).toBe(14);
      expect(readFileSync(join(h.localDir, 'sub', 'out.txt'), 'utf8')).toBe('remote content');
      const { readdirSync } = await import('node:fs');
      expect(readdirSync(join(h.localDir, 'sub'))).toEqual(['out.txt']);
    });

    it('does not create missing directories', async () => {
      expectRefused(await download(join('none', 'out.txt')));
      expect(existsSync(join(h.localDir, 'none'))).toBe(false);
    });

    it('does not replace a file unless told to', async () => {
      writeFileSync(join(h.localDir, 'kept.txt'), 'mine');
      expectRefused(await download('kept.txt'));
      expect(readFileSync(join(h.localDir, 'kept.txt'), 'utf8')).toBe('mine');
      expect((await download('kept.txt', { overwrite: true })).isError).toBe(false);
      expect(readFileSync(join(h.localDir, 'kept.txt'), 'utf8')).toBe('remote content');
    });

    it('refuses a directory as a target, even with overwrite', async () => {
      mkdirSync(join(h.localDir, 'd'));
      expectRefused(await download('d', { overwrite: true }));
    });

    it('allows a link inside the directory that stays inside it', async () => {
      mkdirSync(join(h.localDir, 'real'));
      writeFileSync(join(h.localDir, 'real', 'f.txt'), 'via link');
      linkDir(join(h.localDir, 'real'), join(h.localDir, 'alias'));
      expect((await upload(join('alias', 'f.txt'), '/tmp/f.txt')).isError).toBe(false);
      expect(sandbox.read('/tmp/f.txt')).toBe('via link');
    });

    it('allows .. that stays inside', async () => {
      mkdirSync(join(h.localDir, 'a'));
      expect((await download(join('a', '..', 'ok.txt'))).isError).toBe(false);
      expect(existsSync(join(h.localDir, 'ok.txt'))).toBe(true);
    });

    it('works when the directory itself is reached through a link', async () => {
      const real = tempDir();
      const viaLink = join(tempDir(), 'through');
      linkDir(real, viaLink);
      const linked = await connectSsh({ server, env: { PROXMOX_LOCAL_DIR: viaLink } });
      expect((await linked.call('pve_ssh_download', { node: 'pve1', path: '/tmp/remote.txt', local_path: 'in.txt' })).isError).toBe(false);
      expect(existsSync(join(real, 'in.txt'))).toBe(true);
    });
  });

  describe('dot-dot', () => {
    it.each<[string, (dir: string) => string]>([
      ['plain', () => join('..', 'escape.txt')],
      ['in the middle', () => join('a', '..', '..', 'escape.txt')],
      ['with forward slashes', () => '../escape.txt'],
      ['absolute, through the directory', (dir) => `${dir}${sep}..${sep}escape.txt`],
    ])('refuses it %s, both ways', async (_name, path) => {
      writeFileSync(join(h.localDir, '..', 'escape.txt'), 'in the parent');
      expectRefused(await download(path(h.localDir), { overwrite: true }));
      expect(readFileSync(join(h.localDir, '..', 'escape.txt'), 'utf8')).toBe('in the parent');
      expectRefused(await upload(path(h.localDir)));
      expect(sandbox.exists('/tmp/stolen.txt')).toBe(false);
    });

    it('does not take a sibling with the same prefix for the directory', async () => {
      const sibling = `${h.localDir}-other`;
      mkdirSync(sibling);
      try {
        expectRefused(await download(join(sibling, 'x.txt')));
        expect(existsSync(join(sibling, 'x.txt'))).toBe(false);
      } finally {
        rmSync(sibling, { recursive: true, force: true });
      }
    });
  });

  describe('links out of the directory', () => {
    it('refuses a directory link for reading and writing', async () => {
      linkDir(outside, join(h.localDir, 'link'));
      expectRefused(await upload(join('link', 'secret.txt')));
      expect(sandbox.exists('/tmp/stolen.txt')).toBe(false);
      expectRefused(await download(join('link', 'planted.txt')));
      expect(existsSync(join(outside, 'planted.txt'))).toBe(false);
    });

    it('refuses the link itself as a target', async () => {
      linkDir(outside, join(h.localDir, 'link'));
      expectRefused(await download('link', { overwrite: true }));
      expect(readFileSync(join(outside, 'secret.txt'), 'utf8')).toBe('outside content');
    });

    it('refuses a link whose target does not exist yet', async () => {
      const target = join(outside, 'not-yet');
      linkDir(target, join(h.localDir, 'dangling'));
      expectRefused(await download(join('dangling', 'planted.txt')));
      expectRefused(await download('dangling', { overwrite: true }));
      expect(existsSync(target)).toBe(false);
    });

    it('refuses a file symlink, both ways', async (ctx) => {
      if (!tryLinkFile(join(outside, 'secret.txt'), join(h.localDir, 'link.txt'))) {
        console.warn('[test] SKIPPED: this account may not create file symlinks (EPERM). Directory links are covered above.');
        return ctx.skip();
      }
      expectRefused(await upload('link.txt'));
      expect(sandbox.exists('/tmp/stolen.txt')).toBe(false);
      expectRefused(await download('link.txt', { overwrite: true }));
      expect(readFileSync(join(outside, 'secret.txt'), 'utf8')).toBe('outside content');
    });

    it('refuses a dangling file symlink, which a write would follow', async (ctx) => {
      if (!tryLinkFile(join(outside, 'not-yet.txt'), join(h.localDir, 'dangling.txt'))) {
        console.warn('[test] SKIPPED: this account may not create file symlinks (EPERM).');
        return ctx.skip();
      }
      expectRefused(await download('dangling.txt', { overwrite: true }));
      expect(existsSync(join(outside, 'not-yet.txt'))).toBe(false);
    });
  });

  describe('elsewhere', () => {
    it('refuses an absolute path elsewhere', async () => {
      expectRefused(await upload(join(outside, 'secret.txt')));
      expect(sandbox.exists('/tmp/stolen.txt')).toBe(false);
      expectRefused(await download(join(outside, 'x.txt')));
      expect(existsSync(join(outside, 'x.txt'))).toBe(false);
    });

    it('takes no local path at all without PROXMOX_LOCAL_DIR', async () => {
      const off = await connectSsh({ server, env: { PROXMOX_LOCAL_DIR: '' } });
      const res = await off.call('pve_ssh_upload', { node: 'pve1', local_path: join(outside, 'secret.txt'), path: '/tmp/stolen.txt' });
      expectRefused(res);
      expect(res.data.hint).toContain('PROXMOX_LOCAL_DIR');
      expect(sandbox.exists('/tmp/stolen.txt')).toBe(false);
    });

    it('refuses a missing source, and sends nothing', async () => {
      const before = server.sftpOps.length;
      expectRefused(await upload('missing.txt'));
      expect(server.sftpOps).toHaveLength(before);
    });

    it('refuses a directory as the source of an upload', async () => {
      mkdirSync(join(h.localDir, 'd'));
      expectRefused(await upload('d'));
    });

    it('applies the same limits to pct push and pull', async () => {
      linkDir(outside, join(h.localDir, 'link'));
      expectRefused(await h.call('pve_lxc_push_file', { vmid: 101, local_path: join('link', 'secret.txt'), path: '/tmp/x' }));
      expectRefused(await h.call('pve_lxc_push_file', { vmid: 101, local_path: join(outside, 'secret.txt'), path: '/tmp/x' }));
      expectRefused(await h.call('pve_lxc_pull_file', { vmid: 101, path: '/tmp/remote.txt', local_path: join('link', 'planted.txt') }));
      expectRefused(await h.call('pve_lxc_pull_file', { vmid: 101, path: '/tmp/remote.txt', local_path: join('..', 'planted.txt') }));
      expect(existsSync(join(outside, 'planted.txt'))).toBe(false);
    });

    it.runIf(IS_WINDOWS)('refuses a device name and a stream through a tool, and creates nothing', async () => {
      expectRefused(await download('CON'));
      expectRefused(await download('a.txt:stream'));
      expect(existsSync(join(h.localDir, 'a.txt'))).toBe(false);
    });
  });
});

// The unit tests of the function itself, Windows paths included, are in src/proxmox/localpath.rs.
