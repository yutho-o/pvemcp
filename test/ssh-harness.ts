import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Env } from '../src/config.js';
import { closeAll, connect, type ConnectOptions, type Harness } from './harness.js';
import { FAKE_SSH_PASSWORD, FakeSsh, findPosixShell, ShellSandbox, type FakeSshOptions, type PosixShell } from './fake-ssh.js';
import type { FakeOptions } from './fake-pve.js';

/** Everything open for an SSH test, including the tools. No toolset filter: the SSH tools are in the defaults. */
export const SSH_GATES: Env = {
  PROXMOX_ALLOW_WRITES: 'true',
  PROXMOX_ALLOW_SSH: 'true',
  PROXMOX_SSH_PASSWORD: FAKE_SSH_PASSWORD,
};

export const POSIX_SHELL: PosixShell | undefined = findPosixShell();

if (!POSIX_SHELL) {
  console.warn('[test] SKIPPING the tests that run commands for real: no POSIX shell found. Set PVEMCP_TEST_SH to one, or install Git for Windows.');
}

const cleanups: Array<() => Promise<unknown> | unknown> = [];

export async function closeSsh(): Promise<void> {
  await closeAll();
  for (const cleanup of cleanups.splice(0)) {
    try {
      await cleanup();
    } catch {
      /* already gone */
    }
  }
}

export function tempDir(prefix = 'pvemcp-ssh-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  return dir;
}

export interface SshHarness extends Harness {
  ssh: FakeSsh;
  dir: string;
  knownHosts: string;
  localDir: string;
}

export interface ConnectSshOptions extends Omit<ConnectOptions, 'fake'> {
  /** An already started server. */
  server?: FakeSsh;
  sshOptions?: FakeSshOptions;
  fake?: FakeOptions;
  /** Leave known_hosts empty: the host is unknown. */
  unknownHost?: boolean;
}

/** A fake Proxmox, a fake node on a real SSH connection, and the real SSH transport between them. */
export async function connectSsh(opts: ConnectSshOptions = {}): Promise<SshHarness> {
  const ssh = opts.server ?? new FakeSsh(opts.sshOptions);
  if (!opts.server) {
    await ssh.start();
    cleanups.push(() => ssh.stop());
  }
  const dir = tempDir();
  const knownHosts = join(dir, 'known_hosts');
  const localDir = join(dir, 'local');
  mkdirSync(localDir);
  writeFileSync(knownHosts, opts.unknownHost ? '' : `${ssh.knownHostsLine()}\n`);
  const harness = await connect({
    ...opts,
    fake: { guests: [{ vmid: 100, type: 'qemu', name: 'web' }, { vmid: 101, type: 'lxc', name: 'db' }], ...opts.fake },
    env: {
      ...SSH_GATES,
      PROXMOX_SSH_NODES: 'pve1=127.0.0.1',
      PROXMOX_SSH_PORT: String(ssh.port),
      PROXMOX_SSH_KNOWN_HOSTS: knownHosts,
      PROXMOX_LOCAL_DIR: localDir,
      PROXMOX_SSH_TIMEOUT_SECONDS: '30',
      ...opts.env,
    },
  });
  return { ...harness, ssh, dir, knownHosts, localDir };
}

export { ShellSandbox };
