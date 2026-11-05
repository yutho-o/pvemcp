import { describe, expect, it } from 'vitest';
import { catalog, findEndpoint } from '../src/catalog/index.js';
import { ProxmoxError } from '../src/proxmox/errors.js';
import { assertNotProtected, authorize, classify, destructiveArgs, encodeSegment, hasDestructiveArgs, hostAccessArg, hostAccessParams, normalizePath, type Gate, type PolicySubject } from '../src/proxmox/policy.js';

function placeholders(path: string): Record<string, string> {
  return Object.fromEntries([...path.matchAll(/\{([^}]+)\}/g)].map((m) => [m[1]!, 'x']));
}

function subject(over: Partial<PolicySubject> = {}): PolicySubject {
  return { name: 'test', allowWrites: false, allowElevated: false, allowGuestExec: false, allowSensitive: false, allowSsh: false, dryRun: false, ...over };
}

function errorType(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (err) {
    if (err instanceof ProxmoxError) return err.type;
    throw err;
  }
}

describe('path normalization', () => {
  it('accepts plain paths and drops one trailing slash', () => {
    expect(normalizePath('/nodes/pve1/qemu/100/config')).toEqual(['nodes', 'pve1', 'qemu', '100', 'config']);
    expect(normalizePath('/nodes/pve1/')).toEqual(['nodes', 'pve1']);
    expect(normalizePath('/access/users/root@pam/token/mcp')).toEqual(['access', 'users', 'root@pam', 'token', 'mcp']);
    expect(normalizePath('/nodes/pve1/tasks/UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:/status')).toHaveLength(5);
  });

  it.each([
    ['no leading slash', 'nodes/pve1'],
    ['empty string', ''],
    ['double slash', '/nodes//pve1'],
    ['two trailing slashes', '/nodes/pve1//'],
    ['dot segment', '/nodes/./pve1'],
    ['dot-dot segment', '/nodes/pve1/../../access/ticket'],
    ['query string', '/nodes/pve1?x=1'],
    ['fragment', '/nodes/pve1#x'],
    ['backslash', '/nodes\\pve1'],
    ['backslash traversal', '/nodes/..\\access'],
    ['newline', '/nodes/pve1\n/status'],
    ['carriage return', '/nodes/pve1\r\nX-Evil: 1'],
    ['NUL', '/nodes/pve1\0'],
    ['DEL', '/nodes/pve1\u007f'],
    ['C1 control', '/nodes/pve1\u0085'],
    ['encoded slash', '/nodes/pve1%2fqemu'],
    ['encoded slash, upper case', '/nodes/pve1%2Fqemu'],
    ['encoded dot', '/nodes/%2e%2e/access'],
    ['encoded dot, upper case', '/nodes/%2E%2E/access'],
    ['encoded backslash', '/nodes/pve1%5cqemu'],
    ['encoded percent', '/nodes/pve1%252fqemu'],
    ['any other encoding, which could spell a literal', '/nodes/pve1/qemu/100/agen%74/exec'],
    ['braces with no values', '/nodes/{node}'],
  ])('refuses %s', (_label, path) => {
    expect(errorType(() => normalizePath(path))).toBe('invalid_path');
  });

  it('refuses dangerous values for placeholders, even though they get encoded', () => {
    const fill = (node: string) => normalizePath('/nodes/{node}/status', { node });
    expect(errorType(() => fill(''))).toBe('invalid_path');
    expect(errorType(() => fill('..'))).toBe('invalid_path');
    expect(errorType(() => fill('.'))).toBe('invalid_path');
    expect(errorType(() => fill('a\nb'))).toBe('invalid_path');
    expect(errorType(() => fill('a\\b'))).toBe('invalid_path');
    // A node name must not be able to add path segments.
    expect(errorType(() => fill('pve1/qemu/100/agent/exec'))).toBe('invalid_path');
    expect(errorType(() => normalizePath('/nodes/{node}/status', {}))).toBe('invalid_input');
  });

  it('lets a volume id or a CIDR hold its slash, encoded, but no traversal', () => {
    const path = '/nodes/{node}/storage/{storage}/content/{volume}';
    const values = { node: 'pve1', storage: 'local', volume: 'local:iso/debian.iso' };
    const decision = classify('DELETE', path, values);
    expect(decision.template).toBe(path);
    expect(decision.urlPath).toBe('/nodes/pve1/storage/local/content/local:iso%2Fdebian.iso');
    expect(decision.pathParams.volume).toBe('local:iso/debian.iso');
    expect(errorType(() => classify('DELETE', path, { ...values, volume: 'local:iso/../../../access' }))).toBe('invalid_path');
    expect(errorType(() => classify('DELETE', path, { ...values, volume: '../x' }))).toBe('invalid_path');
    expect(classify('GET', '/cluster/firewall/ipset/{name}/{cidr}', { name: 'a', cidr: '10.0.0.0/24' }).urlPath).toBe('/cluster/firewall/ipset/a/10.0.0.0%2F24');
  });

  it('encodes each segment on its own', () => {
    expect(encodeSegment('a b')).toBe('a%20b');
    expect(encodeSegment('root@pam!tok')).toBe('root@pam!tok');
    expect(encodeSegment('UPID:pve1:1:')).toBe('UPID:pve1:1:');
    expect(encodeSegment('a?b#c%d')).toBe('a%3Fb%23c%25d');
  });
});

describe('classification', () => {
  it('pins the number of methods per gate, so that a schema update cannot move them unnoticed', () => {
    const counts: Partial<Record<Gate, number>> = {};
    let destructive = 0;
    for (const e of catalog.endpoints) {
      const decision = classify(e.method, e.path, placeholders(e.path));
      counts[decision.gate] = (counts[decision.gate] ?? 0) + 1;
      if (decision.destructive) destructive++;
      expect(decision.template, `${e.method} ${e.path}`).toBe(e.path);
    }
    expect(counts).toMatchInlineSnapshot(`
      {
        "blocked": 11,
        "console": 10,
        "elevated": 209,
        "guest_exec": 7,
        "read": 314,
        "sensitive": 21,
        "write": 108,
      }
    `);
    expect(destructive).toMatchInlineSnapshot(`135`);
    expect(catalog.endpoints).toHaveLength(680);
  });

  it.each<[string, string, Gate, boolean]>([
    // read
    ['GET', '/version', 'read', false],
    ['GET', '/nodes/pve1/qemu', 'read', false],
    ['GET', '/nodes/pve1/qemu/100/config', 'read', false],
    ['GET', '/nodes/pve1/qemu/100/agent', 'read', false],
    ['GET', '/nodes/pve1/qemu/100/agent/get-osinfo', 'read', false],
    ['GET', '/cluster/resources', 'read', false],
    ['GET', '/access/users', 'read', false],
    ['GET', '/nodes/pve1/journal', 'read', false],
    // sensitive
    ['GET', '/cluster/metrics/export', 'sensitive', false],
    ['GET', '/cluster/config/join', 'sensitive', false],
    ['GET', '/nodes/pve1/qemu/100/agent/file-read', 'sensitive', false],
    ['GET', '/nodes/pve1/qemu/100/cloudinit/dump', 'sensitive', false],
    ['GET', '/nodes/pve1/vzdump/extractconfig', 'sensitive', false],
    ['GET', '/nodes/pve1/storage/local/file-restore/download', 'sensitive', false],
    ['GET', '/nodes/pve1/report', 'sensitive', false],
    ['GET', '/cluster/acme/plugins', 'sensitive', false],
    ['GET', '/cluster/acme/plugins/x', 'sensitive', false],
    ['GET', '/nodes/pve1/ceph/cfg/raw', 'sensitive', false],
    // A GET that is not a plain read: the node goes out to a host the caller names, or opens a backup.
    ['GET', '/nodes/pve1/ceph/cfg/db', 'sensitive', false],
    ['GET', '/nodes/pve1/ceph/cfg/value', 'sensitive', false],
    ['GET', '/nodes/pve1/scan/cifs', 'sensitive', false],
    ['GET', '/nodes/pve1/scan/iscsi', 'sensitive', false],
    ['GET', '/nodes/pve1/scan/nfs', 'sensitive', false],
    ['GET', '/nodes/pve1/scan/pbs', 'sensitive', false],
    ['GET', '/nodes/pve1/query-url-metadata', 'sensitive', false],
    ['GET', '/nodes/pve1/query-oci-repo-tags', 'sensitive', false],
    ['GET', '/cluster/acme/meta', 'sensitive', false],
    ['GET', '/cluster/acme/tos', 'sensitive', false],
    ['GET', '/nodes/pve1/storage/local/file-restore/list', 'sensitive', false],
    // The same words, on what stays on the node.
    ['GET', '/nodes/pve1/scan/lvm', 'read', false],
    ['GET', '/nodes/pve1/scan/zfs', 'read', false],
    ['GET', '/cluster/acme/directories', 'read', false],
    // write
    ['POST', '/nodes/pve1/qemu', 'write', false],
    ['POST', '/nodes/pve1/lxc/100/status/start', 'write', false],
    ['PUT', '/nodes/pve1/qemu/100/config', 'write', false],
    ['POST', '/nodes/pve1/vzdump', 'write', false],
    ['POST', '/pools', 'write', false],
    ['POST', '/cluster/ha/resources', 'write', false],
    ['POST', '/nodes/pve1/qemu/100/agent/ping', 'write', false],
    ['POST', '/nodes/pve1/storage/local/upload', 'write', false],
    // write, destructive
    ['DELETE', '/nodes/pve1/qemu/100', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/status/stop', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/status/reset', 'write', true],
    ['POST', '/nodes/pve1/lxc/100/status/shutdown', 'write', true],
    ['POST', '/nodes/pve1/lxc/100/status/reboot', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/status/suspend', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/snapshot/s/rollback', 'write', true],
    ['POST', '/nodes/pve1/lxc/100/template', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/agent/shutdown', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/agent/suspend-disk', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/agent/suspend-hybrid', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/agent/suspend-ram', 'write', true],
    ['POST', '/nodes/pve1/qemu/100/agent/fsfreeze-freeze', 'write', true],
    ['PUT', '/nodes/pve1/qemu/100/unlink', 'write', true],
    ['POST', '/cluster/ha/resources/vm:100/relocate', 'write', true],
    // Not destructive: thawing, trimming, and moving an HA resource live.
    ['POST', '/nodes/pve1/qemu/100/agent/fsfreeze-thaw', 'write', false],
    ['POST', '/nodes/pve1/qemu/100/agent/fstrim', 'write', false],
    ['POST', '/cluster/ha/resources/vm:100/migrate', 'write', false],
    // elevated
    ['PUT', '/access/acl', 'elevated', false],
    ['POST', '/access/users', 'elevated', false],
    ['POST', '/access/users/root@pam/token/x', 'elevated', false],
    ['POST', '/storage', 'elevated', false],
    ['DELETE', '/storage/local', 'elevated', true],
    ['POST', '/cluster/config', 'elevated', true],
    ['POST', '/cluster/config/join', 'elevated', true],
    ['PUT', '/cluster/options', 'elevated', false],
    ['PUT', '/cluster/ceph/flags', 'elevated', false],
    ['POST', '/nodes/pve1/ceph/osd', 'elevated', true],
    ['POST', '/cluster/acme/account', 'elevated', false],
    ['POST', '/nodes/pve1/certificates/custom', 'elevated', false],
    ['PUT', '/cluster/sdn', 'elevated', true],
    ['POST', '/cluster/firewall/rules', 'elevated', false],
    ['PUT', '/nodes/pve1/firewall/options', 'elevated', false],
    ['POST', '/cluster/bulk-action/guest/start', 'elevated', false],
    ['POST', '/cluster/bulk-action/guest/shutdown', 'elevated', true],
    ['POST', '/cluster/bulk-action/guest/suspend', 'elevated', true],
    ['POST', '/nodes/pve1/status', 'elevated', true],
    ['POST', '/nodes/pve1/startall', 'elevated', false],
    ['POST', '/nodes/pve1/stopall', 'elevated', true],
    ['POST', '/nodes/pve1/suspendall', 'elevated', true],
    ['POST', '/nodes/pve1/migrateall', 'elevated', true],
    ['POST', '/nodes/pve1/wakeonlan', 'elevated', false],
    ['POST', '/nodes/pve1/apt/update', 'elevated', false],
    ['PUT', '/nodes/pve1/network', 'elevated', true],
    ['PUT', '/nodes/pve1/dns', 'elevated', false],
    ['POST', '/nodes/pve1/hosts', 'elevated', true],
    ['PUT', '/nodes/pve1/time', 'elevated', false],
    ['PUT', '/nodes/pve1/config', 'elevated', false],
    ['POST', '/nodes/pve1/services/pveproxy/restart', 'elevated', true],
    ['PUT', '/nodes/pve1/subscription', 'elevated', false],
    ['PUT', '/nodes/pve1/disks/wipedisk', 'elevated', true],
    ['POST', '/nodes/pve1/disks/zfs', 'elevated', true],
    ['POST', '/nodes/pve1/qemu/100/remote_migrate', 'elevated', false],
    ['POST', '/cluster/config/nodes/pve2', 'elevated', true],
    ['POST', '/cluster/sdn/rollback', 'elevated', true],
    ['POST', '/cluster/ceph/restart-bulk', 'elevated', true],
    ['POST', '/nodes/pve1/ceph/restart', 'elevated', true],
    ['POST', '/nodes/pve1/ceph/restart-bulk', 'elevated', true],
    ['POST', '/nodes/pve1/ceph/stop', 'elevated', true],
    ['POST', '/nodes/pve1/ceph/start', 'elevated', false],
    ['POST', '/nodes/pve1/ceph/osd/1/out', 'elevated', true],
    ['POST', '/nodes/pve1/ceph/osd/1/in', 'elevated', false],
    ['POST', '/cluster/bulk-action/guest/migrate', 'elevated', true],
    ['POST', '/nodes/pve1/disks/initgpt', 'elevated', true],
    ['POST', '/nodes/pve1/disks/directory', 'elevated', true],
    ['POST', '/nodes/pve1/disks/lvm', 'elevated', true],
    ['POST', '/nodes/pve1/disks/lvmthin', 'elevated', true],
    ['POST', '/nodes/pve1/network', 'elevated', false],
    ['POST', '/nodes/pve1/services/pveproxy/stop', 'elevated', true],
    ['POST', '/nodes/pve1/services/pveproxy/start', 'elevated', false],
    ['POST', '/nodes/pve1/services/pveproxy/reload', 'elevated', false],
    ['PUT', '/access/password', 'elevated', true],
    // Writes that used to pass as ordinary ones.
    ['POST', '/cluster/ha/status/arm-ha', 'elevated', false],
    ['POST', '/cluster/ha/status/disarm-ha', 'elevated', true],
    ['POST', '/cluster/jobs/realm-sync/x', 'elevated', false],
    ['POST', '/cluster/mapping/pci', 'elevated', false],
    ['PUT', '/cluster/mapping/dir/x', 'elevated', false],
    ['POST', '/cluster/metrics/server/x', 'elevated', false],
    ['POST', '/cluster/notifications/endpoints/webhook', 'elevated', false],
    ['POST', '/cluster/notifications/matchers', 'elevated', false],
    ['POST', '/cluster/notifications/targets/x/test', 'elevated', false],
    ['POST', '/cluster/qemu/custom-cpu-models', 'elevated', false],
    // Reading those is still a read.
    ['GET', '/cluster/mapping/pci', 'read', false],
    ['GET', '/cluster/metrics/server', 'read', false],
    ['GET', '/cluster/notifications/endpoints/webhook', 'read', false],
    ['POST', '/nodes/pve1/lxc/100/remote_migrate', 'elevated', false],
    // guest_exec
    ['POST', '/nodes/pve1/qemu/100/agent/exec', 'guest_exec', true],
    ['GET', '/nodes/pve1/qemu/100/agent/exec-status', 'guest_exec', false],
    ['POST', '/nodes/pve1/qemu/100/agent/file-write', 'guest_exec', true],
    ['POST', '/nodes/pve1/qemu/100/agent/set-user-password', 'guest_exec', true],
    ['POST', '/nodes/pve1/qemu/100/monitor', 'guest_exec', true],
    ['POST', '/nodes/pve1/qemu/100/agent', 'guest_exec', true],
    ['PUT', '/nodes/pve1/qemu/100/sendkey', 'guest_exec', true],
    // console
    ['POST', '/nodes/pve1/qemu/100/vncproxy', 'console', false],
    ['POST', '/nodes/pve1/qemu/100/termproxy', 'console', false],
    ['POST', '/nodes/pve1/qemu/100/spiceproxy', 'console', false],
    ['POST', '/nodes/pve1/lxc/100/vncproxy', 'console', false],
    ['POST', '/nodes/pve1/lxc/100/termproxy', 'console', false],
    ['POST', '/nodes/pve1/lxc/100/spiceproxy', 'console', false],
    ['POST', '/nodes/pve1/vncshell', 'console', false],
    ['POST', '/nodes/pve1/termproxy', 'console', false],
    ['POST', '/nodes/pve1/spiceshell', 'console', false],
    ['POST', '/access/vncticket', 'console', false],
    // blocked
    ['POST', '/nodes/pve1/execute', 'blocked', false],
    ['GET', '/nodes/pve1/vncwebsocket', 'blocked', false],
    ['GET', '/nodes/pve1/qemu/100/vncwebsocket', 'blocked', false],
    ['GET', '/nodes/pve1/lxc/100/vncwebsocket', 'blocked', false],
    ['GET', '/nodes/pve1/qemu/100/mtunnelwebsocket', 'blocked', false],
    ['POST', '/nodes/pve1/qemu/100/mtunnel', 'blocked', false],
    ['POST', '/nodes/pve1/lxc/100/mtunnel', 'blocked', false],
    ['POST', '/access/ticket', 'blocked', false],
    ['GET', '/access/ticket', 'blocked', false],
    ['POST', '/access/openid/login', 'blocked', false],
  ])('%s %s is %s', (method, path, gate, destructive) => {
    const decision = classify(method, path);
    expect(decision.gate).toBe(gate);
    expect(decision.destructive).toBe(destructive);
  });

  it('fails closed on unknown paths', () => {
    const get = classify('GET', '/nodes/pve1/qemu/100/brand-new');
    expect(get.gate).toBe('sensitive');
    expect(get.template).toBeUndefined();
    expect(classify('POST', '/nodes/pve1/qemu/100/brand-new').gate).toBe('elevated');
    expect(classify('PUT', '/nope').gate).toBe('elevated');
    expect(classify('DELETE', '/nope').destructive).toBe(true);
    // Known path, method it does not have.
    expect(classify('DELETE', '/version').gate).toBe('elevated');
    expect(classify('POST', '/version').gate).toBe('elevated');
    expect(classify('PUT', '/nodes/pve1/qemu/100/status/current').gate).toBe('elevated');
  });

  it('does not let case or a variant reach a rule by the side: an unknown path never gets less than the fail-closed gate', () => {
    for (const path of ['/NODES/pve1/qemu/100/agent/exec', '/nodes/pve1/QEMU/100/agent/exec', '/nodes/pve1/qemu/100/agent/EXEC', '/nodes/pve1/qemu/100/agent/exec/x']) {
      const decision = classify('POST', path);
      expect(decision.template, path).toBeUndefined();
      expect(decision.gate, path).toBe('elevated');
    }
  });

  it('keeps blocked and exec rules on methods and paths outside the catalog', () => {
    expect(classify('GET', '/nodes/pve1/execute').gate).toBe('blocked');
    expect(classify('PUT', '/access/ticket').gate).toBe('blocked');
    expect(classify('DELETE', '/nodes/pve1/lxc/100/mtunnel').gate).toBe('blocked');
    expect(classify('GET', '/nodes/pve1/qemu/100/vncproxy').gate).toBe('console');
  });

  it('matches literal segments before placeholders', () => {
    expect(classify('GET', '/nodes/pve1/qemu/100/status/current').template).toBe('/nodes/{node}/qemu/{vmid}/status/current');
    expect(classify('GET', '/cluster/firewall/groups').template).toBe('/cluster/firewall/groups');
    expect(classify('GET', '/cluster/firewall/groups/g1').template).toBe('/cluster/firewall/groups/{group}');
    expect(classify('GET', '/nodes/pve1/ceph/osd/3').pathParams).toEqual({ node: 'pve1', osdid: '3' });
  });

  it('derives path params from the template, even those the schema does not declare', () => {
    expect(classify('PUT', '/cluster/ha/rules/r1').pathParams).toEqual({ rule: 'r1' });
    expect(classify('PUT', '/cluster/sdn/prefix-lists/p1/entries/5').pathParams).toEqual({ id: 'p1', url_seq: '5' });
  });

  it('refuses other HTTP methods', () => {
    expect(errorType(() => classify('PATCH', '/version'))).toBe('invalid_input');
    expect(errorType(() => classify('get', '/version'))).toBe('invalid_input');
  });

  it('treats force on a guest create and purge as destructive', () => {
    expect(destructiveArgs('POST', '/nodes/{node}/lxc', { force: true })).toBe(true);
    expect(destructiveArgs('POST', '/nodes/{node}/qemu', { force: true })).toBe(true);
    expect(destructiveArgs('POST', '/nodes/{node}/lxc', { force: false, unprivileged: 1 })).toBe(false);
    expect(destructiveArgs('POST', '/nodes/{node}/lxc', { unprivileged: 1 })).toBe(false);
    // Left out, Proxmox makes a privileged container: a human should see that.
    expect(destructiveArgs('POST', '/nodes/{node}/lxc', {})).toBe(true);
    expect(destructiveArgs('POST', '/some/{thing}', { purge: 1 })).toBe(true);
    expect(destructiveArgs('POST', '/some/{thing}', { force: true })).toBe(false);
    expect(destructiveArgs('GET', '/some/{thing}', { purge: true })).toBe(false);
  });

  const VM = '/nodes/{node}/qemu/{vmid}/config';
  const CT = '/nodes/{node}/lxc/{vmid}/config';
  it.each<[string, string, Record<string, unknown>, boolean]>([
    // Removing an unused disk from a configuration removes the volume.
    ['PUT', VM, { delete: 'unused0' }, true],
    ['POST', VM, { delete: 'cores,unused1' }, true],
    ['PUT', CT, { delete: 'unused0' }, true],
    ['PUT', VM, { delete: 'cores,memory' }, false],
    ['PUT', VM, { force: 1 }, true],
    ['PUT', VM, { force: 0, cores: 2 }, false],
    ['POST', '/nodes/{node}/qemu/{vmid}/move_disk', { delete: true }, true],
    ['POST', '/nodes/{node}/qemu/{vmid}/move_disk', { delete: false }, false],
    ['POST', '/nodes/{node}/lxc/{vmid}/move_volume', { delete: 'yes' }, true],
    ['POST', '/nodes/{node}/lxc/{vmid}/migrate', { restart: 1 }, true],
    ['POST', '/nodes/{node}/lxc/{vmid}/migrate', { online: 1 }, false],
    ['PUT', '/access/users/{userid}/token/{tokenid}', { regenerate: true }, true],
    ['PUT', '/access/users/{userid}/token/{tokenid}', { comment: 'x' }, false],
    ['PUT', '/access/acl', { delete: true, path: '/' }, true],
    ['PUT', '/access/acl', { path: '/' }, false],
    ['POST', '/access/domains/{realm}/sync', { 'remove-vanished': 'acl;entry' }, true],
    ['POST', '/access/domains/{realm}/sync', { 'remove-vanished': 'none' }, false],
    ['POST', '/access/domains/{realm}/sync', { 'remove-vanished': 'entry', 'dry-run': true }, false],
    ['POST', '/cluster/jobs/realm-sync/{id}', { 'remove-vanished': 'entry' }, true],
    ['PUT', '/cluster/ha/resources/{sid}', { state: 'stopped' }, true],
    ['POST', '/cluster/ha/resources', { state: 'disabled' }, true],
    ['PUT', '/cluster/ha/resources/{sid}', { state: 'started' }, false],
    ['PUT', '/cluster/replication/{id}', { remove_job: 'full' }, true],
    ['PUT', '/cluster/replication/{id}', { rate: 10 }, false],
    ['POST', '/nodes/{node}/vzdump', { mode: 'stop' }, true],
    ['POST', '/nodes/{node}/vzdump', { stop: 1 }, true],
    ['POST', '/nodes/{node}/vzdump', { mode: 'snapshot' }, false],
    ['PUT', '/cluster/ceph/flags', { pause: 1 }, true],
    ['PUT', '/cluster/ceph/flags', { noout: 1 }, false],
    ['PUT', '/cluster/ceph/flags/{flag}', { flag: 'pause', value: true }, true],
    ['PUT', '/cluster/ceph/flags/{flag}', { flag: 'noout', value: true }, false],
    ['POST', '/nodes/{node}/certificates/custom', { force: true }, true],
    ['POST', '/nodes/{node}/certificates/acme/certificate', { force: true }, true],
    ['PUT', '/cluster/firewall/options', { enable: 1 }, true],
    ['PUT', '/nodes/{node}/firewall/options', { enable: 0 }, true],
    ['PUT', '/cluster/firewall/options', { policy_in: 'DROP' }, false],
    // Reaching the host, in the form of a tool argument and of an API parameter.
    ['PUT', VM, { hookscript: 'local:snippets/x.sh' }, true],
    ['POST', '/nodes/{node}/qemu', { hostpci: { 0: '01:00.0' } }, true],
    ['POST', '/nodes/{node}/qemu', { hostpci0: '01:00.0' }, true],
    ['PUT', CT, { mp: { 0: '/srv,mp=/mnt' } }, true],
    ['POST', '/nodes/{node}/vzdump', { script: '/root/x.sh' }, true],
  ])('%s %s with %j: destructive is %s', (method, template, args, expected) => {
    expect(destructiveArgs(method, template, args)).toBe(expected);
  });

  it('marks as conditional every endpoint that has a parameter one of the rules looks at, and only those', () => {
    const conditional = catalog.endpoints.filter((e) => hasDestructiveArgs(e.params, e.method, e.path)).map((e) => `${e.method} ${e.path}`);
    for (const key of ['PUT /nodes/{node}/qemu/{vmid}/config', 'POST /nodes/{node}/qemu/{vmid}/config', 'POST /nodes/{node}/qemu', 'PUT /nodes/{node}/lxc/{vmid}/config', 'POST /nodes/{node}/lxc', 'POST /nodes/{node}/vzdump', 'POST /cluster/backup', 'PUT /access/acl', 'PUT /cluster/ceph/flags/{flag}', 'POST /access/domains/{realm}/sync', 'DELETE /nodes/{node}/qemu/{vmid}']) {
      expect(conditional, key).toContain(key);
    }
    expect(conditional).not.toContain('POST /nodes/{node}/qemu/{vmid}/status/start');
    expect(conditional).not.toContain('GET /nodes/{node}/qemu/{vmid}/config');
    // Absent here, a rule would be naming a parameter the schema does not have, and would never fire.
    for (const key of ['POST /nodes/{node}/certificates/custom', 'PUT /cluster/replication/{id}', 'PUT /cluster/firewall/options', 'POST /nodes/{node}/lxc/{vmid}/migrate']) {
      expect(conditional, key).toContain(key);
    }
  });
});

describe('arguments that reach the host', () => {
  const writes = subject({ allowWrites: true });
  const elevated = subject({ allowWrites: true, allowElevated: true });
  const VM = '/nodes/pve1/qemu/100/config';
  const CT = '/nodes/pve1/lxc/101/config';

  it.each<[string, string, Record<string, unknown>, string | undefined]>([
    ['PUT', VM, { hookscript: 'local:snippets/x.sh' }, 'hookscript'],
    ['POST', VM, { args: '-device foo' }, 'args'],
    ['POST', '/nodes/pve1/qemu', { vmid: 200, hostpci0: '01:00.0' }, 'hostpci'],
    ['POST', '/nodes/pve1/qemu', { vmid: 200, hostpci: { 0: '01:00.0' } }, 'hostpci'],
    ['PUT', VM, { parallel0: '/dev/parport0' }, 'parallel'],
    ['PUT', VM, { serial0: '/dev/ttyS0' }, 'serial'],
    ['PUT', VM, { usb0: 'host=1234:5678' }, 'usb'],
    ['PUT', VM, { usb1: 'spice,usb3=1,host=1-2' }, 'usb'],
    ['PUT', CT, { hookscript: 'local:snippets/x.sh' }, 'hookscript'],
    ['PUT', CT, { dev0: '/dev/fuse' }, 'dev'],
    ['PUT', CT, { mp0: '/srv/data,mp=/mnt' }, 'mp'],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, mp: { 0: 'volume=/srv/data,mp=/mnt' } }, 'mp'],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, mp0: 'mp=/mnt,volume=/srv/data' }, 'mp'],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, rootfs: '/srv/root' }, 'rootfs'],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, unprivileged: 0 }, 'unprivileged'],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, unprivileged: false }, 'unprivileged'],
    ['POST', '/nodes/pve1/vzdump', { vmid: 100, script: '/root/x.sh' }, 'script'],
    ['POST', '/nodes/pve1/vzdump', { vmid: 100, dumpdir: '/root' }, 'dumpdir'],
    ['POST', '/cluster/backup', { schedule: 'daily', tmpdir: '/root' }, 'tmpdir'],
    ['PUT', '/cluster/backup/x', { script: '/root/x.sh' }, 'script'],
    // What guests use every day stays gate write.
    ['PUT', VM, { cores: 2, net0: 'virtio,bridge=vmbr0', scsi0: 'local-lvm:32' }, undefined],
    ['PUT', VM, { serial0: 'socket', usb0: 'spice' }, undefined],
    ['PUT', VM, { usb0: 'mapping=stick' }, undefined],
    ['PUT', CT, { mp0: 'local-lvm:8,mp=/mnt', rootfs: 'local-lvm:8' }, undefined],
    ['POST', '/nodes/pve1/lxc', { vmid: 200, rootfs: 'volume=local-lvm:8,size=8G', unprivileged: 1 }, undefined],
    ['POST', '/nodes/pve1/vzdump', { vmid: 100, storage: 'local' }, undefined],
  ])('%s %s with %j: %s', (method, path, params, arg) => {
    const { template } = classify(method, path);
    expect(hostAccessArg(method, template, params)).toBe(arg);
    expect(errorType(() => authorize(writes, method, path, [], { params }))).toBe(arg ? 'elevated_disabled' : undefined);
    expect(errorType(() => authorize(elevated, method, path, [], { params }))).toBeUndefined();
  });

  it('names the argument in the refusal', () => {
    expect(() => authorize(writes, 'PUT', VM, [], { params: { hookscript: 'x' } })).toThrow(/with "hookscript"/);
  });

  it('holds on a dry run too: it only shows what elevated rights would send', () => {
    expect(errorType(() => authorize(subject(), 'PUT', VM, [], { dryRun: true, params: { hookscript: 'x' } }))).toBe('elevated_disabled');
  });

  it('only looks at the endpoints where the arguments mean this', () => {
    expect(hostAccessArg('PUT', '/nodes/{node}/qemu/{vmid}/firewall/options', { args: 'x' })).toBeUndefined();
    expect(hostAccessArg('GET', '/nodes/{node}/qemu/{vmid}/config', { args: 'x' })).toBeUndefined();
    expect(hostAccessArg('POST', undefined, { args: 'x' })).toBeUndefined();
  });

  it('announces only parameters the schema has', () => {
    const on = (method: 'POST' | 'PUT', template: string) => hostAccessParams(findEndpoint(method, template)!.params, method, template);
    expect(on('POST', '/nodes/{node}/qemu')).toEqual(['hookscript', 'args', 'hostpci[n]', 'parallel[n]', 'usb[n]', 'serial[n]']);
    expect(on('PUT', '/nodes/{node}/qemu/{vmid}/config')).toEqual(['hookscript', 'args', 'hostpci[n]', 'parallel[n]', 'usb[n]', 'serial[n]']);
    expect(on('POST', '/nodes/{node}/lxc')).toEqual(['hookscript', 'dev[n]', 'mp[n]', 'rootfs', 'unprivileged']);
    expect(on('POST', '/nodes/{node}/vzdump')).toEqual(['script', 'dumpdir', 'tmpdir']);
    expect(on('PUT', '/cluster/backup/{id}')).toEqual(['script', 'dumpdir', 'tmpdir']);
  });
});

describe('gates', () => {
  const none = subject();
  const writes = subject({ allowWrites: true });
  const elevated = subject({ allowWrites: true, allowElevated: true });
  const dry = subject({ dryRun: true });

  const type = (s: PolicySubject, method: string, path: string, opts: Parameters<typeof authorize>[4] = {}, unblocked: string[] = []) =>
    errorType(() => authorize(s, method, path, unblocked, opts));

  it('read needs nothing', () => {
    expect(type(none, 'GET', '/nodes')).toBeUndefined();
  });

  it('sensitive needs allowSensitive', () => {
    expect(type(none, 'GET', '/nodes/pve1/report')).toBe('sensitive_disabled');
    expect(type(elevated, 'GET', '/nodes/pve1/report')).toBe('sensitive_disabled');
    expect(type(subject({ allowSensitive: true }), 'GET', '/nodes/pve1/report')).toBeUndefined();
  });

  it('write needs allowWrites or a dry run', () => {
    const path = '/nodes/pve1/qemu/100/status/start';
    expect(type(none, 'POST', path)).toBe('write_disabled');
    expect(type(writes, 'POST', path)).toBeUndefined();
    expect(type(dry, 'POST', path)).toBeUndefined();
    expect(type(none, 'POST', path, { dryRun: true })).toBeUndefined();
  });

  it('elevated needs writes (or a dry run) and allowElevated', () => {
    const path = '/access/users';
    expect(type(none, 'POST', path)).toBe('write_disabled');
    expect(type(subject({ allowElevated: true }), 'POST', path)).toBe('write_disabled');
    expect(type(writes, 'POST', path)).toBe('elevated_disabled');
    expect(type(dry, 'POST', path)).toBe('elevated_disabled');
    expect(type(elevated, 'POST', path)).toBeUndefined();
    expect(type(subject({ dryRun: true, allowElevated: true }), 'POST', path)).toBeUndefined();
  });

  it('guest_exec needs allowGuestExec, plus writes on anything but GET', () => {
    const post = '/nodes/pve1/qemu/100/agent/exec';
    const get = '/nodes/pve1/qemu/100/agent/exec-status';
    expect(type(elevated, 'POST', post)).toBe('guest_exec_disabled');
    expect(type(subject({ allowGuestExec: true }), 'POST', post)).toBe('write_disabled');
    expect(type(subject({ allowGuestExec: true, allowWrites: true }), 'POST', post)).toBeUndefined();
    expect(type(subject({ allowGuestExec: true, dryRun: true }), 'POST', post)).toBeUndefined();
    expect(type(none, 'GET', get)).toBe('guest_exec_disabled');
    expect(type(subject({ allowGuestExec: true }), 'GET', get)).toBeUndefined();
    expect(type(subject({ allowGuestExec: true }), 'GET', get, { readOnly: true })).toBeUndefined();
  });

  it('console needs elevated, sensitive and writes, with no dry-run shortcut', () => {
    const path = '/nodes/pve1/termproxy';
    expect(type(subject({ allowElevated: true, allowWrites: true }), 'POST', path)).toBe('elevated_disabled');
    expect(type(subject({ allowSensitive: true, allowWrites: true }), 'POST', path)).toBe('elevated_disabled');
    expect(type(subject({ allowSensitive: true, allowElevated: true }), 'POST', path)).toBe('elevated_disabled');
    expect(type(subject({ allowSensitive: true, allowElevated: true, dryRun: true }), 'POST', path)).toBe('elevated_disabled');
    expect(type(subject({ allowSensitive: true, allowElevated: true, allowWrites: true }), 'POST', path)).toBeUndefined();
  });

  it('blocked stays blocked whatever is allowed, unless listed; then it is elevated', () => {
    const all = subject({ allowWrites: true, allowElevated: true, allowGuestExec: true, allowSensitive: true, allowSsh: true });
    expect(type(all, 'POST', '/nodes/pve1/execute')).toBe('blocked_endpoint');
    expect(type(all, 'POST', '/nodes/pve1/execute', {}, ['POST /nodes/{node}/execute'])).toBeUndefined();
    expect(type(all, 'POST', '/nodes/pve1/execute', {}, ['/nodes/{node}/execute'])).toBeUndefined();
    expect(type(all, 'POST', '/nodes/pve1/execute', {}, ['GET /nodes/{node}/execute'])).toBe('blocked_endpoint');
    expect(type(all, 'POST', '/nodes/pve1/execute', {}, ['/nodes/{node}/vncwebsocket'])).toBe('blocked_endpoint');
    expect(type(writes, 'POST', '/nodes/pve1/execute', {}, ['/nodes/{node}/execute'])).toBe('elevated_disabled');
    expect(authorize(all, 'POST', '/nodes/pve1/execute', ['/nodes/{node}/execute']).gate).toBe('elevated');
  });

  it('a read scope refuses anything but a read, even with every gate open', () => {
    const all = subject({ allowWrites: true, allowElevated: true, allowGuestExec: true, allowSensitive: true });
    expect(type(all, 'POST', '/nodes/pve1/qemu/100/status/start', { readOnly: true })).toBe('not_read_only');
    expect(type(all, 'DELETE', '/nodes/pve1/qemu/100', { readOnly: true })).toBe('not_read_only');
    expect(type(all, 'GET', '/nodes', { readOnly: true })).toBeUndefined();
    expect(type(all, 'GET', '/nodes/pve1/report', { readOnly: true })).toBeUndefined();
    expect(type(all, 'GET', '/nodes/pve1/vncwebsocket', { readOnly: true }, ['/nodes/{node}/vncwebsocket'])).toBe('not_read_only');
  });

  it('checks the path before the gate, so that a bad path is never just "disabled"', () => {
    expect(type(none, 'POST', '/nodes/pve1/../x')).toBe('invalid_path');
  });

  it('hides a bypass through encoded separators: the request never gets classified at all', () => {
    const all = subject({ allowWrites: true, allowElevated: true, allowGuestExec: true, allowSensitive: true });
    for (const path of ['/nodes/pve1/qemu/100/agent%2Fexec', '/nodes/pve1/qemu/100/status%2fstart', '/nodes/x%2F..%2Fpve1/execute', '/nodes/pve1/execut%65']) {
      expect(type(all, 'POST', path), path).toBe('invalid_path');
    }
  });
});

describe('protected guests', () => {
  const ids = new Set([100, 101]);
  const check = (method: string, path: string, params?: Record<string, unknown>) =>
    errorType(() => assertNotProtected(ids, method, classify(method, path), params));

  it('refuses any change to a guest in the list, and nothing else', () => {
    expect(check('POST', '/nodes/pve1/qemu/100/status/stop')).toBe('protected_guest');
    expect(check('DELETE', '/nodes/pve1/lxc/101')).toBe('protected_guest');
    expect(check('PUT', '/nodes/pve1/qemu/100/config')).toBe('protected_guest');
    expect(check('GET', '/nodes/pve1/qemu/100/config')).toBeUndefined();
    expect(check('POST', '/nodes/pve1/qemu/102/status/stop')).toBeUndefined();
  });

  it('sees a vmid given as a parameter: create with force would replace it, clone would write over it', () => {
    expect(check('POST', '/nodes/pve1/qemu', { vmid: 100, force: 1 })).toBe('protected_guest');
    expect(check('POST', '/nodes/pve1/qemu/102/clone', { newid: 101 })).toBe('protected_guest');
    expect(check('POST', '/nodes/pve1/qemu', { vmid: 102 })).toBeUndefined();
  });

  it('counts any matching segment on a path outside the catalog', () => {
    expect(check('POST', '/nodes/pve1/qemu/100/brand-new')).toBe('protected_guest');
  });

  it('sees the guest behind a volume or a backup', () => {
    const volume = (id: string) => assertNotProtected(ids, 'DELETE', classify('DELETE', '/nodes/{node}/storage/{storage}/content/{volume}', { node: 'pve1', storage: 's', volume: id }));
    for (const id of ['local-lvm:vm-100-disk-0', 'local:100/vm-100-disk-0.qcow2', 'local:101/subvol-101-disk-0.subvol', 'local:100/base-100-disk-0.raw', 'local:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst', 'local:backup/vzdump-lxc-101-2026_01_01-00_00_00.tar.zst', 'pbs:backup/vm/100/2026-01-01T00:00:00Z', 'pbs:backup/ct/101/2026-01-01T00:00:00Z']) {
      expect(() => volume(id), id).toThrow(/protected/);
    }
    for (const id of ['local:iso/debian-100-netinst.iso', 'local-lvm:vm-102-disk-0', 'local:backup/vzdump-qemu-102-2026_01_01-00_00_00.vma.zst', 'pbs:backup/vm/102/2026-01-01T00:00:00Z']) {
      expect(() => volume(id), id).not.toThrow();
    }
  });

  it('sees the guests named by a bulk action, a target or a replication job', () => {
    expect(check('POST', '/nodes/pve1/stopall', { vms: '102,100' })).toBe('protected_guest');
    expect(check('POST', '/nodes/pve1/stopall', { vms: '102 100' })).toBe('protected_guest');
    expect(check('POST', '/nodes/pve1/stopall', { vms: '102' })).toBeUndefined();
    expect(check('POST', '/cluster/bulk-action/guest/shutdown', { vms: [102, 100] })).toBe('protected_guest');
    expect(check('POST', '/cluster/bulk-action/guest/shutdown', { vms: [102] })).toBeUndefined();
    expect(check('POST', '/nodes/pve1/qemu/102/move_disk', { 'target-vmid': 100 })).toBe('protected_guest');
    expect(check('POST', '/cluster/replication', { id: '100-0', target: 'pve2', type: 'local' })).toBe('protected_guest');
    expect(check('PUT', '/cluster/replication/100-0')).toBe('protected_guest');
    expect(check('DELETE', '/cluster/replication/101-3')).toBe('protected_guest');
    expect(check('DELETE', '/cluster/replication/102-0')).toBeUndefined();
  });

  it('counts reaching every guest as naming the protected ones', () => {
    for (const path of ['/nodes/pve1/stopall', '/nodes/pve1/startall', '/nodes/pve1/suspendall', '/nodes/pve1/migrateall', '/cluster/bulk-action/guest/shutdown', '/cluster/bulk-action/guest/start', '/cluster/bulk-action/guest/suspend', '/cluster/bulk-action/guest/migrate']) {
      expect(check('POST', path), path).toBe('protected_guest');
      expect(check('POST', path, { vms: [] }), path).toBe('protected_guest');
      expect(check('POST', path, { vms: '' }), path).toBe('protected_guest');
      expect(check('POST', path, { vms: '102' }), path).toBeUndefined();
    }
    expect(check('POST', '/nodes/pve1/vzdump', { all: 1 })).toBe('protected_guest');
    expect(check('POST', '/cluster/backup', { all: true, schedule: 'daily', storage: 'local' })).toBe('protected_guest');
    expect(check('PUT', '/cluster/backup/job1', { all: 1 })).toBe('protected_guest');
    expect(check('POST', '/nodes/pve1/vzdump', { all: 1, exclude: '100,101' })).toBeUndefined();
    expect(check('POST', '/nodes/pve1/vzdump', { all: 0 })).toBeUndefined();
    expect(check('POST', '/nodes/pve1/vzdump', { vmid: '102' })).toBeUndefined();
  });

  it('leaves alone what only looks like it: the other cluster, and the list of a pool', () => {
    expect(check('POST', '/nodes/pve1/qemu/102/remote_migrate', { 'target-vmid': 100 })).toBeUndefined();
    expect(check('PUT', '/pools', { poolid: 'p', vms: '100' })).toBeUndefined();
  });

  it('does nothing without a list', () => {
    expect(errorType(() => assertNotProtected(new Set(), 'DELETE', classify('DELETE', '/nodes/pve1/lxc/101')))).toBeUndefined();
  });
});
