import { sh, shRaw } from './quote.js';

/**
 * Shell text run by POSIX sh. Inside a container that may be dash, BusyBox ash or bash, so:
 * no bash syntax, and only options BusyBox has too. A test runs these under a real dash and
 * checks their options against what BusyBox accepts.
 *
 * The scripts detect the distribution where they run instead of in an earlier round trip,
 * so that a dry run shows what would really happen and nothing can change in between.
 *
 * Exit codes of our own, turned into typed errors by the tools.
 */
export const EXIT_NOT_FOUND = 44;
export const EXIT_NOT_A_FILE = 45;
export const EXIT_NOT_READABLE = 46;
export const EXIT_NO_MANAGER = 47;
export const EXIT_REFUSED_LINK = 48;
export const EXIT_SSHD_REJECTED = 65;
export const EXIT_SSHD_NOT_EFFECTIVE = 66;
export const EXIT_RELOAD_FAILED = 67;
export const EXIT_CD_FAILED = 125;

/** How a script is carried into the container: pct exec passes argv on with no shell of its own. */
export function pctExec(vmid: number, script: string): string {
  return sh`pct exec ${vmid} -- sh -c ${script}`;
}

const lines = (...parts: string[]) => parts.join('\n');

/** Sets init to systemd, openrc, sysv or none. */
const DETECT_INIT = lines(
  'if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then init=systemd',
  'elif command -v rc-service >/dev/null 2>&1; then init=openrc',
  'elif command -v service >/dev/null 2>&1; then init=sysv',
  'else init=none',
  'fi',
);

/** Sets sshd to the path of the daemon, or empty. It is not on the PATH of every login. */
const FIND_SSHD = lines(
  'sshd=$(command -v sshd 2>/dev/null) || sshd=',
  'if [ -z "$sshd" ] && [ -x /usr/sbin/sshd ]; then sshd=/usr/sbin/sshd; fi',
);

/** The unit of the daemon under systemd: ssh on Debian and Ubuntu, sshd elsewhere. */
const FIND_SSH_UNIT = lines('u=sshd', 'if systemctl cat ssh.service >/dev/null 2>&1; then u=ssh; fi');

/** Reads /etc/passwd itself: no grep pattern to escape, and getent is not everywhere. */
function passwdLookup(user: string): string {
  return lines(
    sh`want=${user}`,
    'found=',
    'while IFS=: read -r n _p ui gi _g hd _s; do',
    '  if [ "$n" = "$want" ]; then found=1; home=$hd; uid=$ui; gid=$gi; break; fi',
    'done < /etc/passwd',
    `if [ -z "$found" ] || [ -z "$home" ]; then printf 'No such user: %s\\n' "$want" >&2; exit ${EXIT_NOT_FOUND}; fi`,
    'dir="$home/.ssh"',
    'file="$dir/authorized_keys"',
  );
}

/** Size on the first line, the path with links resolved after it. */
export function fileStatScript(path: string): string {
  return lines(
    sh`p=${path}`,
    `if [ ! -e "$p" ]; then echo 'No such file or directory' >&2; exit ${EXIT_NOT_FOUND}; fi`,
    `if [ ! -f "$p" ]; then echo 'Not a regular file' >&2; exit ${EXIT_NOT_A_FILE}; fi`,
    `if [ ! -r "$p" ]; then echo 'Permission denied' >&2; exit ${EXIT_NOT_READABLE}; fi`,
    `wc -c < "$p" | tr -d ' '`,
    `readlink -f "$p" 2>/dev/null || printf '%s\\n' "$p"`,
  );
}

export function readFileScript(path: string, limit?: number): string {
  return limit === undefined ? sh`cat -- ${path}` : sh`head -c ${limit} -- ${path}`;
}

export function listDirScript(path: string): string {
  return sh`ls -la -- ${path}`;
}

export function deleteFileScript(path: string, missingOk: boolean): string {
  return missingOk ? sh`rm -f -- ${path}` : sh`rm -- ${path}`;
}

export interface WriteFileOptions {
  mode?: string;
  owner?: string;
  backup?: boolean;
  createParents?: boolean;
}

/**
 * Stdin to a file, whole or not at all: a temporary file next to the target, renamed over it.
 * An existing file keeps its mode and owner, unless told otherwise. On /etc/pve neither can be
 * set, so that part is best effort unless it was asked for.
 */
export function writeFileScript(path: string, opts: WriteFileOptions): string {
  return lines(
    'umask 077',
    sh`p=${path}`,
    `if [ -L "$p" ]; then p=$(readlink -f "$p") || exit 1; fi`,
    `if [ -d "$p" ]; then echo 'Is a directory' >&2; exit ${EXIT_NOT_A_FILE}; fi`,
    'd=${p%/*}',
    'if [ -z "$d" ]; then d=/; fi',
    opts.createParents ? 'mkdir -p "$d" || exit 1' : `if [ ! -d "$d" ]; then printf 'No such directory: %s\\n' "$d" >&2; exit ${EXIT_NOT_FOUND}; fi`,
    'b=',
    ...(opts.backup ? ['if [ -e "$p" ]; then b="$p.bak.$(date +%Y%m%d%H%M%S)"; cp -p "$p" "$b" || exit 1; fi'] : []),
    't=$(mktemp "$d/.pvemcp.XXXXXX") || exit 1',
    `trap 'rm -f "$t"' EXIT`,
    'cat > "$t" || exit 1',
    'if [ -e "$p" ]; then',
    '  m=$(stat -c %a "$p" 2>/dev/null) && chmod "$m" "$t" 2>/dev/null',
    '  o=$(stat -c %u:%g "$p" 2>/dev/null) && chown "$o" "$t" 2>/dev/null',
    'else',
    '  chmod 644 "$t" 2>/dev/null',
    'fi',
    ...(opts.mode ? [sh`chmod ${opts.mode} "$t" || exit 1`] : []),
    ...(opts.owner ? [sh`chown ${opts.owner} "$t" || exit 1`] : []),
    'mv -f "$t" "$p" || exit 1',
    `wc -c < "$p" | tr -d ' '`,
    `printf '%s\\n' "$b"`,
  );
}

/** For each command wanted, what to run. */
export function lxcInfoScript(): string {
  return lines(
    `echo '@@os'; cat /etc/os-release 2>/dev/null`,
    `echo '@@kernel'; uname -srm 2>/dev/null`,
    `echo '@@hostname'; hostname 2>/dev/null`,
    `echo '@@uptime'; cat /proc/uptime 2>/dev/null`,
    `echo '@@ips'; ip -o addr show 2>/dev/null || ifconfig 2>/dev/null`,
    `echo '@@mounts'; cat /proc/mounts 2>/dev/null`,
    'exit 0',
  );
}

/** BusyBox ps may have -o with fewer columns, or nothing but plain ps. */
export function processesScript(): string {
  return `ps -eo pid,ppid,user,pcpu,pmem,etime,args 2>/dev/null || ps -o pid,ppid,user,args 2>/dev/null || ps`;
}

/** Alpine has netstat from BusyBox, Debian minimal only ss, some templates neither. */
export function portsScript(): string {
  return lines(
    'if command -v ss >/dev/null 2>&1; then ss -tulnp',
    'elif command -v netstat >/dev/null 2>&1; then netstat -tuln',
    `else echo 'Neither ss nor netstat here: raw kernel tables.'; cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null; exit 0`,
    'fi',
  );
}

export function diskUsageScript(path?: string): string {
  return lines(`df -hP 2>/dev/null || df -h`, ...(path ? [`echo '@@du'`, sh`du -xsh -- ${path} 2>&1`] : []), 'exit 0');
}

export function logsScript(opts: { lines: number; unit?: string; since?: string }): string {
  const journal = ['journalctl --no-pager -o short-iso', sh`-n ${opts.lines}`, ...(opts.unit ? [sh`-u ${opts.unit}`] : []), ...(opts.since ? [sh`${`--since=${opts.since}`}`] : [])].join(' ');
  const unitFiles = opts.unit ? sh`/var/log/${opts.unit}.log /var/log/${opts.unit}/current /var/log/${opts.unit}/${opts.unit}.log ` : '';
  return lines(
    sh`n=${opts.lines}`,
    'if command -v journalctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ -d /var/log/journal ]; }; then',
    `  echo 'source=journal'`,
    `  ${journal} && exit 0`,
    'fi',
    `for f in ${unitFiles}/var/log/syslog /var/log/messages; do`,
    '  if [ -r "$f" ]; then',
    `    printf 'source=%s\\n' "$f"`,
    ...(opts.unit ? [sh`    case "$f" in /var/log/syslog|/var/log/messages) grep -F -- ${opts.unit} "$f" | tail -n "$n"; exit 0;; esac`] : []),
    '    tail -n "$n" "$f"',
    '    exit $?',
    '  fi',
    'done',
    `echo 'No journal, and no readable log file in /var/log.' >&2`,
    `exit ${EXIT_NOT_FOUND}`,
  );
}

export function serviceStatusScript(unit?: string): string {
  const systemd = unit
    ? [sh`echo "active=$(systemctl is-active -- ${unit} 2>/dev/null)"`, sh`echo "enabled=$(systemctl is-enabled -- ${unit} 2>/dev/null)"`, sh`systemctl status --no-pager --lines=20 -- ${unit} 2>&1`]
    : ['systemctl list-units --type=service --all --no-pager --no-legend 2>&1'];
  const openrc = unit
    ? [sh`if rc-service ${unit} status >/dev/null 2>&1; then echo active=active; else echo active=inactive; fi`, sh`if rc-update show default 2>/dev/null | grep -qw -- ${unit}; then echo enabled=enabled; else echo enabled=disabled; fi`, sh`rc-service ${unit} status 2>&1`]
    : ['rc-status --all 2>&1'];
  const sysv = unit ? [sh`if service ${unit} status >/dev/null 2>&1; then echo active=active; else echo active=inactive; fi`, sh`service ${unit} status 2>&1`] : ['service --status-all 2>&1'];
  return lines(DETECT_INIT, 'echo "init=$init"', 'case "$init" in', '  systemd)', ...systemd, '  ;;', '  openrc)', ...openrc, '  ;;', '  sysv)', ...sysv, '  ;;', 'esac', 'exit 0');
}

export type ServiceAction = 'start' | 'stop' | 'restart' | 'reload' | 'enable' | 'disable';

export function serviceScript(action: ServiceAction, unit: string): string {
  const openrc = action === 'enable' ? sh`rc-update add ${unit} default` : action === 'disable' ? sh`rc-update del ${unit} default` : sh`rc-service ${unit} ${action}`;
  const sysv =
    action === 'enable' || action === 'disable'
      ? lines(
          'if command -v update-rc.d >/dev/null 2>&1; then',
          sh`    update-rc.d ${unit} ${action}`,
          '  elif command -v chkconfig >/dev/null 2>&1; then',
          sh`    chkconfig ${unit} ${action === 'enable' ? 'on' : 'off'}`,
          '  else',
          `    echo 'Neither update-rc.d nor chkconfig here.' >&2; exit ${EXIT_NO_MANAGER}`,
          '  fi',
        )
      : sh`service ${unit} ${action}`;
  return lines(
    DETECT_INIT,
    'echo "init=$init"',
    'case "$init" in',
    sh`  systemd) systemctl ${action} -- ${unit} ;;`,
    `  openrc) ${openrc} ;;`,
    `  sysv) ${sysv} ;;`,
    `  *) echo 'No service manager found: no systemd, OpenRC or service command.' >&2; exit ${EXIT_NO_MANAGER} ;;`,
    'esac',
  );
}

const NO_MANAGER = `  echo 'No supported package manager found: apt-get, apk, dnf, yum or pacman.' >&2\n  exit ${EXIT_NO_MANAGER}`;
const APT_OPTIONS = '-y -q -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold';

/** Each branch ends with the command whose status counts. */
function perManager(branches: { apt: string[]; apk: string[]; dnf: string[]; yum: string[]; pacman: string[] }): string {
  return lines(
    'if command -v apt-get >/dev/null 2>&1; then',
    '  export DEBIAN_FRONTEND=noninteractive',
    '  echo manager=apt',
    ...branches.apt.map((l) => `  ${l}`),
    'elif command -v apk >/dev/null 2>&1; then',
    '  echo manager=apk',
    ...branches.apk.map((l) => `  ${l}`),
    'elif command -v dnf >/dev/null 2>&1; then',
    '  echo manager=dnf',
    ...branches.dnf.map((l) => `  ${l}`),
    'elif command -v yum >/dev/null 2>&1; then',
    '  echo manager=yum',
    ...branches.yum.map((l) => `  ${l}`),
    'elif command -v pacman >/dev/null 2>&1; then',
    '  echo manager=pacman',
    ...branches.pacman.map((l) => `  ${l}`),
    'else',
    NO_MANAGER,
    'fi',
  );
}

/** Arch does not support partial upgrades, so refreshing there means upgrading. dnf and yum refresh on their own. */
export function installPackagesScript(packages: readonly string[], refresh: boolean): string {
  return perManager({
    apt: [(refresh ? 'apt-get update -q && ' : '') + sh`apt-get install ${shRaw(APT_OPTIONS)} -- ${packages}`],
    apk: [(refresh ? 'apk update -q && ' : '') + sh`apk add --no-progress ${packages}`],
    dnf: [sh`dnf install -y ${packages}`],
    yum: [sh`yum install -y ${packages}`],
    pacman: [refresh ? sh`pacman -Syu --noconfirm --needed ${packages}` : sh`pacman -S --noconfirm --needed ${packages}`],
  });
}

export function removePackagesScript(packages: readonly string[], purge: boolean): string {
  return perManager({
    apt: [sh`apt-get ${purge ? 'purge' : 'remove'} ${shRaw(APT_OPTIONS)} -- ${packages}`],
    apk: [sh`apk del --no-progress ${packages}`],
    dnf: [sh`dnf remove -y ${packages}`],
    yum: [sh`yum remove -y ${packages}`],
    pacman: [purge ? sh`pacman -Rns --noconfirm ${packages}` : sh`pacman -R --noconfirm ${packages}`],
  });
}

export function updatePackagesScript(full: boolean): string {
  return perManager({
    apt: [`apt-get update -q && apt-get ${full ? 'dist-upgrade' : 'upgrade'} ${APT_OPTIONS}`],
    apk: ['apk update -q && apk upgrade --no-progress'],
    dnf: ['dnf upgrade -y'],
    yum: ['yum update -y'],
    pacman: ['pacman -Syu --noconfirm'],
  });
}

/** The first line says which manager; the rest depends on it. */
export function listPackagesScript(): string {
  return lines(
    'if command -v dpkg-query >/dev/null 2>&1; then',
    '  echo manager=dpkg',
    "  dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n'",
    'elif command -v apk >/dev/null 2>&1; then',
    '  echo manager=apk',
    '  apk info -v 2>/dev/null',
    'elif command -v rpm >/dev/null 2>&1; then',
    '  echo manager=rpm',
    "  rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'",
    'elif command -v pacman >/dev/null 2>&1; then',
    '  echo manager=pacman',
    '  pacman -Q',
    'else',
    NO_MANAGER,
    'fi',
  );
}

export interface CreateUserOptions {
  uid?: number;
  shell?: string;
  home?: string;
  comment?: string;
  groups?: readonly string[];
  system?: boolean;
}

/** useradd where shadow is installed, else the adduser of BusyBox, which has other options. */
export function createUserScript(name: string, opts: CreateUserOptions): string {
  const useradd = ['useradd', '-m'];
  const adduser = ['adduser', '-D'];
  if (opts.system) {
    useradd.push('-r');
    adduser.push('-S');
  }
  if (opts.uid !== undefined) {
    useradd.push(sh`-u ${opts.uid}`);
    adduser.push(sh`-u ${opts.uid}`);
  }
  if (opts.shell) {
    useradd.push(sh`-s ${opts.shell}`);
    adduser.push(sh`-s ${opts.shell}`);
  }
  if (opts.home) {
    useradd.push(sh`-d ${opts.home}`);
    adduser.push(sh`-h ${opts.home}`);
  }
  if (opts.comment) {
    useradd.push(sh`-c ${opts.comment}`);
    adduser.push(sh`-g ${opts.comment}`);
  }
  const groups = opts.groups ?? [];
  if (groups.length > 0) useradd.push(sh`-G ${groups.join(',')}`);
  useradd.push(sh`${name}`);
  adduser.push(sh`${name}`);
  return lines(
    'if command -v useradd >/dev/null 2>&1; then',
    `  ${useradd.join(' ')}`,
    'elif command -v adduser >/dev/null 2>&1; then',
    `  ${adduser.join(' ')} || exit $?`,
    ...(groups.length > 0 ? [sh`  for g in ${groups}; do addgroup ${name} "$g" || exit $?; done`] : []),
    'else',
    `  echo 'Neither useradd nor adduser here.' >&2; exit ${EXIT_NO_MANAGER}`,
    'fi',
  );
}

export function deleteUserScript(name: string, removeHome: boolean): string {
  return lines(
    'if command -v userdel >/dev/null 2>&1; then',
    `  userdel ${removeHome ? '-r ' : ''}${sh`${name}`}`,
    'elif command -v deluser >/dev/null 2>&1; then',
    `  deluser ${removeHome ? '--remove-home ' : ''}${sh`${name}`}`,
    'else',
    `  echo 'Neither userdel nor deluser here.' >&2; exit ${EXIT_NO_MANAGER}`,
    'fi',
  );
}

export function sshStatusScript(): string {
  return lines(
    FIND_SSHD,
    'echo "binary=$sshd"',
    'if command -v dropbear >/dev/null 2>&1; then echo dropbear=yes; fi',
    'running=no',
    'if command -v pgrep >/dev/null 2>&1; then',
    '  if pgrep -x sshd >/dev/null 2>&1; then running=yes; fi',
    'elif command -v pidof >/dev/null 2>&1; then',
    '  if pidof sshd >/dev/null 2>&1; then running=yes; fi',
    'fi',
    DETECT_INIT,
    'echo "init=$init"',
    'if [ "$init" = systemd ] && systemctl is-active ssh.socket >/dev/null 2>&1; then running=socket; fi',
    'echo "running=$running"',
    `if [ -n "$sshd" ]; then echo '@@effective'; mkdir -p /run/sshd 2>/dev/null; "$sshd" -T 2>&1; fi`,
    'exit 0',
  );
}

/** Installs the daemon if it is missing, then enables and starts it. Prints installed=yes when it had to install. */
export function sshEnableScript(): string {
  return lines(
    FIND_SSHD,
    'installed=no',
    'if [ -z "$sshd" ]; then',
    '  installed=yes',
    perManager({
      apt: [`apt-get update -q && apt-get install ${APT_OPTIONS} -- openssh-server || exit $?`],
      apk: ['apk update -q && apk add --no-progress openssh || exit $?'],
      dnf: ['dnf install -y openssh-server || exit $?'],
      yum: ['yum install -y openssh-server || exit $?'],
      pacman: ['pacman -Syu --noconfirm --needed openssh || exit $?'],
    }),
    FIND_SSHD,
    'fi',
    `if [ -z "$sshd" ]; then echo 'sshd is still missing after the installation.' >&2; exit 1; fi`,
    'echo "installed=$installed"',
    // Missing host keys only. Some templates leave this to the first boot of the service.
    'if command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -A >/dev/null 2>&1; fi',
    'mkdir -p /run/sshd 2>/dev/null',
    DETECT_INIT,
    'echo "init=$init"',
    'case "$init" in',
    '  systemd)',
    FIND_SSH_UNIT,
    // Recent Ubuntu starts the daemon from a socket: enabling the service next to it would conflict.
    '    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then systemctl start ssh.socket || exit $?',
    '    else systemctl enable --now "$u" || exit $?',
    '    fi',
    '  ;;',
    '  openrc)',
    '    rc-update add sshd default || exit $?',
    '    rc-service sshd start || exit $?',
    '  ;;',
    '  sysv)',
    '    service ssh start 2>/dev/null || service sshd start || exit $?',
    '  ;;',
    '  *)',
    '    "$sshd" || exit $?',
    '  ;;',
    'esac',
  );
}

export function sshDisableScript(): string {
  return lines(
    DETECT_INIT,
    'echo "init=$init"',
    'case "$init" in',
    '  systemd)',
    FIND_SSH_UNIT,
    '    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then systemctl disable --now ssh.socket; fi',
    '    systemctl disable --now "$u" || exit $?',
    '  ;;',
    '  openrc)',
    '    rc-service sshd stop',
    '    rc-update del sshd default',
    '    exit 0',
    '  ;;',
    '  sysv)',
    '    service ssh stop 2>/dev/null || service sshd stop || exit $?',
    '    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d ssh disable; elif command -v chkconfig >/dev/null 2>&1; then chkconfig sshd off; fi',
    '    exit 0',
    '  ;;',
    '  *)',
    `    echo 'No service manager found: cannot disable sshd for good.' >&2; exit ${EXIT_NO_MANAGER}`,
    '  ;;',
    'esac',
  );
}

export function listKeysScript(user: string): string {
  return lines(passwdLookup(user), 'if [ -f "$file" ]; then cat "$file"; fi', 'exit 0');
}

/**
 * Prints present or added. Refuses links: root would otherwise chmod and append through a
 * link that the user of that home directory planted, pointing at /etc/shadow.
 */
export function addKeyScript(user: string, key: string, blob: string): string {
  return lines(
    passwdLookup(user),
    sh`key=${key}`,
    sh`blob=${blob}`,
    `if [ -L "$dir" ] || [ -L "$file" ]; then echo 'Refusing to follow a link at ~/.ssh or authorized_keys.' >&2; exit ${EXIT_REFUSED_LINK}; fi`,
    'mkdir -p "$dir" || exit 1',
    'if [ ! -e "$file" ]; then : > "$file" || exit 1; fi',
    'chmod 700 "$dir" || exit 1',
    'chmod 600 "$file" || exit 1',
    'chown -h "$uid:$gid" "$dir" "$file" || exit 1',
    'if grep -qF -- "$blob" "$file"; then echo present; exit 0; fi',
    'if [ -s "$file" ] && [ -n "$(tail -c 1 "$file")" ]; then echo >> "$file"; fi',
    `printf '%s\\n' "$key" >> "$file" || exit 1`,
    'echo added',
  );
}

/** Prints removed=N. Rewrites in place, so that mode and owner stay what they are. */
export function removeKeyScript(user: string, blob: string): string {
  return lines(
    passwdLookup(user),
    sh`blob=${blob}`,
    'if [ ! -f "$file" ]; then echo removed=0; exit 0; fi',
    `if [ -L "$dir" ] || [ -L "$file" ]; then echo 'Refusing to follow a link at ~/.ssh or authorized_keys.' >&2; exit ${EXIT_REFUSED_LINK}; fi`,
    'count=$(grep -cF -- "$blob" "$file")',
    'if [ "${count:-0}" -gt 0 ]; then',
    '  t=$(mktemp "$dir/.pvemcp.XXXXXX") || exit 1',
    `  trap 'rm -f "$t"' EXIT`,
    '  grep -vF -- "$blob" "$file" > "$t"',
    '  cat "$t" > "$file" || exit 1',
    'fi',
    'echo "removed=${count:-0}"',
  );
}

export interface SshdSettings {
  permitRootLogin?: 'yes' | 'no' | 'prohibit-password' | 'forced-commands-only';
  passwordAuthentication?: boolean;
  pubkeyAuthentication?: boolean;
  port?: number;
}

function directives(settings: SshdSettings): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  if (settings.permitRootLogin !== undefined) out.push({ name: 'PermitRootLogin', value: settings.permitRootLogin });
  if (settings.passwordAuthentication !== undefined) out.push({ name: 'PasswordAuthentication', value: settings.passwordAuthentication ? 'yes' : 'no' });
  if (settings.pubkeyAuthentication !== undefined) out.push({ name: 'PubkeyAuthentication', value: settings.pubkeyAuthentication ? 'yes' : 'no' });
  if (settings.port !== undefined) out.push({ name: 'Port', value: String(settings.port) });
  return out;
}

/**
 * The file is changed only with sshd -t agreeing, then sshd -T must show the values really
 * in force: sshd keeps the first value of a setting, and Port adds up, so another file can
 * beat this one. Any failure puts the old file back.
 */
export function sshConfigureScript(settings: SshdSettings): string {
  const wanted = directives(settings);
  const names = wanted.map((d) => d.name).join('|');
  const newLines = wanted.map((d) => `${d.name} ${d.value}`);
  const checks = wanted
    .filter((d) => d.name !== 'Port')
    .map((d) => sh`if ! printf '%s\\n' "$effective" | grep -qix ${`${d.name} ${d.value}`}; then bad=${d.name}; fi`);
  if (settings.port !== undefined) checks.push(sh`if [ "$(printf '%s\\n' "$effective" | grep -i '^port ')" != ${`port ${settings.port}`} ]; then bad=Port; fi`);
  const dropLines = sh`grep -viE ${`^[[:space:]]*(${names})[[:space:]]`}`;
  return lines(
    'umask 022',
    'c=/etc/ssh/sshd_config',
    'd=/etc/ssh/sshd_config.d',
    FIND_SSHD,
    `if [ -z "$sshd" ] || [ ! -f "$c" ]; then echo 'sshd is not installed here: pve_lxc_ssh_enable installs it.' >&2; exit ${EXIT_NOT_FOUND}; fi`,
    'n=$(mktemp /tmp/.pvemcp-sshd.XXXXXX) || exit 1',
    'b=$(mktemp /tmp/.pvemcp-sshd.XXXXXX) || exit 1',
    `trap 'rm -f "$n" "$b"' EXIT`,
    `if [ -d "$d" ] && grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\\.d' "$c"; then`,
    '  t="$d/00-pvemcp.conf"',
    '  layout=dropin',
    '  had=no',
    `  if [ -f "$t" ]; then had=yes; cp -p "$t" "$b" || exit 1; ${dropLines} "$t" > "$n"; fi`,
    sh`  printf '%s\\n' ${newLines} >> "$n"`,
    'else',
    // An old sshd_config with no Include: a block at the very top, since the first value wins.
    '  t="$c"',
    '  layout=main',
    '  had=yes',
    '  cp -p "$c" "$b" || exit 1',
    '  {',
    `    echo '# BEGIN pvemcp'`,
    `    sed -n '/^# BEGIN pvemcp$/,/^# END pvemcp$/p' "$c" | grep -v -e '^# BEGIN pvemcp$' -e '^# END pvemcp$' | ${dropLines}`,
    sh`    printf '%s\\n' ${newLines}`,
    `    echo '# END pvemcp'`,
    settings.port !== undefined
      ? `    sed '/^# BEGIN pvemcp$/,/^# END pvemcp$/d' "$c" | grep -viE '^[[:space:]]*Port[[:space:]]'`
      : `    sed '/^# BEGIN pvemcp$/,/^# END pvemcp$/d' "$c"`,
    '  } > "$n"',
    'fi',
    'echo "layout=$layout"',
    'restore() {',
    '  if [ "$had" = yes ]; then cat "$b" > "$t"; else rm -f "$t"; fi',
    '}',
    'cat "$n" > "$t" || { restore; exit 1; }',
    'chmod 644 "$t" 2>/dev/null',
    'mkdir -p /run/sshd 2>/dev/null',
    'if ! out=$("$sshd" -t 2>&1); then',
    '  restore',
    `  printf 'sshd -t refused this configuration, so the old one was put back: %s\\n' "$out" >&2`,
    `  exit ${EXIT_SSHD_REJECTED}`,
    'fi',
    'effective=$("$sshd" -T 2>/dev/null)',
    'bad=',
    ...checks,
    'if [ -n "$bad" ]; then',
    '  restore',
    `  printf 'sshd would not use the new value of %s: another file sets it first. The old configuration was put back.\\n' "$bad" >&2`,
    `  exit ${EXIT_SSHD_NOT_EFFECTIVE}`,
    'fi',
    DETECT_INIT,
    'reloaded=no',
    'reload_sshd() {',
    '  case "$init" in',
    '    systemd)',
    FIND_SSH_UNIT,
    '      systemctl daemon-reload 2>/dev/null',
    '      if systemctl is-active ssh.socket >/dev/null 2>&1; then systemctl restart ssh.socket || return 1; reloaded=yes; fi',
    '      if systemctl is-active "$u" >/dev/null 2>&1; then systemctl reload-or-restart "$u" || return 1; reloaded=yes; fi',
    '    ;;',
    '    openrc)',
    '      if rc-service sshd status >/dev/null 2>&1; then rc-service sshd reload || rc-service sshd restart || return 1; reloaded=yes; fi',
    '    ;;',
    '    sysv)',
    '      if service ssh status >/dev/null 2>&1; then service ssh reload || return 1; reloaded=yes;',
    '      elif service sshd status >/dev/null 2>&1; then service sshd reload || return 1; reloaded=yes; fi',
    '    ;;',
    '  esac',
    '  return 0',
    '}',
    'if ! reload_sshd; then',
    '  restore',
    '  reload_sshd',
    `  echo 'sshd could not reload the new configuration, so the old one was put back.' >&2`,
    `  exit ${EXIT_RELOAD_FAILED}`,
    'fi',
    'echo "reloaded=$reloaded"',
    sh`printf '%s\\n' "$effective" | grep -iE ${`^(${names.toLowerCase()}) `}`,
    'exit 0',
  );
}

/** Every script with sample arguments, for the tests that check them all. */
export function sampleScripts(): Record<string, string> {
  const settings: SshdSettings = { permitRootLogin: 'no', passwordAuthentication: false, pubkeyAuthentication: true, port: 2222 };
  return {
    fileStat: fileStatScript('/etc/hostname'),
    readFile: readFileScript('/etc/hostname'),
    readFilePartial: readFileScript('/etc/hostname', 100),
    listDir: listDirScript('/etc'),
    deleteFile: deleteFileScript('/tmp/x', false),
    deleteFileMissingOk: deleteFileScript('/tmp/x', true),
    writeFile: writeFileScript('/tmp/x', { mode: '0640', owner: 'root:root', backup: true, createParents: true }),
    writeFilePlain: writeFileScript('/tmp/x', {}),
    lxcInfo: lxcInfoScript(),
    processes: processesScript(),
    ports: portsScript(),
    diskUsage: diskUsageScript('/var'),
    logs: logsScript({ lines: 50 }),
    logsUnit: logsScript({ lines: 50, unit: 'nginx', since: '-1h' }),
    serviceStatus: serviceStatusScript('nginx'),
    serviceStatusAll: serviceStatusScript(),
    service: serviceScript('restart', 'nginx'),
    serviceEnable: serviceScript('enable', 'nginx'),
    serviceDisable: serviceScript('disable', 'nginx'),
    install: installPackagesScript(['curl', 'g++'], true),
    installNoRefresh: installPackagesScript(['curl'], false),
    remove: removePackagesScript(['curl'], false),
    purge: removePackagesScript(['curl'], true),
    update: updatePackagesScript(false),
    updateFull: updatePackagesScript(true),
    listPackages: listPackagesScript(),
    createUser: createUserScript('alice', { uid: 1500, shell: '/bin/sh', home: '/home/alice', comment: 'Alice', groups: ['wheel', 'adm'], system: false }),
    createSystemUser: createUserScript('svc', { system: true }),
    deleteUser: deleteUserScript('alice', true),
    sshStatus: sshStatusScript(),
    sshEnable: sshEnableScript(),
    sshDisable: sshDisableScript(),
    listKeys: listKeysScript('root'),
    addKey: addKeyScript('root', 'ssh-ed25519 AAAA comment', 'AAAA'),
    removeKey: removeKeyScript('root', 'AAAA'),
    sshConfigure: sshConfigureScript(settings),
    sshConfigureNoPort: sshConfigureScript({ permitRootLogin: 'prohibit-password' }),
  };
}
