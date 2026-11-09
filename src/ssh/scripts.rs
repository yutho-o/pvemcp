//! Shell text run by POSIX sh. Inside a container that may be dash, BusyBox ash or bash, so:
//! no bash syntax, and only options BusyBox has too. A test runs these under a real sh and
//! checks them for bash syntax.
//!
//! The scripts detect the distribution where they run instead of in an earlier round trip,
//! so that a dry run shows what would really happen and nothing can change in between.
//!
//! Exit codes of our own, turned into typed errors by the tools.
//!
//! Lines holding braces of the shell (`${x}`, `{ ... }`) are plain strings, never sh! formats.

use crate::errors::Result;
use crate::sh;
use crate::ssh::quote::raw;

pub const EXIT_NOT_FOUND: i64 = 44;
pub const EXIT_NOT_A_FILE: i64 = 45;
pub const EXIT_NOT_READABLE: i64 = 46;
pub const EXIT_NO_MANAGER: i64 = 47;
pub const EXIT_REFUSED_LINK: i64 = 48;
pub const EXIT_SSHD_REJECTED: i64 = 65;
pub const EXIT_SSHD_NOT_EFFECTIVE: i64 = 66;
pub const EXIT_RELOAD_FAILED: i64 = 67;
pub const EXIT_CD_FAILED: i64 = 125;

/// How a script is carried into the container: pct exec passes argv on with no shell of its own.
pub fn pct_exec(vmid: i64, script: &str) -> Result<String> {
    sh!("pct exec {} -- sh -c {}", vmid, script)
}

fn lines<S: AsRef<str>>(parts: &[S]) -> String {
    parts.iter().map(|p| p.as_ref()).collect::<Vec<_>>().join("\n")
}

/// Sets init to systemd, openrc, sysv or none.
const DETECT_INIT: &str = "if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then init=systemd\n\
elif command -v rc-service >/dev/null 2>&1; then init=openrc\n\
elif command -v service >/dev/null 2>&1; then init=sysv\n\
else init=none\n\
fi";

/// Sets sshd to the path of the daemon, or empty. It is not on the PATH of every login.
const FIND_SSHD: &str = "sshd=$(command -v sshd 2>/dev/null) || sshd=\n\
if [ -z \"$sshd\" ] && [ -x /usr/sbin/sshd ]; then sshd=/usr/sbin/sshd; fi";

/// The unit of the daemon under systemd: ssh on Debian and Ubuntu, sshd elsewhere.
const FIND_SSH_UNIT: &str = "u=sshd\nif systemctl cat ssh.service >/dev/null 2>&1; then u=ssh; fi";

/// Reads /etc/passwd itself: no grep pattern to escape, and getent is not everywhere.
fn passwd_lookup(user: &str) -> Result<String> {
    Ok(lines(&[
        sh!("want={}", user)?,
        "found=".into(),
        "while IFS=: read -r n _p ui gi _g hd _s; do".into(),
        "  if [ \"$n\" = \"$want\" ]; then found=1; home=$hd; uid=$ui; gid=$gi; break; fi".into(),
        "done < /etc/passwd".into(),
        format!(r#"if [ -z "$found" ] || [ -z "$home" ]; then printf 'No such user: %s\n' "$want" >&2; exit {EXIT_NOT_FOUND}; fi"#),
        "dir=\"$home/.ssh\"".into(),
        "file=\"$dir/authorized_keys\"".into(),
    ]))
}

/// Size on the first line, the path with links resolved after it.
pub fn file_stat_script(path: &str) -> Result<String> {
    Ok(lines(&[
        sh!("p={}", path)?,
        format!(r#"if [ ! -e "$p" ]; then echo 'No such file or directory' >&2; exit {EXIT_NOT_FOUND}; fi"#),
        format!(r#"if [ ! -f "$p" ]; then echo 'Not a regular file' >&2; exit {EXIT_NOT_A_FILE}; fi"#),
        format!(r#"if [ ! -r "$p" ]; then echo 'Permission denied' >&2; exit {EXIT_NOT_READABLE}; fi"#),
        r#"wc -c < "$p" | tr -d ' '"#.into(),
        r#"readlink -f "$p" 2>/dev/null || printf '%s\n' "$p""#.into(),
    ]))
}

pub fn read_file_script(path: &str, limit: Option<u64>) -> Result<String> {
    match limit {
        None => sh!("cat -- {}", path),
        Some(n) => sh!("head -c {} -- {}", n, path),
    }
}

pub fn list_dir_script(path: &str) -> Result<String> {
    sh!("ls -la -- {}", path)
}

pub fn delete_file_script(path: &str, missing_ok: bool) -> Result<String> {
    if missing_ok { sh!("rm -f -- {}", path) } else { sh!("rm -- {}", path) }
}

#[derive(Debug, Clone, Default)]
pub struct WriteFileOptions {
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub backup: bool,
    pub create_parents: bool,
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

/// Stdin to a file, whole or not at all: a temporary file next to the target, renamed over it.
/// An existing file keeps its mode and owner, unless told otherwise. On /etc/pve neither can be
/// set, so that part is best effort unless it was asked for.
pub fn write_file_script(path: &str, opts: &WriteFileOptions) -> Result<String> {
    let mut out: Vec<String> = vec![
        "umask 077".into(),
        sh!("p={}", path)?,
        r#"if [ -L "$p" ]; then p=$(readlink -f "$p") || exit 1; fi"#.into(),
        format!(r#"if [ -d "$p" ]; then echo 'Is a directory' >&2; exit {EXIT_NOT_A_FILE}; fi"#),
        "d=${p%/*}".into(),
        r#"if [ -z "$d" ]; then d=/; fi"#.into(),
        if opts.create_parents {
            r#"mkdir -p "$d" || exit 1"#.into()
        } else {
            format!(r#"if [ ! -d "$d" ]; then printf 'No such directory: %s\n' "$d" >&2; exit {EXIT_NOT_FOUND}; fi"#)
        },
        "b=".into(),
    ];
    if opts.backup {
        out.push(r#"if [ -e "$p" ]; then b="$p.bak.$(date +%Y%m%d%H%M%S)"; cp -p "$p" "$b" || exit 1; fi"#.into());
    }
    out.extend([
        r#"t=$(mktemp "$d/.pvemcp.XXXXXX") || exit 1"#.to_string(),
        r#"trap 'rm -f "$t"' EXIT"#.into(),
        r#"cat > "$t" || exit 1"#.into(),
        r#"if [ -e "$p" ]; then"#.into(),
        r#"  m=$(stat -c %a "$p" 2>/dev/null) && chmod "$m" "$t" 2>/dev/null"#.into(),
        r#"  o=$(stat -c %u:%g "$p" 2>/dev/null) && chown "$o" "$t" 2>/dev/null"#.into(),
        "else".into(),
        r#"  chmod 644 "$t" 2>/dev/null"#.into(),
        "fi".into(),
    ]);
    if let Some(mode) = non_empty(&opts.mode) {
        out.push(sh!("chmod {} \"$t\" || exit 1", mode)?);
    }
    if let Some(owner) = non_empty(&opts.owner) {
        out.push(sh!("chown {} \"$t\" || exit 1", owner)?);
    }
    out.extend([r#"mv -f "$t" "$p" || exit 1"#.to_string(), r#"wc -c < "$p" | tr -d ' '"#.into(), r#"printf '%s\n' "$b""#.into()]);
    Ok(lines(&out))
}

/// For each command wanted, what to run.
pub fn lxc_info_script() -> String {
    lines(&[
        "echo '@@os'; cat /etc/os-release 2>/dev/null",
        "echo '@@kernel'; uname -srm 2>/dev/null",
        "echo '@@hostname'; hostname 2>/dev/null",
        "echo '@@uptime'; cat /proc/uptime 2>/dev/null",
        "echo '@@ips'; ip -o addr show 2>/dev/null || ifconfig 2>/dev/null",
        "echo '@@mounts'; cat /proc/mounts 2>/dev/null",
        "exit 0",
    ])
}

/// BusyBox ps may have -o with fewer columns, or nothing but plain ps.
pub fn processes_script() -> String {
    "ps -eo pid,ppid,user,pcpu,pmem,etime,args 2>/dev/null || ps -o pid,ppid,user,args 2>/dev/null || ps".into()
}

/// Alpine has netstat from BusyBox, Debian minimal only ss, some templates neither.
pub fn ports_script() -> String {
    lines(&[
        "if command -v ss >/dev/null 2>&1; then ss -tulnp",
        "elif command -v netstat >/dev/null 2>&1; then netstat -tuln",
        "else echo 'Neither ss nor netstat here: raw kernel tables.'; cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null; exit 0",
        "fi",
    ])
}

pub fn disk_usage_script(path: Option<&str>) -> Result<String> {
    let mut out: Vec<String> = vec!["df -hP 2>/dev/null || df -h".into()];
    if let Some(p) = path.filter(|p| !p.is_empty()) {
        out.push("echo '@@du'".into());
        out.push(sh!("du -xsh -- {} 2>&1", p)?);
    }
    out.push("exit 0".into());
    Ok(lines(&out))
}

#[derive(Debug, Clone, Default)]
pub struct LogsOptions {
    pub lines: i64,
    pub unit: Option<String>,
    pub since: Option<String>,
}

pub fn logs_script(opts: &LogsOptions) -> Result<String> {
    let unit = non_empty(&opts.unit);
    let mut journal: Vec<String> = vec!["journalctl --no-pager -o short-iso".into(), sh!("-n {}", opts.lines)?];
    if let Some(u) = unit {
        journal.push(sh!("-u {}", u)?);
    }
    if let Some(since) = non_empty(&opts.since) {
        journal.push(sh!("{}", format!("--since={since}"))?);
    }
    let journal = journal.join(" ");
    let unit_files = match unit {
        Some(u) => sh!("/var/log/{}.log /var/log/{}/current /var/log/{}/{}.log ", u, u, u, u)?,
        None => String::new(),
    };
    let mut out: Vec<String> = vec![
        sh!("n={}", opts.lines)?,
        "if command -v journalctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ -d /var/log/journal ]; }; then".into(),
        "  echo 'source=journal'".into(),
        format!("  {journal} && exit 0"),
        "fi".into(),
        format!("for f in {unit_files}/var/log/syslog /var/log/messages; do"),
        "  if [ -r \"$f\" ]; then".into(),
        r#"    printf 'source=%s\n' "$f""#.into(),
    ];
    if let Some(u) = unit {
        out.push(sh!("    case \"$f\" in /var/log/syslog|/var/log/messages) grep -F -- {} \"$f\" | tail -n \"$n\"; exit 0;; esac", u)?);
    }
    out.extend([
        "    tail -n \"$n\" \"$f\"".to_string(),
        "    exit $?".into(),
        "  fi".into(),
        "done".into(),
        "echo 'No journal, and no readable log file in /var/log.' >&2".into(),
        format!("exit {EXIT_NOT_FOUND}"),
    ]);
    Ok(lines(&out))
}

pub fn service_status_script(unit: Option<&str>) -> Result<String> {
    let unit = unit.filter(|u| !u.is_empty());
    let (systemd, openrc, sysv): (Vec<String>, Vec<String>, Vec<String>) = match unit {
        Some(u) => (
            vec![
                sh!("echo \"active=$(systemctl is-active -- {} 2>/dev/null)\"", u)?,
                sh!("echo \"enabled=$(systemctl is-enabled -- {} 2>/dev/null)\"", u)?,
                sh!("systemctl status --no-pager --lines=20 -- {} 2>&1", u)?,
            ],
            vec![
                sh!("if rc-service {} status >/dev/null 2>&1; then echo active=active; else echo active=inactive; fi", u)?,
                sh!("if rc-update show default 2>/dev/null | grep -qw -- {}; then echo enabled=enabled; else echo enabled=disabled; fi", u)?,
                sh!("rc-service {} status 2>&1", u)?,
            ],
            vec![sh!("if service {} status >/dev/null 2>&1; then echo active=active; else echo active=inactive; fi", u)?, sh!("service {} status 2>&1", u)?],
        ),
        None => (
            vec!["systemctl list-units --type=service --all --no-pager --no-legend 2>&1".into()],
            vec!["rc-status --all 2>&1".into()],
            vec!["service --status-all 2>&1".into()],
        ),
    };
    let mut out: Vec<String> = vec![DETECT_INIT.into(), "echo \"init=$init\"".into(), "case \"$init\" in".into(), "  systemd)".into()];
    out.extend(systemd);
    out.extend(["  ;;".to_string(), "  openrc)".into()]);
    out.extend(openrc);
    out.extend(["  ;;".to_string(), "  sysv)".into()]);
    out.extend(sysv);
    out.extend(["  ;;".to_string(), "esac".into(), "exit 0".into()]);
    Ok(lines(&out))
}

/// start, stop, restart, reload, enable or disable.
pub fn service_script(action: &str, unit: &str) -> Result<String> {
    let openrc = match action {
        "enable" => sh!("rc-update add {} default", unit)?,
        "disable" => sh!("rc-update del {} default", unit)?,
        _ => sh!("rc-service {} {}", unit, action)?,
    };
    let sysv = if action == "enable" || action == "disable" {
        lines(&[
            "if command -v update-rc.d >/dev/null 2>&1; then".to_string(),
            sh!("    update-rc.d {} {}", unit, action)?,
            "  elif command -v chkconfig >/dev/null 2>&1; then".into(),
            sh!("    chkconfig {} {}", unit, if action == "enable" { "on" } else { "off" })?,
            "  else".into(),
            format!("    echo 'Neither update-rc.d nor chkconfig here.' >&2; exit {EXIT_NO_MANAGER}"),
            "  fi".into(),
        ])
    } else {
        sh!("service {} {}", unit, action)?
    };
    Ok(lines(&[
        DETECT_INIT.to_string(),
        "echo \"init=$init\"".into(),
        "case \"$init\" in".into(),
        sh!("  systemd) systemctl {} -- {} ;;", action, unit)?,
        format!("  openrc) {openrc} ;;"),
        format!("  sysv) {sysv} ;;"),
        format!("  *) echo 'No service manager found: no systemd, OpenRC or service command.' >&2; exit {EXIT_NO_MANAGER} ;;"),
        "esac".into(),
    ]))
}

fn no_manager() -> String {
    format!("  echo 'No supported package manager found: apt-get, apk, dnf, yum or pacman.' >&2\n  exit {EXIT_NO_MANAGER}")
}
const APT_OPTIONS: &str = "-y -q -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold";

struct Branches {
    apt: Vec<String>,
    apk: Vec<String>,
    dnf: Vec<String>,
    yum: Vec<String>,
    pacman: Vec<String>,
}

/// Each branch ends with the command whose status counts.
fn per_manager(b: Branches) -> String {
    let indent = |v: Vec<String>| v.into_iter().map(|l| format!("  {l}")).collect::<Vec<_>>();
    let mut out: Vec<String> = vec!["if command -v apt-get >/dev/null 2>&1; then".into(), "  export DEBIAN_FRONTEND=noninteractive".into(), "  echo manager=apt".into()];
    out.extend(indent(b.apt));
    out.extend(["elif command -v apk >/dev/null 2>&1; then".to_string(), "  echo manager=apk".into()]);
    out.extend(indent(b.apk));
    out.extend(["elif command -v dnf >/dev/null 2>&1; then".to_string(), "  echo manager=dnf".into()]);
    out.extend(indent(b.dnf));
    out.extend(["elif command -v yum >/dev/null 2>&1; then".to_string(), "  echo manager=yum".into()]);
    out.extend(indent(b.yum));
    out.extend(["elif command -v pacman >/dev/null 2>&1; then".to_string(), "  echo manager=pacman".into()]);
    out.extend(indent(b.pacman));
    out.extend(["else".to_string(), no_manager(), "fi".into()]);
    lines(&out)
}

/// Arch does not support partial upgrades, so refreshing there means upgrading. dnf and yum refresh on their own.
pub fn install_packages_script(packages: &[String], refresh: bool) -> Result<String> {
    Ok(per_manager(Branches {
        apt: vec![format!("{}{}", if refresh { "apt-get update -q && " } else { "" }, sh!("apt-get install {} -- {}", raw(APT_OPTIONS), packages)?)],
        apk: vec![format!("{}{}", if refresh { "apk update -q && " } else { "" }, sh!("apk add --no-progress {}", packages)?)],
        dnf: vec![sh!("dnf install -y {}", packages)?],
        yum: vec![sh!("yum install -y {}", packages)?],
        pacman: vec![if refresh { sh!("pacman -Syu --noconfirm --needed {}", packages)? } else { sh!("pacman -S --noconfirm --needed {}", packages)? }],
    }))
}

pub fn remove_packages_script(packages: &[String], purge: bool) -> Result<String> {
    Ok(per_manager(Branches {
        apt: vec![sh!("apt-get {} {} -- {}", if purge { "purge" } else { "remove" }, raw(APT_OPTIONS), packages)?],
        apk: vec![sh!("apk del --no-progress {}", packages)?],
        dnf: vec![sh!("dnf remove -y {}", packages)?],
        yum: vec![sh!("yum remove -y {}", packages)?],
        pacman: vec![if purge { sh!("pacman -Rns --noconfirm {}", packages)? } else { sh!("pacman -R --noconfirm {}", packages)? }],
    }))
}

pub fn update_packages_script(full: bool) -> String {
    per_manager(Branches {
        apt: vec![format!("apt-get update -q && apt-get {} {APT_OPTIONS}", if full { "dist-upgrade" } else { "upgrade" })],
        apk: vec!["apk update -q && apk upgrade --no-progress".into()],
        dnf: vec!["dnf upgrade -y".into()],
        yum: vec!["yum update -y".into()],
        pacman: vec!["pacman -Syu --noconfirm".into()],
    })
}

/// The first line says which manager; the rest depends on it.
pub fn list_packages_script() -> String {
    lines(&[
        "if command -v dpkg-query >/dev/null 2>&1; then".to_string(),
        "  echo manager=dpkg".into(),
        r"  dpkg-query -W -f='${Package}\t${Version}\t${Status}\n'".into(),
        "elif command -v apk >/dev/null 2>&1; then".into(),
        "  echo manager=apk".into(),
        "  apk info -v 2>/dev/null".into(),
        "elif command -v rpm >/dev/null 2>&1; then".into(),
        "  echo manager=rpm".into(),
        r"  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'".into(),
        "elif command -v pacman >/dev/null 2>&1; then".into(),
        "  echo manager=pacman".into(),
        "  pacman -Q".into(),
        "else".into(),
        no_manager(),
        "fi".into(),
    ])
}

#[derive(Debug, Clone, Default)]
pub struct CreateUserOptions {
    pub uid: Option<i64>,
    pub shell: Option<String>,
    pub home: Option<String>,
    pub comment: Option<String>,
    pub groups: Vec<String>,
    pub system: bool,
}

/// useradd where shadow is installed, else the adduser of BusyBox, which has other options.
pub fn create_user_script(name: &str, opts: &CreateUserOptions) -> Result<String> {
    let mut useradd: Vec<String> = vec!["useradd".into(), "-m".into()];
    let mut adduser: Vec<String> = vec!["adduser".into(), "-D".into()];
    if opts.system {
        useradd.push("-r".into());
        adduser.push("-S".into());
    }
    if let Some(uid) = opts.uid {
        useradd.push(sh!("-u {}", uid)?);
        adduser.push(sh!("-u {}", uid)?);
    }
    if let Some(shell) = non_empty(&opts.shell) {
        useradd.push(sh!("-s {}", shell)?);
        adduser.push(sh!("-s {}", shell)?);
    }
    if let Some(home) = non_empty(&opts.home) {
        useradd.push(sh!("-d {}", home)?);
        adduser.push(sh!("-h {}", home)?);
    }
    if let Some(comment) = non_empty(&opts.comment) {
        useradd.push(sh!("-c {}", comment)?);
        adduser.push(sh!("-g {}", comment)?);
    }
    let groups = &opts.groups;
    if !groups.is_empty() {
        useradd.push(sh!("-G {}", groups.join(","))?);
    }
    useradd.push(sh!("{}", name)?);
    adduser.push(sh!("{}", name)?);
    let mut out: Vec<String> = vec![
        "if command -v useradd >/dev/null 2>&1; then".into(),
        format!("  {}", useradd.join(" ")),
        "elif command -v adduser >/dev/null 2>&1; then".into(),
        format!("  {} || exit $?", adduser.join(" ")),
    ];
    if !groups.is_empty() {
        out.push(sh!("  for g in {}; do addgroup {} \"$g\" || exit $?; done", groups, name)?);
    }
    out.extend(["else".to_string(), format!("  echo 'Neither useradd nor adduser here.' >&2; exit {EXIT_NO_MANAGER}"), "fi".into()]);
    Ok(lines(&out))
}

pub fn delete_user_script(name: &str, remove_home: bool) -> Result<String> {
    let quoted = sh!("{}", name)?;
    Ok(lines(&[
        "if command -v userdel >/dev/null 2>&1; then".to_string(),
        format!("  userdel {}{quoted}", if remove_home { "-r " } else { "" }),
        "elif command -v deluser >/dev/null 2>&1; then".into(),
        format!("  deluser {}{quoted}", if remove_home { "--remove-home " } else { "" }),
        "else".into(),
        format!("  echo 'Neither userdel nor deluser here.' >&2; exit {EXIT_NO_MANAGER}"),
        "fi".into(),
    ]))
}

pub fn ssh_status_script() -> String {
    lines(&[
        FIND_SSHD,
        "echo \"binary=$sshd\"",
        "if command -v dropbear >/dev/null 2>&1; then echo dropbear=yes; fi",
        "running=no",
        "if command -v pgrep >/dev/null 2>&1; then",
        "  if pgrep -x sshd >/dev/null 2>&1; then running=yes; fi",
        "elif command -v pidof >/dev/null 2>&1; then",
        "  if pidof sshd >/dev/null 2>&1; then running=yes; fi",
        "fi",
        DETECT_INIT,
        "echo \"init=$init\"",
        "if [ \"$init\" = systemd ] && systemctl is-active ssh.socket >/dev/null 2>&1; then running=socket; fi",
        "echo \"running=$running\"",
        "if [ -n \"$sshd\" ]; then echo '@@effective'; mkdir -p /run/sshd 2>/dev/null; \"$sshd\" -T 2>&1; fi",
        "exit 0",
    ])
}

/// Installs the daemon if it is missing, then enables and starts it. Prints installed=yes when it had to install.
pub fn ssh_enable_script() -> String {
    let install = per_manager(Branches {
        apt: vec![format!("apt-get update -q && apt-get install {APT_OPTIONS} -- openssh-server || exit $?")],
        apk: vec!["apk update -q && apk add --no-progress openssh || exit $?".into()],
        dnf: vec!["dnf install -y openssh-server || exit $?".into()],
        yum: vec!["yum install -y openssh-server || exit $?".into()],
        pacman: vec!["pacman -Syu --noconfirm --needed openssh || exit $?".into()],
    });
    lines(&[
        FIND_SSHD,
        "installed=no",
        "if [ -z \"$sshd\" ]; then",
        "  installed=yes",
        &install,
        FIND_SSHD,
        "fi",
        "if [ -z \"$sshd\" ]; then echo 'sshd is still missing after the installation.' >&2; exit 1; fi",
        "echo \"installed=$installed\"",
        // Missing host keys only. Some templates leave this to the first boot of the service.
        "if command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -A >/dev/null 2>&1; fi",
        "mkdir -p /run/sshd 2>/dev/null",
        DETECT_INIT,
        "echo \"init=$init\"",
        "case \"$init\" in",
        "  systemd)",
        FIND_SSH_UNIT,
        // Recent Ubuntu starts the daemon from a socket: enabling the service next to it would conflict.
        "    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then systemctl start ssh.socket || exit $?",
        "    else systemctl enable --now \"$u\" || exit $?",
        "    fi",
        "  ;;",
        "  openrc)",
        "    rc-update add sshd default || exit $?",
        "    rc-service sshd start || exit $?",
        "  ;;",
        "  sysv)",
        "    service ssh start 2>/dev/null || service sshd start || exit $?",
        "  ;;",
        "  *)",
        "    \"$sshd\" || exit $?",
        "  ;;",
        "esac",
    ])
}

pub fn ssh_disable_script() -> String {
    let no_manager_line = format!("    echo 'No service manager found: cannot disable sshd for good.' >&2; exit {EXIT_NO_MANAGER}");
    lines(&[
        DETECT_INIT,
        "echo \"init=$init\"",
        "case \"$init\" in",
        "  systemd)",
        FIND_SSH_UNIT,
        "    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then systemctl disable --now ssh.socket; fi",
        "    systemctl disable --now \"$u\" || exit $?",
        "  ;;",
        "  openrc)",
        "    rc-service sshd stop",
        "    rc-update del sshd default",
        "    exit 0",
        "  ;;",
        "  sysv)",
        "    service ssh stop 2>/dev/null || service sshd stop || exit $?",
        "    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d ssh disable; elif command -v chkconfig >/dev/null 2>&1; then chkconfig sshd off; fi",
        "    exit 0",
        "  ;;",
        "  *)",
        &no_manager_line,
        "  ;;",
        "esac",
    ])
}

pub fn list_keys_script(user: &str) -> Result<String> {
    Ok(lines(&[passwd_lookup(user)?, "if [ -f \"$file\" ]; then cat \"$file\"; fi".into(), "exit 0".into()]))
}

fn refuse_link_line() -> String {
    format!(r#"if [ -L "$dir" ] || [ -L "$file" ]; then echo 'Refusing to follow a link at ~/.ssh or authorized_keys.' >&2; exit {EXIT_REFUSED_LINK}; fi"#)
}

/// Prints present or added. Refuses links: root would otherwise chmod and append through a
/// link that the user of that home directory planted, pointing at /etc/shadow.
pub fn add_key_script(user: &str, key: &str, blob: &str) -> Result<String> {
    Ok(lines(&[
        passwd_lookup(user)?,
        sh!("key={}", key)?,
        sh!("blob={}", blob)?,
        refuse_link_line(),
        r#"mkdir -p "$dir" || exit 1"#.into(),
        r#"if [ ! -e "$file" ]; then : > "$file" || exit 1; fi"#.into(),
        r#"chmod 700 "$dir" || exit 1"#.into(),
        r#"chmod 600 "$file" || exit 1"#.into(),
        r#"chown -h "$uid:$gid" "$dir" "$file" || exit 1"#.into(),
        r#"if grep -qF -- "$blob" "$file"; then echo present; exit 0; fi"#.into(),
        r#"if [ -s "$file" ] && [ -n "$(tail -c 1 "$file")" ]; then echo >> "$file"; fi"#.into(),
        r#"printf '%s\n' "$key" >> "$file" || exit 1"#.into(),
        "echo added".into(),
    ]))
}

/// Prints removed=N. Rewrites in place, so that mode and owner stay what they are.
pub fn remove_key_script(user: &str, blob: &str) -> Result<String> {
    Ok(lines(&[
        passwd_lookup(user)?,
        sh!("blob={}", blob)?,
        r#"if [ ! -f "$file" ]; then echo removed=0; exit 0; fi"#.into(),
        refuse_link_line(),
        r#"count=$(grep -cF -- "$blob" "$file")"#.into(),
        r#"if [ "${count:-0}" -gt 0 ]; then"#.into(),
        r#"  t=$(mktemp "$dir/.pvemcp.XXXXXX") || exit 1"#.into(),
        r#"  trap 'rm -f "$t"' EXIT"#.into(),
        r#"  grep -vF -- "$blob" "$file" > "$t""#.into(),
        r#"  cat "$t" > "$file" || exit 1"#.into(),
        "fi".into(),
        r#"echo "removed=${count:-0}""#.into(),
    ]))
}

#[derive(Debug, Clone, Default)]
pub struct SshdSettings {
    /// yes, no, prohibit-password or forced-commands-only.
    pub permit_root_login: Option<String>,
    pub password_authentication: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub port: Option<i64>,
}

impl SshdSettings {
    pub fn is_empty(&self) -> bool {
        self.permit_root_login.is_none() && self.password_authentication.is_none() && self.pubkey_authentication.is_none() && self.port.is_none()
    }
}

fn directives(s: &SshdSettings) -> Vec<(&'static str, String)> {
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    let mut out = Vec::new();
    if let Some(v) = &s.permit_root_login {
        out.push(("PermitRootLogin", v.clone()));
    }
    if let Some(v) = s.password_authentication {
        out.push(("PasswordAuthentication", yes_no(v)));
    }
    if let Some(v) = s.pubkey_authentication {
        out.push(("PubkeyAuthentication", yes_no(v)));
    }
    if let Some(v) = s.port {
        out.push(("Port", v.to_string()));
    }
    out
}

/// The file is changed only with sshd -t agreeing, then sshd -T must show the values really
/// in force: sshd keeps the first value of a setting, and Port adds up, so another file can
/// beat this one. Any failure puts the old file back.
pub fn ssh_configure_script(settings: &SshdSettings) -> Result<String> {
    let wanted = directives(settings);
    let names = wanted.iter().map(|(n, _)| *n).collect::<Vec<_>>().join("|");
    let new_lines: Vec<String> = wanted.iter().map(|(n, v)| format!("{n} {v}")).collect();
    let mut checks: Vec<String> = Vec::new();
    for (n, v) in wanted.iter().filter(|(n, _)| *n != "Port") {
        checks.push(sh!(r#"if ! printf '%s\n' "$effective" | grep -qix {}; then bad={}; fi"#, format!("{n} {v}"), *n)?);
    }
    if let Some(port) = settings.port {
        checks.push(sh!(r#"if [ "$(printf '%s\n' "$effective" | grep -i '^port ')" != {} ]; then bad=Port; fi"#, format!("port {port}"))?);
    }
    let drop_lines = sh!("grep -viE {}", format!("^[[:space:]]*({names})[[:space:]]"))?;
    let mut out: Vec<String> = vec![
        "umask 022".into(),
        "c=/etc/ssh/sshd_config".into(),
        "d=/etc/ssh/sshd_config.d".into(),
        FIND_SSHD.into(),
        format!(r#"if [ -z "$sshd" ] || [ ! -f "$c" ]; then echo 'sshd is not installed here: pve_lxc_ssh_enable installs it.' >&2; exit {EXIT_NOT_FOUND}; fi"#),
        "n=$(mktemp /tmp/.pvemcp-sshd.XXXXXX) || exit 1".into(),
        "b=$(mktemp /tmp/.pvemcp-sshd.XXXXXX) || exit 1".into(),
        r#"trap 'rm -f "$n" "$b"' EXIT"#.into(),
        r#"if [ -d "$d" ] && grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$c"; then"#.into(),
        r#"  t="$d/00-pvemcp.conf""#.into(),
        "  layout=dropin".into(),
        "  had=no".into(),
        format!(r#"  if [ -f "$t" ]; then had=yes; cp -p "$t" "$b" || exit 1; {drop_lines} "$t" > "$n"; fi"#),
        sh!(r#"  printf '%s\n' {} >> "$n""#, &new_lines)?,
        "else".into(),
        // An old sshd_config with no Include: a block at the very top, since the first value wins.
        r#"  t="$c""#.into(),
        "  layout=main".into(),
        "  had=yes".into(),
        r#"  cp -p "$c" "$b" || exit 1"#.into(),
        "  {".into(),
        "    echo '# BEGIN pvemcp'".into(),
        format!(r#"    sed -n '/^# BEGIN pvemcp$/,/^# END pvemcp$/p' "$c" | grep -v -e '^# BEGIN pvemcp$' -e '^# END pvemcp$' | {drop_lines}"#),
        sh!(r#"    printf '%s\n' {}"#, &new_lines)?,
        "    echo '# END pvemcp'".into(),
        if settings.port.is_some() {
            r#"    sed '/^# BEGIN pvemcp$/,/^# END pvemcp$/d' "$c" | grep -viE '^[[:space:]]*Port[[:space:]]'"#.into()
        } else {
            r#"    sed '/^# BEGIN pvemcp$/,/^# END pvemcp$/d' "$c""#.into()
        },
        r#"  } > "$n""#.into(),
        "fi".into(),
        r#"echo "layout=$layout""#.into(),
        "restore() {".into(),
        r#"  if [ "$had" = yes ]; then cat "$b" > "$t"; else rm -f "$t"; fi"#.into(),
        "}".into(),
        r#"cat "$n" > "$t" || { restore; exit 1; }"#.into(),
        r#"chmod 644 "$t" 2>/dev/null"#.into(),
        "mkdir -p /run/sshd 2>/dev/null".into(),
        r#"if ! out=$("$sshd" -t 2>&1); then"#.into(),
        "  restore".into(),
        r#"  printf 'sshd -t refused this configuration, so the old one was put back: %s\n' "$out" >&2"#.into(),
        format!("  exit {EXIT_SSHD_REJECTED}"),
        "fi".into(),
        r#"effective=$("$sshd" -T 2>/dev/null)"#.into(),
        "bad=".into(),
    ];
    out.extend(checks);
    out.extend([
        r#"if [ -n "$bad" ]; then"#.to_string(),
        "  restore".into(),
        r#"  printf 'sshd would not use the new value of %s: another file sets it first. The old configuration was put back.\n' "$bad" >&2"#.into(),
        format!("  exit {EXIT_SSHD_NOT_EFFECTIVE}"),
        "fi".into(),
        DETECT_INIT.into(),
        "reloaded=no".into(),
        "reload_sshd() {".into(),
        r#"  case "$init" in"#.into(),
        "    systemd)".into(),
        FIND_SSH_UNIT.into(),
        "      systemctl daemon-reload 2>/dev/null".into(),
        "      if systemctl is-active ssh.socket >/dev/null 2>&1; then systemctl restart ssh.socket || return 1; reloaded=yes; fi".into(),
        r#"      if systemctl is-active "$u" >/dev/null 2>&1; then systemctl reload-or-restart "$u" || return 1; reloaded=yes; fi"#.into(),
        "    ;;".into(),
        "    openrc)".into(),
        "      if rc-service sshd status >/dev/null 2>&1; then rc-service sshd reload || rc-service sshd restart || return 1; reloaded=yes; fi".into(),
        "    ;;".into(),
        "    sysv)".into(),
        "      if service ssh status >/dev/null 2>&1; then service ssh reload || return 1; reloaded=yes;".into(),
        "      elif service sshd status >/dev/null 2>&1; then service sshd reload || return 1; reloaded=yes; fi".into(),
        "    ;;".into(),
        "  esac".into(),
        "  return 0".into(),
        "}".into(),
        "if ! reload_sshd; then".into(),
        "  restore".into(),
        "  reload_sshd".into(),
        "  echo 'sshd could not reload the new configuration, so the old one was put back.' >&2".into(),
        format!("  exit {EXIT_RELOAD_FAILED}"),
        "fi".into(),
        r#"echo "reloaded=$reloaded""#.into(),
        sh!(r#"printf '%s\n' "$effective" | grep -iE {}"#, format!("^({}) ", names.to_lowercase()))?,
        "exit 0".into(),
    ]);
    Ok(lines(&out))
}

/// Every script with sample arguments, for the tests that check them all. In the order of the TypeScript version.
pub fn sample_scripts() -> Vec<(&'static str, String)> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let settings = SshdSettings { permit_root_login: Some("no".into()), password_authentication: Some(false), pubkey_authentication: Some(true), port: Some(2222) };
    let all = || -> Result<Vec<(&'static str, String)>> {
        Ok(vec![
            ("fileStat", file_stat_script("/etc/hostname")?),
            ("readFile", read_file_script("/etc/hostname", None)?),
            ("readFilePartial", read_file_script("/etc/hostname", Some(100))?),
            ("listDir", list_dir_script("/etc")?),
            ("deleteFile", delete_file_script("/tmp/x", false)?),
            ("deleteFileMissingOk", delete_file_script("/tmp/x", true)?),
            ("writeFile", write_file_script("/tmp/x", &WriteFileOptions { mode: Some("0640".into()), owner: Some("root:root".into()), backup: true, create_parents: true })?),
            ("writeFilePlain", write_file_script("/tmp/x", &WriteFileOptions::default())?),
            ("lxcInfo", lxc_info_script()),
            ("processes", processes_script()),
            ("ports", ports_script()),
            ("diskUsage", disk_usage_script(Some("/var"))?),
            ("logs", logs_script(&LogsOptions { lines: 50, unit: None, since: None })?),
            ("logsUnit", logs_script(&LogsOptions { lines: 50, unit: Some("nginx".into()), since: Some("-1h".into()) })?),
            ("serviceStatus", service_status_script(Some("nginx"))?),
            ("serviceStatusAll", service_status_script(None)?),
            ("service", service_script("restart", "nginx")?),
            ("serviceEnable", service_script("enable", "nginx")?),
            ("serviceDisable", service_script("disable", "nginx")?),
            ("install", install_packages_script(&s(&["curl", "g++"]), true)?),
            ("installNoRefresh", install_packages_script(&s(&["curl"]), false)?),
            ("remove", remove_packages_script(&s(&["curl"]), false)?),
            ("purge", remove_packages_script(&s(&["curl"]), true)?),
            ("update", update_packages_script(false)),
            ("updateFull", update_packages_script(true)),
            ("listPackages", list_packages_script()),
            (
                "createUser",
                create_user_script(
                    "alice",
                    &CreateUserOptions { uid: Some(1500), shell: Some("/bin/sh".into()), home: Some("/home/alice".into()), comment: Some("Alice".into()), groups: s(&["wheel", "adm"]), system: false },
                )?,
            ),
            ("createSystemUser", create_user_script("svc", &CreateUserOptions { system: true, ..Default::default() })?),
            ("deleteUser", delete_user_script("alice", true)?),
            ("sshStatus", ssh_status_script()),
            ("sshEnable", ssh_enable_script()),
            ("sshDisable", ssh_disable_script()),
            ("listKeys", list_keys_script("root")?),
            ("addKey", add_key_script("root", "ssh-ed25519 AAAA comment", "AAAA")?),
            ("removeKey", remove_key_script("root", "AAAA")?),
            ("sshConfigure", ssh_configure_script(&settings)?),
            ("sshConfigureNoPort", ssh_configure_script(&SshdSettings { permit_root_login: Some("prohibit-password".into()), ..Default::default() })?),
        ])
    };
    all().expect("sample arguments hold no NUL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// Dash already rejects most of it. These would slip through a parse, or are options dash does not check.
    const BASHISMS: &[(&str, &str)] = &[
        ("[[ ]]", r"\[\[ "),
        ("function keyword", r"\bfunction\s+\w+"),
        ("here string", r"<<<"),
        ("ANSI-C quoting", r"(?m)(?:^|\s)\$'"),
        ("process substitution", r"[<>]\("),
        ("&> redirect", r"&>"),
        ("pipefail", r"pipefail"),
        ("source", r"(?m)^\s*source\s"),
        ("echo with options", r"\becho -[neE]\b"),
        ("local", r"(?m)^\s*local\s"),
        ("arrays", r"\$\{\w+\["),
        ("pattern substitution", r"\$\{\w+//"),
        ("== in test", r"\[ [^\]]*== "),
        ("hard-coded bash", r"\bbash\b"),
    ];

    #[test]
    fn ssh_scripts_have_no_bash_syntax() {
        for (name, script) in sample_scripts() {
            for (what, pattern) in BASHISMS {
                assert!(!Regex::new(pattern).unwrap().is_match(&script), "{name}: {what}");
            }
        }
    }

    #[test]
    fn ssh_pct_exec_syntax() {
        // The way the man page has it: vmid, then -- and the command.
        assert_eq!(pct_exec(100, "id").unwrap(), "pct exec '100' -- sh -c 'id'");
        // Exactly one level of quoting around the script.
        assert_eq!(pct_exec(100, "cat 'a b'").unwrap(), r"pct exec '100' -- sh -c 'cat '\''a b'\'''");
    }

    #[test]
    fn ssh_scripts_refuse_nul() {
        assert!(file_stat_script("/a\0b").is_err());
        assert!(delete_file_script("/a\0b", true).is_err());
        assert!(pct_exec(1, "a\0b").is_err());
    }

    /// Parses every script, plain and carried by pct exec, when a POSIX sh is at hand.
    #[test]
    fn ssh_scripts_parse_in_sh() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let shell = ["dash", "sh"].into_iter().find(|s| Command::new(s).arg("-c").arg("exit 0").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|st| st.success()).unwrap_or(false));
        let Some(shell) = shell else { return };
        for (name, script) in sample_scripts() {
            for text in [script.clone(), pct_exec(101, &script).unwrap()] {
                let mut child = Command::new(shell).arg("-n").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
                child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
                let out = child.wait_with_output().unwrap();
                assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
    }

    /// Byte for byte what the TypeScript version printed: reference/scripts.samples.json is
    /// JSON.stringify(sampleScripts()) of its dist/ssh/scripts.js.
    #[test]
    fn ssh_scripts_match_typescript_dump() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/reference/scripts.samples.json");
        let text = std::fs::read_to_string(path).expect("reference/scripts.samples.json");
        let reference: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text).unwrap();
        let ours = sample_scripts();
        assert_eq!(reference.len(), ours.len());
        for (name, script) in ours {
            assert_eq!(reference.get(name).and_then(|v| v.as_str()), Some(script.as_str()), "{name}");
        }
    }
}
