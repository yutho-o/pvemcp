//! The gates of ScopedSsh at the chokepoint, over a recording stand-in for the transport: the real
//! one has its own tests, and the tools are tested through the binary (test/ssh-*.test.ts).

use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Recording {
    commands: Mutex<Vec<ShellCommand>>,
    shells: Mutex<Vec<ShellOptions>>,
    sftp_calls: Arc<Mutex<Vec<String>>>,
}

struct RecordingSftp(Arc<Mutex<Vec<String>>>);

impl RecordingSftp {
    fn note(&self, what: String) -> BoxFuture<'static, Result<()>> {
        self.0.lock().unwrap().push(what);
        futures::future::ready(Ok(())).boxed()
    }
}

impl SftpSession for RecordingSftp {
    fn read_file<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        futures::future::ready(Ok(b"content".to_vec())).boxed()
    }
    fn write_file<'a>(&'a self, path: &'a str, _: Vec<u8>, _: Option<u32>) -> BoxFuture<'a, Result<()>> {
        self.note(format!("writeFile {path}"))
    }
    fn fast_put<'a>(&'a self, _: &'a str, remote: &'a str, _: Option<u32>, _: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.note(format!("fastPut {remote}"))
    }
    fn fast_get<'a>(&'a self, remote: &'a str, _: &'a str, _: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.note(format!("fastGet {remote}"))
    }
    fn stat<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<SftpStat>> {
        futures::future::ready(Ok(SftpStat { size: 1, mode: 0o644, mtime: 0, is_directory: false, is_file: true })).boxed()
    }
    fn readdir<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>>> {
        futures::future::ready(Ok(Vec::new())).boxed()
    }
    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<()>> {
        self.note(format!("unlink {path}"))
    }
    fn rename<'a>(&'a self, from: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
        self.note(format!("rename {from}"))
    }
    fn chmod<'a>(&'a self, path: &'a str, _: u32) -> BoxFuture<'a, Result<()>> {
        self.note(format!("chmod {path}"))
    }
    fn close(&self) {}
}

impl SshTransport for Recording {
    fn exec<'a>(&'a self, _: &'a SshTarget, command: &'a ShellCommand, _: ExecOptions) -> BoxFuture<'a, Result<ExecResult>> {
        self.commands.lock().unwrap().push(command.clone());
        // A control character, as a hostile host would send: ScopedSsh scrubs it.
        futures::future::ready(Ok(ExecResult { stdout: "ran\u{7}".into(), exit_code: Some(0), duration_ms: 1, ..Default::default() })).boxed()
    }
    fn sftp<'a>(&'a self, _: &'a SshTarget) -> BoxFuture<'a, Result<Arc<dyn SftpSession>>> {
        let session: Arc<dyn SftpSession> = Arc::new(RecordingSftp(self.sftp_calls.clone()));
        futures::future::ready(Ok(session)).boxed()
    }
    fn shell<'a>(&'a self, _: &'a SshTarget, opts: ShellOptions) -> BoxFuture<'a, Result<ShellChannel>> {
        self.shells.lock().unwrap().push(opts);
        let (input, _) = mpsc::unbounded_channel();
        let (_, events) = mpsc::unbounded_channel();
        futures::future::ready(Ok(ShellChannel { input, events })).boxed()
    }
    fn close(&self) -> BoxFuture<'_, ()> {
        futures::future::ready(()).boxed()
    }
}

struct Scoped {
    ssh: ScopedSsh,
    rec: Arc<Recording>,
    dry_run_log: DryRunLog,
    audited: Arc<Mutex<Vec<Map<String, Value>>>>,
    /// How many times the transport was asked for.
    factory_calls: Arc<AtomicUsize>,
}

fn scoped(env: &[(&str, &str)], read_only: bool, dry_run: bool) -> Scoped {
    let mut vars: crate::config::Env =
        [("PROXMOX_URL", "https://192.0.2.1"), ("PROXMOX_TOKEN", "a@pve!t=s"), ("PROXMOX_SSH_PASSWORD", "x")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    for (k, v) in env {
        vars.insert(k.to_string(), v.to_string());
    }
    let config = crate::config::load_config(&vars).unwrap();
    let instance = Arc::new(config.instances["default"].clone());
    let rec = Arc::new(Recording::default());
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let transport: TransportGetter = {
        let (rec, calls) = (rec.clone(), factory_calls.clone());
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            rec.clone() as Arc<dyn SshTransport>
        })
    };
    let dry_run_log: DryRunLog = Arc::new(Mutex::new(Vec::new()));
    let audited: Arc<Mutex<Vec<Map<String, Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let on_command: OnCommand = {
        let audited = audited.clone();
        Arc::new(move |e| audited.lock().unwrap().push(e))
    };
    let ssh = ScopedSsh::new(instance, transport, SshScope { read_only, dry_run, dry_run_log: dry_run_log.clone(), on_command: Some(on_command) });
    Scoped { ssh, rec, dry_run_log, audited, factory_calls }
}

fn kind_of<T>(r: Result<T>) -> &'static str {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => e.kind,
    }
}

fn pve1() -> SshTarget {
    SshTarget::node("pve1")
}

fn no_opts() -> ExecOptions {
    ExecOptions::default()
}

const SSH_ON: &[(&str, &str)] = &[("PROXMOX_ALLOW_SSH", "true")];
const SSH_WRITES: &[(&str, &str)] = &[("PROXMOX_ALLOW_SSH", "true"), ("PROXMOX_ALLOW_WRITES", "true")];

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[tokio::test]
async fn refuses_everything_when_ssh_is_off_without_touching_the_transport() {
    let s = scoped(&[("PROXMOX_ALLOW_WRITES", "true"), ("PROXMOX_ALLOW_ELEVATED", "true")], false, false);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::read("uptime"), no_opts()).await), kind::SSH_DISABLED);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::write("reboot"), no_opts()).await), kind::SSH_DISABLED);
    assert_eq!(kind_of(s.ssh.sftp(&pve1(), Access::Read).await), kind::SSH_DISABLED);
    assert_eq!(kind_of(s.ssh.shell(&pve1(), ShellOptions::default()).await), kind::SSH_DISABLED);
    assert_eq!(s.factory_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn runs_a_read_scrubs_its_output_and_logs_nothing_for_the_audit() {
    let s = scoped(SSH_ON, false, false);
    assert_eq!(s.ssh.run(&pve1(), &ShellCommand::read("uptime"), no_opts()).await.unwrap().stdout, "ran");
    let commands = s.rec.commands.lock().unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!((commands[0].text.as_str(), commands[0].access), ("uptime", Access::Read));
    assert!(s.audited.lock().unwrap().is_empty());
}

#[tokio::test]
async fn needs_writes_for_a_write() {
    let s = scoped(SSH_ON, false, false);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::write("reboot"), no_opts()).await), kind::WRITE_DISABLED);
    assert!(s.rec.commands.lock().unwrap().is_empty());
}

#[tokio::test]
async fn refuses_a_write_from_a_read_tool_with_every_gate_open() {
    let s = scoped(SSH_WRITES, true, false);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::write("reboot"), no_opts()).await), kind::NOT_READ_ONLY);
    assert_eq!(kind_of(s.ssh.shell(&pve1(), ShellOptions::default()).await), kind::NOT_READ_ONLY);
    assert_eq!(kind_of(s.ssh.sftp(&pve1(), Access::Write).await), kind::NOT_READ_ONLY);
    assert!(s.rec.commands.lock().unwrap().is_empty());
    assert_eq!(s.factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(s.ssh.run(&pve1(), &ShellCommand::read("uptime"), no_opts()).await.unwrap().stdout, "ran");
}

#[tokio::test]
async fn records_a_write_with_display_instead_of_the_text_and_only_a_digest_of_stdin() {
    let s = scoped(SSH_WRITES, false, false);
    let stdin = "root:hunter22";
    s.ssh.run(&pve1(), &ShellCommand::write("chpasswd --secret").stdin(stdin).display("chpasswd"), no_opts()).await.unwrap();
    assert_eq!(s.rec.commands.lock().unwrap()[0].stdin.as_deref(), Some(stdin.as_bytes()));
    let audited = Value::Array(s.audited.lock().unwrap().iter().cloned().map(Value::Object).collect());
    assert_eq!(
        audited,
        serde_json::json!([{ "status": "sent", "ssh": { "node": "pve1", "command": "chpasswd", "stdin": { "bytes": stdin.len(), "sha256": sha256(stdin.as_bytes()) } } }])
    );
    assert!(!audited.to_string().contains("hunter22"));
}

#[tokio::test]
async fn leaves_no_trace_of_a_sensitive_stdin() {
    let s = scoped(SSH_WRITES, false, false);
    s.ssh.run(&pve1(), &ShellCommand::write("chpasswd").stdin("root:hunter22").sensitive_stdin(), no_opts()).await.unwrap();
    assert_eq!(Value::Object(s.audited.lock().unwrap()[0].clone()), serde_json::json!({ "status": "sent", "ssh": { "node": "pve1", "command": "chpasswd" } }));
}

#[tokio::test]
async fn refuses_a_command_holding_nul() {
    let s = scoped(SSH_ON, false, false);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::read("a\0b"), no_opts()).await), kind::INVALID_INPUT);
    assert!(s.rec.commands.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_dry_run_logs_and_does_not_connect_even_without_writes() {
    let s = scoped(SSH_ON, false, true);
    let res = s.ssh.run(&pve1(), &ShellCommand::write("tee /etc/x").stdin("payload").display("write /etc/x"), no_opts()).await.unwrap();
    assert!(res.dry_run);
    assert_eq!((res.exit_code, res.stdout.as_str()), (Some(0), ""));
    assert_eq!(s.factory_calls.load(Ordering::SeqCst), 0);
    let log = Value::Array(s.dry_run_log.lock().unwrap().clone());
    assert_eq!(log, serde_json::json!([{ "ssh": { "node": "pve1", "command": "write /etc/x", "access": "write", "stdin": { "bytes": 7, "sha256": sha256(b"payload") } } }]));
    assert!(!log.to_string().contains("\"payload"));
}

#[tokio::test]
async fn a_dry_run_still_refuses_when_ssh_is_off() {
    let s = scoped(&[], false, true);
    assert_eq!(kind_of(s.ssh.run(&pve1(), &ShellCommand::write("reboot"), no_opts()).await), kind::SSH_DISABLED);
    assert!(s.dry_run_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_dry_run_logs_sftp_writes_refuses_sftp_reads_and_opens_no_session() {
    let s = scoped(SSH_ON, false, true);
    let sftp = s.ssh.sftp(&pve1(), Access::Write).await.unwrap();
    sftp.write_file("/tmp/x", b"secret-content".to_vec(), None).await.unwrap();
    sftp.unlink("/tmp/y").await.unwrap();
    assert_eq!(kind_of(sftp.read_file("/tmp/x").await), kind::INVALID_INPUT);
    assert_eq!(s.factory_calls.load(Ordering::SeqCst), 0);
    let log = s.dry_run_log.lock().unwrap().clone();
    assert_eq!(log.len(), 2);
    assert!(!Value::Array(log).to_string().contains("secret-content"));
}

#[tokio::test]
async fn a_dry_run_opens_no_interactive_session() {
    let s = scoped(SSH_ON, false, true);
    let opts = ShellOptions { command: Some("pct enter 100".into()), ..Default::default() };
    assert_eq!(kind_of(s.ssh.shell(&pve1(), opts).await), kind::INVALID_INPUT);
    assert!(s.rec.shells.lock().unwrap().is_empty());
    assert_eq!(s.dry_run_log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_read_session_reads_and_cannot_write() {
    let s = scoped(SSH_WRITES, false, false);
    let sftp = s.ssh.sftp(&pve1(), Access::Read).await.unwrap();
    assert_eq!(sftp.read_file("/etc/hostname").await.unwrap(), b"content");
    assert_eq!(kind_of(sftp.write_file("/tmp/x", b"y".to_vec(), None).await), kind::NOT_READ_ONLY);
    assert_eq!(kind_of(sftp.unlink("/tmp/x").await), kind::NOT_READ_ONLY);
    assert!(s.rec.sftp_calls.lock().unwrap().is_empty());
    assert!(s.audited.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_write_session_is_audited() {
    let s = scoped(SSH_WRITES, false, false);
    let sftp = s.ssh.sftp(&pve1(), Access::Write).await.unwrap();
    sftp.write_file("/tmp/x", b"y".to_vec(), None).await.unwrap();
    sftp.chmod("/tmp/x", 0o600).await.unwrap();
    assert_eq!(*s.rec.sftp_calls.lock().unwrap(), vec!["writeFile /tmp/x".to_string(), "chmod /tmp/x".to_string()]);
    let ssh: Vec<Value> = s.audited.lock().unwrap().iter().map(|a| a["ssh"].clone()).collect();
    assert_eq!(Value::Array(ssh), serde_json::json!([{ "node": "pve1", "sftp": "writeFile", "path": "/tmp/x" }, { "node": "pve1", "sftp": "chmod", "path": "/tmp/x" }]));
}

#[tokio::test]
async fn a_shell_needs_write_access_and_is_audited() {
    let closed = scoped(SSH_ON, false, false);
    assert_eq!(kind_of(closed.ssh.shell(&pve1(), ShellOptions::default()).await), kind::WRITE_DISABLED);
    let open = scoped(SSH_WRITES, false, false);
    open.ssh.shell(&pve1(), ShellOptions { command: Some("pct enter 100".into()), ..Default::default() }).await.unwrap();
    assert_eq!(open.rec.shells.lock().unwrap()[0].command.as_deref(), Some("pct enter 100"));
    assert_eq!(open.audited.lock().unwrap()[0]["ssh"], serde_json::json!({ "node": "pve1", "command": "pct enter 100", "pty": true }));
}
