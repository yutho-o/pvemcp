//! SFTP over russh-sftp, behind the SftpSession of this crate: the timeout of each call, the
//! errors an agent can act on, and the slot of the connection given back on close.

use super::{DirEntry, SftpSession, SftpStat};
use crate::errors::{PveError, Result, kind};
use futures::FutureExt;
use futures::future::BoxFuture;
use russh_sftp::client::SftpSession as RawSftp;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type OnClose = Box<dyn FnOnce() + Send>;

/// The size of one piece of a local transfer.
const CHUNK: usize = 256 * 1024;

pub struct Sftp {
    raw: RawSftp,
    timeout_ms: u64,
    closed: AtomicBool,
    on_close: Mutex<Option<OnClose>>,
}

/// What went wrong, before it is put in words for an operation and a path.
enum Failure {
    Sftp(SftpError),
    Io(std::io::Error),
    /// A local file: its own message, already in words.
    Local(PveError),
}

impl From<SftpError> for Failure {
    fn from(e: SftpError) -> Self {
        Failure::Sftp(e)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        // An io::Error from a remote file may carry the SFTP error it came from.
        match e.get_ref().and_then(|inner| inner.downcast_ref::<SftpError>()) {
            Some(inner) => Failure::Sftp(inner.clone()),
            None => Failure::Io(e),
        }
    }
}

fn map_error(failure: Failure, operation: &str, path: &str) -> PveError {
    let message = match failure {
        Failure::Local(e) => return e,
        Failure::Sftp(SftpError::Status(status)) => match status.status_code {
            StatusCode::NoSuchFile => return PveError::new(kind::NOT_FOUND, format!("SFTP {operation}: {path} does not exist.")),
            StatusCode::PermissionDenied => {
                return PveError::new(kind::FORBIDDEN, format!("SFTP {operation}: permission denied on {path}.")).hint("SFTP runs as the SSH user, without sudo.");
            }
            code if status.error_message.is_empty() => code.to_string(),
            _ => status.error_message,
        },
        Failure::Sftp(e) => e.to_string(),
        Failure::Io(e) => e.to_string(),
    };
    PveError::new(kind::UPSTREAM_ERROR, format!("SFTP {operation} on {path} failed: {message}"))
}

/// The mode without the type of file, and the type read from it.
pub fn to_stat(attrs: &FileAttributes) -> SftpStat {
    let mode = attrs.permissions.unwrap_or(0);
    let kind = mode & 0o170000;
    SftpStat { size: attrs.size.unwrap_or(0), mode: mode & 0o7777, mtime: attrs.mtime.map(u64::from).unwrap_or(0), is_directory: kind == 0o040000, is_file: kind == 0o100000 }
}

fn mode_attrs(mode: u32) -> FileAttributes {
    FileAttributes { permissions: Some(mode), ..FileAttributes::empty() }
}

fn local_error(path: &str, e: std::io::Error) -> Failure {
    Failure::Local(PveError::new(kind::UPSTREAM_ERROR, format!("The local file {path} cannot be used: {e}.")))
}

impl Sftp {
    /// timeout_ms bounds each call that does not give its own; on_close runs once, on close.
    pub fn new(raw: RawSftp, timeout_ms: u64, on_close: OnClose) -> Self {
        // Each request has a limit of its own in russh-sftp, 10 seconds unless told otherwise:
        // never shorter than the limit of the whole call.
        raw.set_timeout(timeout_ms.div_ceil(1000).max(10));
        Sftp { raw, timeout_ms, closed: AtomicBool::new(false), on_close: Mutex::new(Some(on_close)) }
    }

    async fn call<T>(&self, operation: &str, path: &str, limit_ms: Option<u64>, run: impl Future<Output = std::result::Result<T, Failure>>) -> Result<T> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(PveError::new(kind::SSH_UNREACHABLE, format!("SFTP {operation} on {path}: the channel is closed.")));
        }
        let limit_ms = limit_ms.unwrap_or(self.timeout_ms);
        let timed_out = || {
            PveError::new(kind::SSH_TIMEOUT, format!("SFTP {operation} on {path} did not finish within {}s.", (limit_ms as f64 / 1000.0).round()))
                .hint("A partial file may be left behind. A longer timeout_seconds may be needed for a large file.")
        };
        match tokio::time::timeout(Duration::from_millis(limit_ms), run).await {
            Ok(Ok(value)) => Ok(value),
            // The limit of one request: the host stalled, and the session is no more use than at the limit of the call.
            Ok(Err(Failure::Sftp(SftpError::Timeout))) => {
                self.shut();
                Err(timed_out())
            }
            Ok(Err(failure)) => Err(map_error(failure, operation, path)),
            Err(_) => {
                self.shut();
                Err(timed_out())
            }
        }
    }

    fn shut(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Only drops the channel: nothing to wait for.
        let _ = self.raw.close().now_or_never();
        if let Some(on_close) = self.on_close.lock().unwrap().take() {
            on_close();
        }
    }

    async fn create(&self, path: &str, mode: Option<u32>) -> std::result::Result<russh_sftp::client::fs::File, Failure> {
        let attrs = mode.map(mode_attrs).unwrap_or_default();
        let file = self.raw.open_with_flags_and_attributes(path, OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE, attrs).await?;
        // The mode given at open goes through the umask of the host, and does nothing to a file
        // that was already there: set it before any content is written, by handle, else by path,
        // and go on if neither works, as ssh2 did.
        if let Some(mode) = mode
            && file.set_metadata(mode_attrs(mode)).await.is_err()
        {
            let _ = self.raw.set_metadata(path, mode_attrs(mode)).await;
        }
        Ok(file)
    }
}

impl Drop for Sftp {
    fn drop(&mut self) {
        self.shut();
    }
}

impl SftpSession for Sftp {
    fn read_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.call("read", path, None, async move { Ok(self.raw.read(path).await?) }).boxed()
    }

    fn write_file<'a>(&'a self, path: &'a str, data: Vec<u8>, mode: Option<u32>) -> BoxFuture<'a, Result<()>> {
        self.call("write", path, None, async move {
            let mut file = self.create(path, mode).await?;
            file.write_all(&data).await?;
            file.shutdown().await?;
            Ok(())
        })
        .boxed()
    }

    fn fast_put<'a>(&'a self, local_path: &'a str, remote_path: &'a str, mode: Option<u32>, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.call("upload", remote_path, timeout_ms, async move {
            let mut local = tokio::fs::File::open(local_path).await.map_err(|e| local_error(local_path, e))?;
            let mut remote = self.create(remote_path, mode).await?;
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let n = local.read(&mut buffer).await.map_err(|e| local_error(local_path, e))?;
                if n == 0 {
                    break;
                }
                remote.write_all(&buffer[..n]).await?;
            }
            remote.shutdown().await?;
            Ok(())
        })
        .boxed()
    }

    fn fast_get<'a>(&'a self, remote_path: &'a str, local_path: &'a str, timeout_ms: Option<u64>) -> BoxFuture<'a, Result<()>> {
        self.call("download", remote_path, timeout_ms, async move {
            let mut remote = self.raw.open(remote_path).await?;
            let mut local = tokio::fs::File::create(local_path).await.map_err(|e| local_error(local_path, e))?;
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let n = remote.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                local.write_all(&buffer[..n]).await.map_err(|e| local_error(local_path, e))?;
            }
            local.flush().await.map_err(|e| local_error(local_path, e))?;
            remote.shutdown().await?;
            Ok(())
        })
        .boxed()
    }

    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<SftpStat>> {
        self.call("stat", path, None, async move { Ok(to_stat(&self.raw.metadata(path).await?)) }).boxed()
    }

    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>>> {
        self.call("readdir", path, None, async move {
            // Without . and .., as ssh2 gave them.
            Ok(self.raw.read_dir(path).await?.map(|e| DirEntry { name: e.file_name(), stat: to_stat(&e.metadata()) }).collect())
        })
        .boxed()
    }

    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<()>> {
        self.call("unlink", path, None, async move { Ok(self.raw.remove_file(path).await?) }).boxed()
    }

    fn rename<'a>(&'a self, from: &'a str, to: &'a str) -> BoxFuture<'a, Result<()>> {
        self.call("rename", from, None, async move { Ok(self.raw.rename(from, to).await?) }).boxed()
    }

    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<()>> {
        self.call("chmod", path, None, async move { Ok(self.raw.set_metadata(path, mode_attrs(mode)).await?) }).boxed()
    }

    fn close(&self) {
        self.shut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats() {
        let attrs = FileAttributes { size: Some(12), permissions: Some(0o100644), mtime: Some(1700000000), ..FileAttributes::empty() };
        assert_eq!(to_stat(&attrs), SftpStat { size: 12, mode: 0o644, mtime: 1700000000, is_directory: false, is_file: true });
        let dir = to_stat(&FileAttributes { permissions: Some(0o41777), ..FileAttributes::empty() });
        assert_eq!((dir.mode, dir.is_directory, dir.is_file, dir.size, dir.mtime), (0o1777, true, false, 0, 0));
        assert_eq!(to_stat(&FileAttributes::empty()), SftpStat::default());
    }

    #[test]
    fn errors() {
        let status = |code| SftpError::Status(russh_sftp::protocol::Status { id: 1, status_code: code, error_message: "x".into(), language_tag: String::new() });
        let e = map_error(Failure::Sftp(status(StatusCode::NoSuchFile)), "stat", "/a");
        assert_eq!((e.kind, e.message.as_str()), (kind::NOT_FOUND, "SFTP stat: /a does not exist."));
        let e = map_error(Failure::Sftp(status(StatusCode::PermissionDenied)), "write", "/a");
        assert_eq!((e.kind, e.message.as_str(), e.hint.as_deref()), (kind::FORBIDDEN, "SFTP write: permission denied on /a.", Some("SFTP runs as the SSH user, without sudo.")));
        let e = map_error(Failure::Sftp(status(StatusCode::Failure)), "unlink", "/a");
        assert_eq!((e.kind, e.message.as_str()), (kind::UPSTREAM_ERROR, "SFTP unlink on /a failed: x"));
    }
}
