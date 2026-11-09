//! Files on the machine running this server are only reachable under PROXMOX_LOCAL_DIR.

use crate::errors::{PveError, Result, kind};
use regex::Regex;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

fn refuse(message: String, hint: Option<&str>) -> PveError {
    let e = PveError::new(kind::LOCAL_PATH_REFUSED, message);
    match hint {
        Some(h) => e.hint(h),
        None => e,
    }
}

static DEVICE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(?:con|conin\$|conout\$|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?$").unwrap());
static DRIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z]:").unwrap());

/// What Windows reads differently from what a path check sees: a device name opens the device
/// wherever it is, "file:stream" is a hidden stream of another file, and trailing dots and spaces
/// are dropped, so that "a.txt." is a.txt.
fn assert_plain_windows_path(path: &str, display: &str) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    let without_drive = DRIVE.replace(path, "");
    for part in without_drive.split(['\\', '/']).filter(|p| !p.is_empty()) {
        if DEVICE_NAME.is_match(part) || part.contains(':') || (part != "." && part != ".." && (part.ends_with('.') || part.ends_with(' '))) {
            return Err(refuse(format!("The local path {display} holds a name that Windows treats specially (\"{part}\")."), None));
        }
    }
    Ok(())
}

/// realpath, without the \\?\ prefix Windows adds: Node shows plain paths.
fn realpath(path: &Path) -> std::io::Result<PathBuf> {
    let real = std::fs::canonicalize(path)?;
    #[cfg(windows)]
    {
        let text = real.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{rest}")));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(real)
}

/// path.resolve: absolute, with . and .. folded, without touching the disk.
fn resolve(base: &Path, path: &str) -> PathBuf {
    let joined = if Path::new(path).is_absolute() { PathBuf::from(path) } else { base.join(drive_relative(base, path).unwrap_or_else(|| PathBuf::from(path))) };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// "C:relative.txt" is relative to the current directory of drive C. As path.resolve does, it is
/// relative to the base when that is on the same drive, and to the root of its drive otherwise.
/// Rust would replace the base with it and read it against the process's own current directory.
fn drive_relative(base: &Path, path: &str) -> Option<PathBuf> {
    if !cfg!(windows) || !DRIVE.is_match(path) || path[2..].starts_with(['\\', '/']) {
        return None;
    }
    let (drive, rest) = path.split_at(2);
    let base_drive = base.to_string_lossy().chars().take(2).collect::<String>();
    Some(if base_drive.eq_ignore_ascii_case(drive) { PathBuf::from(rest) } else { PathBuf::from(format!("{drive}\\{rest}")) })
}

fn io_code(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "ENOENT".into(),
        std::io::ErrorKind::PermissionDenied => "EACCES".into(),
        std::io::ErrorKind::NotADirectory => "ENOTDIR".into(),
        _ => e.to_string(),
    }
}

/// Files on the machine running this server are only reachable under PROXMOX_LOCAL_DIR, and an
/// agent must not be able to leave it. Links are resolved first: a symlink inside the
/// directory pointing at ~/.ssh is outside. For a file about to be written, the parent counts.
pub fn resolve_local_path(local_dir: Option<&str>, path: &str, must_exist: bool) -> Result<String> {
    let Some(local_dir) = local_dir else {
        return Err(refuse("Local file transfers are off on this server.".into(), Some("Do not retry. The operator can set PROXMOX_LOCAL_DIR to a directory reserved for transfers.")));
    };
    if path.is_empty() || path.contains('\0') {
        return Err(refuse("The local path is empty or holds a NUL character.".into(), None));
    }
    assert_plain_windows_path(path, path)?;
    let root = realpath(Path::new(local_dir)).map_err(|e| refuse(format!("PROXMOX_LOCAL_DIR ({local_dir}) cannot be read: {e}"), None))?;
    let candidate = resolve(&root, path);
    let cannot_read = |e: std::io::Error| refuse(format!("The local path {path} cannot be read: {}.", io_code(&e)), Some(&format!("Paths are relative to PROXMOX_LOCAL_DIR ({local_dir}).")));
    let mut real = if must_exist {
        realpath(&candidate).map_err(cannot_read)?
    } else {
        let parent = candidate.parent().unwrap_or(Path::new("/"));
        let name = candidate.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        realpath(parent).map_err(cannot_read)?.join(name)
    };
    if !must_exist {
        // The target itself may be an existing link pointing elsewhere.
        match realpath(&real) {
            Ok(r) => real = r,
            Err(_) => {
                // Not there yet, or a link to something not there yet: writing through that one would land outside.
                let dangling = std::fs::symlink_metadata(&real).map(|m| m.file_type().is_symlink()).unwrap_or(false);
                if dangling {
                    return Err(refuse(format!("The local path {path} is a link to a file that does not exist."), Some("Do not retry with another route to the same file.")));
                }
            }
        }
    }
    let inside = real.strip_prefix(&root).ok().filter(|rel| !rel.as_os_str().is_empty());
    let inside = if cfg!(windows) && inside.is_none() {
        // Case does not count on Windows.
        let (r, root_text) = (real.to_string_lossy().to_lowercase(), root.to_string_lossy().to_lowercase());
        let root_text = root_text.trim_end_matches(['\\', '/']).to_string();
        r.strip_prefix(&root_text).is_some_and(|rest| rest.len() > 1 && (rest.starts_with('\\') || rest.starts_with('/')))
    } else {
        inside.is_some()
    };
    if !inside {
        return Err(refuse(format!("The local path {path} is outside PROXMOX_LOCAL_DIR."), Some("Do not retry with another route to the same file. Move the file there, or ask the operator.")));
    }
    Ok(real.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    //! Ported from the unit parts of test/config.test.ts and test/ssh-localpath.test.ts. The
    //! transfers through the tools stay in test/ssh-localpath.test.ts, against the binary.

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> TempDir {
            let dir = std::env::temp_dir().join(format!("pvemcp-localpath-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(realpath(&dir).unwrap())
        }
        fn s(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
        fn join(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A directory link that needs no privilege on Windows (a junction), a plain symlink elsewhere.
    fn link_dir(target: &Path, link: &Path) {
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).stdout(std::process::Stdio::null()).status().unwrap();
            assert!(status.success(), "mklink /J failed");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    fn message(r: Result<String>) -> String {
        match r {
            Ok(p) => panic!("expected a refusal, got {p}"),
            Err(e) => {
                assert_eq!(e.kind, "local_path_refused", "{}", e.message);
                e.message
            }
        }
    }

    fn lower(p: impl AsRef<Path>) -> String {
        p.as_ref().to_string_lossy().to_lowercase()
    }

    #[test]
    fn refuses_everything_without_a_directory() {
        assert!(message(resolve_local_path(None, "x", false)).contains("off on this server"));
    }

    #[test]
    fn accepts_what_is_inside_and_refuses_what_is_outside() {
        let dir = TempDir::new();
        let root = dir.join("transfers");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub").join("a.txt"), "a").unwrap();
        std::fs::write(dir.join("outside.txt"), "b").unwrap();
        let r = root.to_string_lossy().into_owned();
        let ok = |p: &str, must: bool| resolve_local_path(Some(&r), p, must).unwrap_or_else(|e| panic!("{p}: {}", e.message));
        assert!(ok("sub/a.txt", true).ends_with("a.txt"));
        assert!(ok(&root.join("sub").join("a.txt").to_string_lossy(), true).ends_with("a.txt"));
        assert!(ok("sub/new.txt", false).ends_with("new.txt"));
        for p in ["../outside.txt".to_string(), dir.join("outside.txt").to_string_lossy().into_owned(), "sub/../../outside.txt".to_string()] {
            message(resolve_local_path(Some(&r), &p, true));
        }
        assert!(message(resolve_local_path(Some(&r), ".", true)).contains("outside"));
        assert!(message(resolve_local_path(Some(&r), "missing.txt", true)).contains("cannot be read"));
        assert!(message(resolve_local_path(Some(&r), "no/such/dir/x", false)).contains("cannot be read"));
        assert!(message(resolve_local_path(Some(&r), "a\0b", false)).contains("NUL"));
    }

    #[test]
    fn follows_links_before_deciding() {
        let dir = TempDir::new();
        let root = dir.join("transfers");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.join("outside.txt"), "b").unwrap();
        link_dir(&dir.0, &root.join("link"));
        let r = root.to_string_lossy().into_owned();
        assert!(message(resolve_local_path(Some(&r), "link/outside.txt", true)).contains("outside"));
        assert!(message(resolve_local_path(Some(&r), "link/new.txt", false)).contains("outside"));
    }

    #[test]
    fn refuses_empty_nul_and_the_directory_itself() {
        let dir = TempDir::new();
        let d = dir.s();
        for p in ["", "a\0b", ".", d.as_str()] {
            message(resolve_local_path(Some(&d), p, false));
        }
    }

    #[test]
    fn refuses_a_directory_setting_that_does_not_exist() {
        let dir = TempDir::new();
        let gone = dir.join("gone").to_string_lossy().into_owned();
        assert!(message(resolve_local_path(Some(&gone), "a", false)).contains("cannot be read"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_refuses_another_drive_and_a_path_relative_to_another_current_directory() {
        let dir = TempDir::new();
        let d = dir.s();
        let drive = d.chars().next().unwrap().to_ascii_uppercase();
        let other = if drive == 'Z' { 'Y' } else { 'Z' };
        message(resolve_local_path(Some(&d), &format!("{other}:\\Windows\\win.ini"), false));
        message(resolve_local_path(Some(&d), &format!("{other}:relative.txt"), false));
        // With the drive of the directory, Node resolves it against the directory: it stays inside.
        let got = resolve_local_path(Some(&d), &format!("{drive}:relative.txt"), false).unwrap();
        assert_eq!(lower(got), lower(dir.join("relative.txt")));
        message(resolve_local_path(Some(&d), "\\Windows\\win.ini", false));
    }

    #[cfg(windows)]
    #[test]
    fn windows_refuses_unc_and_device_paths() {
        let dir = TempDir::new();
        let d = dir.s();
        for p in ["\\\\server\\share\\x", "\\\\?\\C:\\Windows\\win.ini", "\\\\.\\PhysicalDrive0", "//server/share/x"] {
            assert!(resolve_local_path(Some(&d), p, false).is_err(), "{p}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_takes_another_case_of_the_directory_for_the_same_directory() {
        let dir = TempDir::new();
        let d = dir.s();
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        let expected = lower(dir.join("a.txt"));
        let upper = d.to_uppercase();
        let low = d.to_lowercase();
        assert_eq!(lower(resolve_local_path(Some(&d), &format!("{upper}\\a.txt"), true).unwrap()), expected);
        assert_eq!(lower(resolve_local_path(Some(&d), &format!("{low}\\a.txt"), true).unwrap()), expected);
        assert_eq!(lower(resolve_local_path(Some(&upper), &format!("{d}\\a.txt"), true).unwrap()), expected);
        assert_eq!(lower(resolve_local_path(Some(&d), &format!("{upper}\\new.txt"), false).unwrap()), lower(dir.join("new.txt")));
    }

    #[cfg(windows)]
    #[test]
    fn windows_is_not_fooled_by_case_when_leaving_the_directory() {
        let parent = TempDir::new();
        let dir = parent.join("inner");
        let sibling = parent.join("INNER-other");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let d = dir.to_string_lossy().into_owned();
        assert!(resolve_local_path(Some(&d), &sibling.join("a.txt").to_string_lossy(), false).is_err());
        assert!(resolve_local_path(Some(&d), &format!("{}\\a.txt", parent.s().to_uppercase()), false).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_takes_forward_slashes_for_separators() {
        let dir = TempDir::new();
        let d = dir.s();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        assert_eq!(resolve_local_path(Some(&d), "a/b.txt", false).unwrap(), dir.join("a").join("b.txt").to_string_lossy());
        assert!(resolve_local_path(Some(&d), "a/../../b.txt", false).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_refuses_device_names_and_names_it_would_not_take_literally() {
        let dir = TempDir::new();
        let d = dir.s();
        for name in ["CON", "con.txt", "NUL", "nul.tar.gz", "COM1", "LPT9.log", "PRN", "AUX", "a\\NUL", "CONIN$", "CONOUT$", "COM¹"] {
            assert!(resolve_local_path(Some(&d), name, false).is_err(), "{name}");
        }
        for name in ["a.txt:hidden", "a.txt::$DATA", "a.txt.", "a.txt ", "dir.\\a.txt", "dir \\a.txt"] {
            assert!(resolve_local_path(Some(&d), name, false).is_err(), "{name:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_does_not_refuse_names_that_only_look_like_those() {
        let dir = TempDir::new();
        let d = dir.s();
        for name in ["console.txt", "nullable", "com10", "a.b.c", "with space.txt", "é.txt", "conin"] {
            assert_eq!(resolve_local_path(Some(&d), name, false).unwrap_or_else(|e| panic!("{name}: {}", e.message)), dir.join(name).to_string_lossy(), "{name}");
        }
    }
}
