//! Location of the SPIFFE Workload API socket, per platform.

use std::path::PathBuf;

/// Path to the `hired` SPIFFE Workload API socket for the current user.
///
/// Linux and the BSDs use `$XDG_RUNTIME_DIR/hire/workload.sock`. Under a systemd
/// user session that is `/run/user/{uid}/hire/workload.sock`, which is also what a
/// user unit's `%t` specifier resolves to. macOS uses the per-user
/// Darwin temp directory, which is what launchd exports as `$TMPDIR`. When neither is
/// available the path is `/tmp/hire-{uid}/workload.sock`.
///
/// Every caller in the workspace derives the path here, so the daemon and its clients
/// cannot disagree about where the socket is.
///
// ponytail: unix domain sockets only | ceiling: Windows needs a named pipe
//   (`\\.\pipe\hired\public\api`, SPIRE's convention), which this function
//   cannot express |
//   upgrade path: abstract the transport over UnixListener/UnixStream first, then
//   return a platform-tagged endpoint instead of a PathBuf
pub fn workload_socket_path() -> PathBuf {
    // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    socket_under(runtime_dir(), uid)
}

/// Assembles the socket path from a runtime directory, or from the uid when there is none.
fn socket_under(runtime_dir: Option<PathBuf>, uid: u32) -> PathBuf {
    match runtime_dir {
        Some(dir) => dir.join("hire").join("workload.sock"),
        // The uid is in the directory name because /tmp is shared and world-writable.
        None => PathBuf::from(format!("/tmp/hire-{uid}")).join("workload.sock"),
    }
}

/// Darwin's per-user temp confinement directory, `/var/folders/<..>/T/`, mode 0700.
///
/// Read from the system rather than from `$TMPDIR` so that a client with a scrubbed or
/// overridden environment still finds the daemon's socket.
///
/// Measured on macOS 26.6.2. `confstr` returned the same 49-byte directory whether
/// `$TMPDIR` was set normally, unset, or overridden to `/tmp`. Both `$TMPDIR` and
/// `std::env::temp_dir()` followed the override and reported `/tmp`, so either would
/// have sent a client looking in a different place from the daemon. The assembled
/// socket path is 70 bytes against the 104-byte `sun_path` limit; an inherited
/// `$TMPDIR` carries no such bound. A real `UnixListener::bind` at the derived path
/// succeeded on that machine.
#[cfg(target_os = "macos")]
fn runtime_dir() -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: buf is a valid writable buffer of exactly the length passed to confstr.
    let written = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    // confstr returns the byte length including the trailing NUL, or 0 on failure.
    if written == 0 || written > buf.len() {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&buf[..written - 1])))
}

/// The XDG Base Directory runtime directory, if the session has one.
///
/// An empty value counts as absent: the XDG specification treats unset and empty alike,
/// and taking `Some("")` here would yield the relative path `hire/workload.sock`,
/// which the daemon would bind under its working directory while clients looked for it
/// under the runtime directory.
#[cfg(not(target_os = "macos"))]
fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// Longest path a `sockaddr_un` can carry: `sizeof(sun_path)` minus the trailing NUL.
    const SUN_PATH_MAX: usize = if cfg!(target_os = "macos") { 103 } else { 107 };

    #[test]
    fn runtime_dir_gives_the_documented_systemd_path() {
        assert_eq!(
            socket_under(Some(PathBuf::from("/run/user/1000")), 1000),
            PathBuf::from("/run/user/1000/hire/workload.sock")
        );
    }

    #[test]
    fn runtime_dir_gives_the_documented_macos_path() {
        // confstr returns the directory with a trailing slash.
        assert_eq!(
            socket_under(Some(PathBuf::from("/var/folders/1s/8j5xq0000gn/T/")), 501),
            PathBuf::from("/var/folders/1s/8j5xq0000gn/T/hire/workload.sock")
        );
    }

    #[test]
    fn fallback_gives_the_documented_non_systemd_path() {
        assert_eq!(
            socket_under(None, 1000),
            PathBuf::from("/tmp/hire-1000/workload.sock")
        );
    }

    #[test]
    fn fallback_is_scoped_per_uid() {
        let mine = socket_under(None, 1000);
        assert_ne!(mine, socket_under(None, 1001));
        assert_ne!(mine.parent(), Some(Path::new("/tmp")));
    }

    #[test]
    fn host_path_is_absolute_and_named_for_the_workload_api() {
        let path = workload_socket_path();
        assert!(path.is_absolute(), "{} is not absolute", path.display());
        assert_eq!(path.file_name(), Some(OsStr::new("workload.sock")));
        assert_ne!(path.parent(), Some(Path::new("/tmp")));
    }

    #[test]
    fn host_path_fits_in_sun_path() {
        let path = workload_socket_path();
        let len = path.as_os_str().as_bytes().len();
        assert!(
            len <= SUN_PATH_MAX,
            "{} is {len} bytes, sun_path holds {SUN_PATH_MAX}",
            path.display()
        );
    }

    #[test]
    fn host_path_is_the_same_for_every_caller() {
        assert_eq!(workload_socket_path(), workload_socket_path());
    }
}
