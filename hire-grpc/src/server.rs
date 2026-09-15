use std::fs::File;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use crate::consumer_attest::AttestedStream;
use crate::service::WorkloadApiService;
use crate::workload::spiffe_workload_api_server::SpiffeWorkloadApiServer;

/// Bind and serve the SPIFFE Workload API on the given Unix socket path.
///
/// The socket is bound by [`bind_listener`], which also prepares its parent
/// directory and restricts the socket to this user.
pub async fn serve(socket_path: &Path, service: WorkloadApiService) -> Result<(), ServeError> {
    // `_lock` must stay alive for as long as this server serves: flock is
    // released when the file descriptor closes, so dropping it here would let a
    // second daemon take the socket. It is bound to a named variable rather
    // than `_` for that reason -- `_` would drop it immediately.
    let (listener, _lock) = bind_listener(socket_path)?;

    tracing::info!(?socket_path, "SPIFFE Workload API listening");

    // Attest at accept, so the consumer's identity is fixed before it sends a
    // byte and is hashed once per connection rather than once per RPC. tonic
    // requires `IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static`;
    // AttestedStream satisfies all five.
    use tokio_stream::StreamExt as _;
    let incoming = UnixListenerStream::new(listener).map(|conn| conn.map(AttestedStream::accept));
    Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

/// Binds the Workload API socket, private to this user.
///
/// The order matters. `prepare_socket_dir` runs first, because it is what
/// establishes that this user owns the directory; unlinking a stale socket
/// before that check would delete a file inside a directory we are about to
/// refuse to use.
///
/// Access is enforced by the parent directory, not by the socket's own mode.
/// `bind` creates the socket under the process umask, so there is a window
/// between `bind` and `set_permissions` in which its mode is whatever the umask
/// allowed. That window is not reachable: connecting to a Unix socket requires
/// search permission on every directory above it, and `prepare_socket_dir`
/// leaves the parent 0700 and owned by this user before the socket exists. The
/// 0600 mode is set anyway so the permissions read correctly and so the socket
/// does not depend on the directory alone. Narrowing the window with `umask`
/// was rejected: umask is per-process state shared by every thread, so a daemon
/// that sets and restores it around `bind` changes the mode of files other
/// tokio workers create at the same time.
fn bind_listener(socket_path: &Path) -> Result<(UnixListener, File), ServeError> {
    if let Some(parent) = socket_path.parent() {
        prepare_socket_dir(parent)?;
    }

    // Before the unlink below, not after: the lock is what says whether the
    // socket about to be removed belongs to a daemon that is still running.
    let lock = acquire_lock(socket_path)?;

    // Unlink unconditionally rather than testing `exists()` first: `exists()`
    // follows symlinks, so it reports false for a dangling symlink left at the
    // socket path, which `bind` would then fail on with EADDRINUSE.
    match std::fs::remove_file(socket_path) {
        Ok(()) => tracing::warn!(?socket_path, "removed stale socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ServeError::StaleSocket {
                path: socket_path.to_owned(),
                source,
            })
        }
    }

    let listener = UnixListener::bind(socket_path).map_err(|source| ServeError::Bind {
        path: socket_path.to_owned(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| ServeError::Permissions {
                path: socket_path.to_owned(),
                source,
            },
        )?;
    }

    Ok((listener, lock))
}

/// Path of the lock guarding one socket: the socket's own path plus `.lock`.
///
/// Keyed to the socket rather than to its directory because the invariant is
/// one daemon per socket path, and because several sockets can share a
/// directory -- the integration tests bind a dozen under `/tmp`, and a
/// directory-wide lock would make them refuse each other.
fn lock_path(socket_path: &Path) -> PathBuf {
    let mut p = socket_path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

/// Claims the right to serve on `socket_path`, or reports who already has it.
///
/// The socket file cannot answer "is the daemon that made this still alive?" --
/// a path left by a crash and a path held by a running daemon look identical,
/// which is why unlinking unconditionally could displace a live daemon. An
/// advisory lock answers exactly that question: the kernel drops a `flock` when
/// the process holding it dies, so a crashed daemon's lock is already free and
/// the ordinary stale-socket cleanup still works, while a live daemon's lock is
/// held and `LOCK_NB` reports `EWOULDBLOCK` instead of waiting.
///
/// The returned `File` is the lock. It is released when that handle closes, so
/// the caller must hold it for as long as it serves.
///
/// The lock file is never unlinked. Removing it would race: another process may
/// already have opened the same path, and would then lock a file that no longer
/// names anything. It is an empty file in the runtime directory and costs an
/// inode.
fn acquire_lock(socket_path: &Path) -> Result<File, ServeError> {
    let path = lock_path(socket_path);

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let lock = opts.open(&path).map_err(|source| ServeError::Lock {
        path: path.clone(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd as _;
        // SAFETY: flock takes an open file descriptor and a flag set, and has no
        // other preconditions. `lock` owns the descriptor and outlives the call.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.kind() {
                std::io::ErrorKind::WouldBlock => ServeError::AlreadyRunning {
                    path: socket_path.to_owned(),
                },
                _ => ServeError::Lock { path, source: e },
            });
        }
    }

    Ok(lock)
}

/// Creates the socket's parent directory owned by this user and readable only by them.
///
/// The fallback path is `/tmp/hire-{uid}`, and `/tmp` is world-writable, so another
/// local user can create that directory first. `create_dir_all` succeeds on a directory
/// that already exists no matter who owns it, and the sticky bit on `/tmp` protects
/// entries in `/tmp` rather than entries inside a subdirectory someone else owns. Binding
/// there would let that user unlink the socket and offer their own in its place, which
/// for a daemon that issues identity credentials means impersonating it. So refuse a
/// directory this user does not own, and tighten one that is too permissive.
#[cfg(unix)]
fn prepare_socket_dir(dir: &Path) -> Result<(), ServeError> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let wrap = |source| ServeError::SocketDir {
        path: dir.to_owned(),
        source,
    };

    match std::fs::metadata(dir) {
        Ok(md) => {
            if !md.is_dir() {
                return Err(ServeError::SocketDirNotADirectory {
                    path: dir.to_owned(),
                });
            }
            // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
            let uid = unsafe { libc::getuid() };
            let sticky = md.mode() & 0o1000 != 0;
            if md.uid() == uid {
                if md.mode() & 0o077 != 0 {
                    tracing::warn!(
                        ?dir,
                        mode = format!("{:o}", md.mode() & 0o777),
                        "tightening socket directory to 0700"
                    );
                    std::fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(wrap)?;
                }
            } else if !(md.uid() == 0 && sticky) {
                // A root-owned sticky directory such as /tmp is safe: the kernel lets
                // only the entry's owner remove it. Anything else owned by another user
                // is not, because the directory's owner can unlink whatever we bind.
                return Err(ServeError::SocketDirNotOurs {
                    path: dir.to_owned(),
                    owner: md.uid(),
                    expected: uid,
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(wrap)?;
        }
        Err(e) => return Err(wrap(e)),
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_socket_dir(dir: &Path) -> Result<(), ServeError> {
    std::fs::create_dir_all(dir).map_err(|source| ServeError::SocketDir {
        path: dir.to_owned(),
        source,
    })
}

/// Why the Workload API server could not start, or why it stopped.
///
/// Concrete rather than `Box<dyn std::error::Error>` so a caller can tell the
/// cases apart: refusing a directory another user owns calls for a different
/// response from a transport failure, and each filesystem variant names the
/// path it failed on as a field rather than only inside a message. The boxed
/// form was also neither `Send` nor `Sync`, so `hired` could do nothing with
/// it but flatten it to its `Display` text.
///
/// `Bind` does not today distinguish "another hired is running":
/// [`bind_listener`] unlinks any existing socket before binding, so it takes
/// the socket over rather than meeting `AddrInUse`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// Something that is not a directory sits where the socket's parent belongs.
    #[error("{path} exists and is not a directory")]
    SocketDirNotADirectory {
        /// The path that is occupied.
        path: PathBuf,
    },

    /// The socket's parent directory belongs to another user, who could unlink
    /// the socket and offer their own in its place.
    #[error("refusing to use {path}: owned by uid {owner}, expected {expected}")]
    SocketDirNotOurs {
        /// The directory that was refused.
        path: PathBuf,
        /// The uid that owns it.
        owner: u32,
        /// This process's uid.
        expected: u32,
    },

    /// The socket's parent directory could not be created or tightened.
    #[error("cannot prepare the socket directory {path}")]
    SocketDir {
        /// The directory being prepared.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// A stale socket was present and could not be removed.
    #[error("cannot remove the stale socket at {path}")]
    StaleSocket {
        /// The socket path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The socket could not be bound. `AddrInUse` means another daemon holds it.
    #[error("cannot bind the socket at {path}")]
    Bind {
        /// The socket path.
        path: PathBuf,
        /// The underlying error from `bind(2)`.
        #[source]
        source: std::io::Error,
    },

    /// The socket was bound but could not be restricted to this user.
    #[error("cannot restrict the socket at {path} to this user")]
    Permissions {
        /// The socket path.
        path: PathBuf,
        /// The underlying error from `chmod(2)`.
        #[source]
        source: std::io::Error,
    },

    /// Another daemon is already serving this socket and still running.
    #[error("another hired is already serving {path}")]
    AlreadyRunning {
        /// The socket the running daemon holds.
        path: PathBuf,
    },

    /// The lock guarding the socket could not be opened or taken.
    #[error("cannot lock {path}")]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The underlying error from `open(2)` or `flock(2)`.
        #[source]
        source: std::io::Error,
    },

    /// The gRPC server stopped with a transport error.
    #[error("the workload API server stopped")]
    Transport(#[from] tonic::transport::Error),
}

#[cfg(all(test, unix))]
mod tests {
    use super::{bind_listener, prepare_socket_dir, ServeError};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        // SAFETY: getpid() takes no arguments, has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        std::env::temp_dir().join(format!("hire-srvtest-{pid}-{name}"))
    }

    #[test]
    fn creates_a_missing_directory_private_to_this_user() {
        let dir = scratch("missing");
        let _ = fs::remove_dir_all(&dir);
        prepare_socket_dir(&dir).expect("should create the directory");
        let md = fs::metadata(&dir).expect("directory should exist");
        assert!(md.is_dir());
        assert_eq!(
            md.mode() & 0o777,
            0o700,
            "must not be group- or world-accessible"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tightens_a_directory_we_own_that_is_too_permissive() {
        let dir = scratch("loose");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        prepare_socket_dir(&dir).expect("should accept and tighten a directory we own");
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accepts_a_root_owned_sticky_directory() {
        // /tmp is root-owned and sticky, so the kernel lets only an entry's owner
        // remove it. The e2e test binds a socket directly there.
        let tmp = PathBuf::from("/tmp");
        let md = fs::metadata(&tmp).unwrap();
        assert_eq!(md.uid(), 0, "precondition: /tmp is root-owned");
        assert_ne!(md.mode() & 0o1000, 0, "precondition: /tmp is sticky");
        prepare_socket_dir(&tmp).expect("a root-owned sticky directory is safe");
    }

    #[test]
    fn refuses_a_directory_owned_by_another_user_without_the_sticky_bit() {
        // /usr is root-owned and not sticky. Binding under a directory another user
        // owns would let them unlink our socket and offer their own.
        let usr = PathBuf::from("/usr");
        let md = fs::metadata(&usr).unwrap();
        assert_eq!(md.uid(), 0, "precondition: /usr is root-owned");
        assert_eq!(md.mode() & 0o1000, 0, "precondition: /usr is not sticky");
        let err = prepare_socket_dir(&usr).expect_err("must refuse");
        assert!(err.to_string().contains("refusing to use"), "got: {err}");
    }

    #[tokio::test]
    async fn the_bound_socket_is_unreachable_by_other_users() {
        // Both halves matter and neither is sufficient alone: the 0700 directory
        // is what actually denies other uids, since connect(2) needs search
        // permission on it, and the 0600 socket is what the permissions read as.
        let dir = scratch("bound");
        let _ = fs::remove_dir_all(&dir);
        let sock = dir.join("workload.sock");

        let (listener, _lock) = bind_listener(&sock).expect("should bind");

        assert_eq!(
            fs::metadata(&dir).expect("directory should exist").mode() & 0o777,
            0o700,
            "another user must not be able to search into the socket directory"
        );
        assert_eq!(
            fs::symlink_metadata(&sock)
                .expect("socket should exist")
                .mode()
                & 0o777,
            0o600,
            "another user must not be able to connect to the socket"
        );

        drop(listener);
        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn binds_over_a_dangling_symlink_left_at_the_socket_path() {
        // Path::exists() follows symlinks, so it reports false here. Testing it
        // before unlinking left the symlink in place and bind(2) then failed with
        // EADDRINUSE, which reads as "the daemon is already running".
        let dir = scratch("dangling");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create dir");
        let sock = dir.join("workload.sock");
        std::os::unix::fs::symlink(dir.join("no-such-target"), &sock).expect("symlink");
        assert!(
            !sock.exists(),
            "precondition: a dangling symlink is not exists()"
        );

        let (listener, _lock) =
            bind_listener(&sock).expect("a dangling symlink must not block bind");
        assert!(
            !fs::symlink_metadata(&sock)
                .expect("socket should exist")
                .file_type()
                .is_symlink(),
            "the symlink should have been replaced by a real socket"
        );

        drop(listener);
        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn vets_the_directory_before_touching_anything_inside_it() {
        // Ordering, not just refusal. The socket's parent here is a regular
        // file, which prepare_socket_dir rejects by name. Unlinking first would
        // instead surface the kernel's ENOTDIR from remove_file, so the message
        // says which of the two ran. Pinning the order matters because the other
        // rejection prepare_socket_dir makes is "another user owns this
        // directory", and unlinking before that check deletes a file inside a
        // directory we are about to refuse to use.
        let parent = scratch("notdir");
        let _ = fs::remove_file(&parent);
        fs::write(&parent, b"not a directory").expect("create the blocking file");

        let err = bind_listener(&parent.join("workload.sock"))
            .expect_err("must refuse a parent that is not a directory");
        assert!(
            matches!(err, ServeError::SocketDirNotADirectory { ref path } if *path == parent),
            "the directory check must run first; got: {err:?}"
        );

        fs::remove_file(&parent).ok();
    }

    #[tokio::test]
    async fn a_directory_another_user_owns_is_refused_as_a_matchable_variant() {
        // The point of the concrete error type: a caller can tell this case
        // apart and read the offending path and uid as fields, rather than
        // parsing them back out of a message.
        // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
        let me = unsafe { libc::getuid() };
        let err = bind_listener(Path::new("/usr/hire-never-created.sock"))
            .expect_err("/usr is root-owned and not sticky");
        match err {
            ServeError::SocketDirNotOurs {
                path,
                owner,
                expected,
            } => {
                assert_eq!(path, PathBuf::from("/usr"));
                assert_eq!(owner, 0);
                assert_eq!(expected, me);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_second_daemon_is_refused_while_the_first_still_holds_the_socket() {
        // The case that used to be silent: the second daemon unlinked the
        // first's socket and bound its own, and since the two hold different
        // signing keys and different pseudonym material, every consumer
        // re-homed to new pseudonyms and a JWKS that no longer carried the kid
        // on its existing token.
        let dir = scratch("occupied");
        let _ = fs::remove_dir_all(&dir);
        let sock = dir.join("workload.sock");

        let first = bind_listener(&sock).expect("the first daemon binds");

        let err = bind_listener(&sock).expect_err("the second must be refused");
        assert!(
            matches!(err, ServeError::AlreadyRunning { ref path } if *path == sock),
            "got: {err:?}"
        );
        assert!(
            sock.exists(),
            "the refused daemon must not have unlinked the running one's socket"
        );

        drop(first);
        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn the_socket_is_reclaimed_once_the_first_daemon_is_gone() {
        // The other half: a crashed daemon leaves both a socket and a lock
        // file, and the kernel releases its flock when it dies. A daemon that
        // refused to reclaim that would be unable to restart after a crash.
        let dir = scratch("reclaim");
        let _ = fs::remove_dir_all(&dir);
        let sock = dir.join("workload.sock");

        let first = bind_listener(&sock).expect("the first daemon binds");
        drop(first); // what process death does to the lock and leaves the socket
        assert!(
            sock.exists(),
            "precondition: the socket file outlives the daemon"
        );

        let second = bind_listener(&sock).expect("a released lock must be reclaimable");
        drop(second);
        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn the_lock_covers_one_socket_and_not_its_directory() {
        // Several sockets share a directory -- the integration tests bind a
        // dozen under /tmp. A directory-wide lock would make them refuse each
        // other, so the lock is keyed to the socket path.
        let dir = scratch("siblings");
        let _ = fs::remove_dir_all(&dir);
        let a = dir.join("a.sock");
        let b = dir.join("b.sock");

        let first = bind_listener(&a).expect("first socket");
        let second = bind_listener(&b).expect("a different socket must not be blocked");

        drop(first);
        drop(second);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_error_crosses_a_task_boundary() {
        // Box<dyn Error> was neither Send nor Sync, which is why hired could
        // only stringify it. Asserted at compile time so it cannot regress.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<ServeError>();
    }
}
