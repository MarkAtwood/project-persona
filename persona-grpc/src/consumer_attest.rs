//! Consumer attestation: naming the process on the other end of the socket.
//!
//! Attestation runs once, when the connection is accepted, before the peer has
//! sent a byte, and the result rides with the connection as tonic's
//! `Connected::ConnectInfo`. tonic calls `connect_info()` exactly once per
//! accepted connection and clones it into every request's extensions, so a peer
//! cannot change what it is between the handshake and the request, and a large
//! executable is hashed once per connection rather than once per RPC.
//!
//! There is no unattested fallback. The only two available are both worse than
//! refusing: a pid-keyed identity changes on every launch of the consumer, so it
//! is not an identifier the consumer can correlate itself by; and a uid-keyed one
//! is identical for every process the user runs, so it is a stable global
//! correlator wearing a pseudonym's clothes. Refusing removes the choice instead
//! of making the wrong one.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use persona_core::ConsumerIdentity;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::unix::UCred;
use tokio::net::UnixStream;
use tonic::transport::server::Connected;

/// Names a connected peer from its Unix socket credentials.
///
/// ## Security
///
/// This buys unlinkability against honest-but-curious consumers, which is what
/// the README promises. It is not authentication against a local adversary: a
/// malicious same-uid process can exec the victim's binary or ptrace it, and
/// pids are reusable, so a peer can exec between `connect()` and the lookup
/// below. The window is narrowed by attesting at accept, not closed.
///
/// The peer's uid is checked against the daemon's own. That is defence in depth,
/// not the primary control: the socket is 0600 inside a 0700 directory
/// `prepare_socket_dir` verifies this user owns, so the kernel already refuses
/// other uids.
///
/// The consumer's identity is the SHA-256 of its main executable. That is the
/// only value obtainable on both Linux and macOS, with no new dependency, that
/// is uid-independent, stable across relaunches of the same application, and
/// different between different applications. uid is not an identity: every
/// application the user runs shares it.
pub fn attest_peer(cred: UCred) -> Result<ConsumerIdentity, AttestError> {
    // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
    let my_uid = unsafe { libc::getuid() };
    if cred.uid() != my_uid {
        return Err(AttestError::WrongUid {
            peer: cred.uid(),
            expected: my_uid,
        });
    }
    let pid = cred.pid().ok_or(AttestError::NoPeerPid)?;
    // ponytail: the consumer is its executable's content hash, so an application
    //   update rotates its pseudonym | ceiling: two applications shipping the same
    //   launcher binary are indistinguishable, and PRFAQ.md already concedes the
    //   update case | upgrade path: a signing identity — Flatpak app id from
    //   /proc/{pid}/environ on Linux, LOCAL_PEERTOKEN -> audit_token_t ->
    //   SecCodeCopyGuestWithAttributes on macOS — each of which yields a richer
    //   ConsumerIdentity variant and changes nothing above this function
    Ok(ConsumerIdentity::BinarySha256(hash_file(
        &exe_path_for_pid(pid)?,
    )?))
}

#[cfg(target_os = "linux")]
fn exe_path_for_pid(pid: libc::pid_t) -> Result<PathBuf, AttestError> {
    // A kernel magic link: it resolves to the inode the process is actually
    // running, even if that file has since been unlinked or replaced.
    std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| AttestError::NoExePath)
}

#[cfg(target_os = "macos")]
fn exe_path_for_pid(pid: libc::pid_t) -> Result<PathBuf, AttestError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    // ponytail: proc_pidpath hands back a path string, which we then reopen by
    //   name | ceiling: strictly weaker than Linux's magic link — the file at that
    //   path is substitutable between attesting and hashing | upgrade path:
    //   LOCAL_PEERTOKEN -> audit_token_t -> SecCodeCopyGuestWithAttributes, which
    //   asks the kernel about the running code rather than about a path
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buf is a live, writable allocation of exactly the length passed as
    // buffersize; proc_pidpath writes at most that many bytes and returns the
    // number written, or a non-positive value on failure.
    let n = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return Err(AttestError::NoExePath);
    }
    // Apple's documentation does not promise whether the returned length counts
    // the terminator, so trim at the first NUL rather than trusting it.
    let written = &buf[..n as usize];
    let end = written
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(written.len());
    if end == 0 {
        return Err(AttestError::NoExePath);
    }
    Ok(PathBuf::from(OsStr::from_bytes(&written[..end])))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exe_path_for_pid(_pid: libc::pid_t) -> Result<PathBuf, AttestError> {
    Err(AttestError::NotSupported)
}

fn hash_file(path: &Path) -> Result<[u8; 32], AttestError> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).map_err(|_| AttestError::Unreadable)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|_| AttestError::Unreadable)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The peer's uid is not the daemon's own.
    #[error("peer uid {peer} is not the daemon's uid {expected}")]
    WrongUid {
        /// The connecting process's uid.
        peer: u32,
        /// The daemon's own uid.
        expected: u32,
    },
    /// The kernel refused to report credentials for this connection.
    #[error("no peer credentials on this connection: {0}")]
    PeerCred(#[source] io::Error),
    /// Credentials arrived without a pid, so the peer cannot be located.
    #[error("the kernel did not report a peer pid")]
    NoPeerPid,
    /// The peer's executable path could not be resolved from its pid.
    #[error("cannot resolve the peer's executable path")]
    NoExePath,
    /// The peer's executable exists but could not be read and hashed.
    #[error("cannot read the peer's executable")]
    Unreadable,
    /// This platform has no supported way to name a socket peer.
    #[error("consumer attestation is not implemented on this platform")]
    NotSupported,
}

/// The attested consumer for a connection, or `None` if attestation failed.
///
/// `None` is not a weaker identity that can still be served; it is the absence
/// of one, and issuance refuses it. The specific reason is logged once at accept
/// rather than returned, so a caller the daemon could not identify is not told
/// how identification failed.
#[derive(Debug, Clone)]
pub struct PeerIdentity(Option<ConsumerIdentity>);

impl PeerIdentity {
    /// The attested consumer, if the peer was attested.
    pub fn get(&self) -> Option<&ConsumerIdentity> {
        self.0.as_ref()
    }
}

/// A `UnixStream` whose peer was attested when the connection was accepted.
#[derive(Debug)]
pub struct AttestedStream {
    inner: UnixStream,
    peer: PeerIdentity,
}

impl AttestedStream {
    /// Attest the peer of a freshly accepted connection.
    ///
    // ponytail: the peer's executable is hashed synchronously on the accept path
    //   | ceiling: one accept blocks a runtime worker for one SHA-256 over the
    //     consumer's binary — roughly 150ms for a 200 MB Electron main binary, and
    //     it serialises with the next accept | upgrade path: tokio_stream's
    //     StreamExt::then plus spawn_blocking in server::serve; `Then` is still a
    //     Stream, so the serve_with_incoming bound still holds and this signature
    //     does not change
    pub fn accept(inner: UnixStream) -> Self {
        let attested = match inner.peer_cred() {
            Ok(cred) => attest_peer(cred),
            Err(e) => Err(AttestError::PeerCred(e)),
        };
        let peer = match attested {
            Ok(id) => {
                tracing::debug!(event = "consumer_attested", consumer = %id.selector_key());
                PeerIdentity(Some(id))
            }
            Err(e) => {
                tracing::warn!(event = "consumer_unattested", reason = %e);
                PeerIdentity(None)
            }
        };
        Self { inner, peer }
    }
}

impl Connected for AttestedStream {
    type ConnectInfo = PeerIdentity;

    fn connect_info(&self) -> PeerIdentity {
        self.peer.clone()
    }
}

impl AsyncRead for AttestedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AttestedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // Omitting the vectored pair silently degrades HTTP/2 frame writes to one
    // syscall per buffer.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn attests_a_real_peer_as_the_hash_of_its_executable() {
        // The oracle is std's own current_exe() plus an independent hash of that
        // file, which is a different lookup path from the one under test
        // (peer pid -> /proc/{pid}/exe or proc_pidpath). It is a cross-path check,
        // not an externally sourced vector: both sides use sha2.
        let dir = std::env::temp_dir();
        // SAFETY: getpid() takes no arguments, has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        let path = dir.join(format!("persona-attest-test-{pid}.sock"));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");

        let connect = tokio::spawn({
            let path = path.clone();
            async move { UnixStream::connect(&path).await.expect("connect") }
        });
        let (server_side, _) = listener.accept().await.expect("accept");
        let _client = connect.await.expect("client task");

        let attested = attest_peer(server_side.peer_cred().expect("peer_cred"))
            .expect("a same-uid peer with a readable executable must attest");

        let expected = hash_file(&std::env::current_exe().expect("current_exe"))
            .expect("hash our own executable");
        assert_eq!(attested, ConsumerIdentity::BinarySha256(expected));

        let _ = std::fs::remove_file(&path);
    }
}
