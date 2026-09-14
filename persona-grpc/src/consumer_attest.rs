use persona_core::ConsumerIdentity;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Attests a Unix socket peer and returns its ConsumerIdentity.
///
/// On Linux: uses SO_PEERCRED to get uid/pid, reads /proc/{pid}/exe for
/// binary path, computes SHA-256 hash of the binary.
///
/// Falls back to Unattested if /proc/{pid}/exe cannot be read (e.g.,
/// process exited before we could read it).
///
/// ## Security
/// uid is verified against the daemon's own uid. Connections from other
/// uids are rejected.
#[cfg(target_os = "linux")]
pub fn attest_peer(stream: &tokio::net::UnixStream) -> Result<ConsumerIdentity, AttestError> {
    let fd = stream.as_raw_fd();
    let ucred = get_peer_ucred(fd)?;

    let my_uid = unsafe { libc::getuid() };
    if ucred.uid != my_uid {
        return Err(AttestError::WrongUid {
            peer: ucred.uid,
            expected: my_uid,
        });
    }

    let pid = ucred.pid as u32;
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid));
    let identity = match exe_path {
        Ok(path) => match hash_file(&path) {
            Ok(hash) => ConsumerIdentity::BinarySha256(hash),
            Err(_) => ConsumerIdentity::Unattested {
                uid: ucred.uid,
                pid,
            },
        },
        Err(_) => ConsumerIdentity::Unattested {
            uid: ucred.uid,
            pid,
        },
    };

    // ponytail: binary hash only | upgrade to read Flatpak app ID from /proc/{pid}/environ when needed
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn get_peer_ucred(fd: std::os::unix::io::RawFd) -> Result<libc::ucred, AttestError> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut _,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(AttestError::Io(std::io::Error::last_os_error()));
    }
    Ok(ucred)
}

#[cfg(target_os = "linux")]
fn hash_file(path: &std::path::Path) -> Result<[u8; 32], std::io::Error> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    Ok(Sha256::digest(&data).into())
}

/// Attests a Unix socket peer and returns its ConsumerIdentity.
#[cfg(not(target_os = "linux"))]
pub fn attest_peer(_stream: &tokio::net::UnixStream) -> Result<ConsumerIdentity, AttestError> {
    Err(AttestError::NotSupported)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    #[error("wrong uid: peer {peer} != expected {expected}")]
    WrongUid { peer: u32, expected: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not supported on this platform")]
    NotSupported,
}
