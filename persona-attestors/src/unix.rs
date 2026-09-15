//! Unix account attestor — the operating system as an identity source.
//!
//! Every other attestor needs something extra to be running: an agent, a
//! daemon, a card, a cached token. This one needs only the kernel, so it is the
//! source that never degrades away. What it attests is correspondingly thin.
//! `getuid()` names the account a process runs under, which is a fact the
//! caller could have read for itself; what the daemon adds is provenance, a
//! pseudonym and audience binding, not authentication.

use std::ffi::CStr;
use std::mem::MaybeUninit;

use async_trait::async_trait;

use crate::claim::PlatformIdentity;
use crate::{Attestor, AttestorError, Candidate, Evidence, SelfAssertedDomain};

/// Largest passwd buffer worth trying before giving up, in bytes.
///
/// `getpwuid_r` may keep asking for more room, and a directory backend that
/// answers `ERANGE` forever would otherwise loop until the allocator refuses.
const MAX_PASSWD_BUF: usize = 1 << 20;

/// Attestor that names the local account this process runs under.
///
/// Always available, deliberately: there is no `is_available` here because a
/// check that can only return `true` is a lie shaped like a check.
///
/// The account is read once, at construction, and held: `enumerate` runs on
/// every `FetchJWTSVID`, and the passwd lookup it would otherwise perform can
/// traverse a networked directory backend. See [`UnixAttestor::new`].
#[derive(Debug)]
pub struct UnixAttestor {
    /// The account this process ran under when the attestor was built.
    uid: libc::uid_t,
    /// The passwd name for [`UnixAttestor::uid`], or `uid {n}` when the
    /// database names none and when the lookup itself failed.
    display_name: String,
}

impl UnixAttestor {
    /// Reads the account this process runs under, once.
    ///
    /// Blocking, deliberately. The name lookup traverses NSS on Linux and Open
    /// Directory on macOS, either of which can reach the network and block for
    /// seconds; personad builds this while probing sources at startup, so the
    /// cost lands there instead of on every request. Neither answer can change
    /// under a process that does not call `setuid`, and one that does is
    /// refused by [`Attestor::prove`], which re-reads the uid rather than
    /// trusting this one.
    ///
    /// A lookup that fails names the account by uid rather than propagating the
    /// error: a source whose whole claim is that it never degrades away must
    /// not degrade away because a directory server is unreachable.
    pub fn new() -> Self {
        let uid = current_uid();
        let display_name = match username_for(uid) {
            Ok(Some(name)) => name,
            Ok(None) => format!("uid {uid}"),
            Err(e) => {
                tracing::warn!(
                    event = "unix_passwd_lookup_failed",
                    uid = uid,
                    error = %e,
                    "passwd lookup failed; naming the account by uid"
                );
                format!("uid {uid}")
            }
        };
        Self { uid, display_name }
    }
}

impl Default for UnixAttestor {
    fn default() -> Self {
        Self::new()
    }
}

fn current_uid() -> libc::uid_t {
    // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The SPIFFE path for `uid`, written by `enumerate` and re-checked by `prove`.
///
/// One function because two callers must agree. The uid rather than the name:
/// the uid is what `getuid()` attests, and deriving the path from the passwd
/// entry instead would re-home every pseudonym the day an account is renamed.
fn spiffe_path(uid: libc::uid_t) -> String {
    format!("unix/{uid}")
}

/// The account name the passwd database maps `uid` to, or `None` when it maps
/// none.
///
/// A missing entry is an answer rather than a failure: a uid with no name is
/// what a container with no `/etc/passwd` looks like.
///
/// ## Errors
/// [`AttestorError::Io`] when the lookup itself fails, and
/// [`AttestorError::Unavailable`] when the entry will not fit in
/// [`MAX_PASSWD_BUF`].
fn username_for(uid: libc::uid_t) -> Result<Option<String>, AttestorError> {
    // SAFETY: sysconf() takes a single constant name, has no preconditions and
    // reports failure in its return value rather than by trapping.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut cap = if suggested > 0 {
        suggested as usize
    } else {
        1024
    };

    loop {
        let mut buf = vec![0u8; cap];
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut found: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: passwd is a live, writable allocation of one libc::passwd, and
        // buf is a live, writable allocation of exactly the length passed as
        // buflen. getpwuid_r writes the entry through the first pointer, its
        // strings into buf, and either that pointer or NULL into found; it
        // reports failure in its return value and never through errno.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut found,
            )
        };

        if rc == libc::ERANGE {
            cap = cap.saturating_mul(2);
            if cap > MAX_PASSWD_BUF {
                return Err(AttestorError::Unavailable(
                    "passwd entry larger than 1 MiB".into(),
                ));
            }
            continue;
        }
        // Success with a NULL entry is "no such user". Some C libraries report
        // that as ENOENT or ESRCH instead; it is the same answer.
        if rc == libc::ENOENT || rc == libc::ESRCH {
            return Ok(None);
        }
        if rc != 0 {
            return Err(AttestorError::Io(std::io::Error::from_raw_os_error(rc)));
        }
        if found.is_null() {
            return Ok(None);
        }

        // SAFETY: getpwuid_r returned 0 and a non-NULL entry, so it initialised
        // the passwd it was handed. pw_name points into buf, which outlives this
        // borrow, and is NUL-terminated because getpwuid_r wrote it as a C string.
        let name = unsafe { CStr::from_ptr(passwd.assume_init().pw_name) };
        return Ok(Some(name.to_string_lossy().into_owned()));
    }
}

#[async_trait]
impl Attestor for UnixAttestor {
    fn name(&self) -> &str {
        "unix"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        // Answered from what `new` read. Nothing here touches the passwd
        // database, so this path cannot block on a directory backend and cannot
        // fail.
        //
        // ponytail: the account lands in ssh.local | ceiling: a uid is not
        //   unique across machines, so two boxes issue the same SPIFFE ID for
        //   uid 1000 | upgrade path: a `unix.local` trust domain scoped by
        //   hostname, once persona-core grows the variant and personad seeds a
        //   bundle for it — until then an unseeded domain would fail the
        //   daemon's own ValidateJWTSVID.
        Ok(vec![Candidate::new(
            "unix",
            SelfAssertedDomain::SshLocal,
            spiffe_path(self.uid),
            self.display_name.clone(),
        )])
    }

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        // The challenge goes unused, and that is the honest shape rather than an
        // omission: the kernel answers the same question however it is asked, so
        // there is nothing a nonce could bind. Re-reading the uid is the
        // analogue of ssh's re-list — is this the account we run under *now*?
        let _ = challenge;
        let uid = current_uid();
        if candidate.path != spiffe_path(uid) {
            tracing::info!(
                event = "unix_account_mismatch",
                candidate = %candidate.path,
                "candidate does not name the account this process runs under"
            );
            return Err(AttestorError::ChallengeFailed(
                "candidate does not name the current account".into(),
            ));
        }
        Ok(vec![Evidence::PlatformAssertion(
            PlatformIdentity::observe(candidate.path.clone()),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `id -un` is the oracle. It is a separate binary reached through a
    /// separate code path from the FFI call under test, but both ultimately
    /// consult the same NSS or Open Directory backend, so this is a cross-path
    /// check and not an externally sourced vector. There is no external vector
    /// for what this machine's account is called; the fact is local by
    /// definition.
    #[test]
    fn the_resolved_name_matches_id() {
        let out = std::process::Command::new("id")
            .arg("-un")
            .output()
            .expect("id is a POSIX utility and must be present");
        assert!(out.status.success(), "id -un failed");
        let expected = String::from_utf8(out.stdout).unwrap().trim().to_owned();

        assert_eq!(username_for(current_uid()).unwrap(), Some(expected));
    }

    #[test]
    fn a_uid_with_no_passwd_entry_is_an_answer_not_an_error() {
        assert_eq!(username_for(4_000_000_000).unwrap(), None);
    }

    #[test]
    fn the_path_names_the_uid_not_the_account_name() {
        assert_eq!(spiffe_path(1000), "unix/1000");
    }
}
