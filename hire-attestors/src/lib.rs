//! Attestor plugin trait and identity source implementations.

pub mod claim;
pub mod did_key;
pub mod fido2;
pub mod goa;
pub mod gpg;
pub mod oidc;
pub mod piv;
pub mod ssh;
pub mod tailscale;
#[cfg(unix)]
pub mod unix;

pub use claim::{
    Candidate, ChallengeSignature, Claim, Evidence, HardwareTouch, PlatformIdentity,
    SelfAssertedDomain, VerifiedToken,
};
pub use did_key::DidKeyAttestor;
pub use fido2::Fido2Attestor;
pub use goa::GoaAttestor;
pub use gpg::GpgAttestor;
pub use oidc::OidcCachedAttestor;
pub use piv::PivAttestor;
pub use ssh::SshAgentAttestor;
pub use tailscale::TailscaleAttestor;
#[cfg(unix)]
pub use unix::UnixAttestor;

pub mod registry;
pub use registry::probe_sources;

use hire_core::PresenceLevel;
use std::fmt;

/// A signed cryptographic assertion produced by prove().
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SignedAssertion {
    /// Raw bytes of the signed assertion (format is attestor-specific).
    pub bytes: Vec<u8>,
    /// MIME type or format descriptor, e.g. "application/cbor+fido2".
    pub format: String,
}

impl SignedAssertion {
    /// Construct a new [`SignedAssertion`].
    pub fn new(bytes: Vec<u8>, format: impl Into<String>) -> Self {
        Self {
            bytes,
            format: format.into(),
        }
    }
}

/// Liveness/staleness result from freshness().
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessResult {
    /// The claim is fresh and the presence level is current.
    Fresh,
    /// The claim is stale; presence has decayed to the given level.
    Stale(PresenceLevel),
    /// The underlying source is no longer available (e.g. socket closed).
    Unavailable,
}

/// Error type for attestor operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestorError {
    #[error("source unavailable: {0}")]
    Unavailable(String),
    #[error("challenge failed: {0}")]
    ChallengeFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// The core attestor plugin trait.
///
/// Each identity source (Tailscale, FIDO2, SSH agent, etc.) implements this
/// trait. The daemon probes each source at startup and dispatches to whichever
/// are available on the current platform.
///
/// All methods are async. The trait is object-safe: callers use
/// `Box<dyn Attestor>` for dynamic dispatch.
#[async_trait::async_trait]
pub trait Attestor: Send + Sync + fmt::Debug {
    /// Returns the human-readable name of this attestor, e.g. "tailscale".
    fn name(&self) -> &str;

    /// Discovers candidate identities this source can see.
    ///
    /// Returns an empty `Vec` if none are visible (not an error). Discovery is
    /// not proof: a [`Candidate`] carries no assurance and no presence level.
    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError>;

    /// Produces evidence binding `candidate` to `challenge`.
    ///
    /// `challenge` is a freshly-generated nonce. The attestor proves the key
    /// material backing the candidate, and the tier follows from what it
    /// proved — see [`Claim::derive`].
    ///
    /// The default declines. An attestor that cannot verify anything cannot
    /// contribute an assurance level, and the daemon declines rather than
    /// issuing a credential nobody proved.
    ///
    /// ## Errors
    /// Returns [`AttestorError::ChallengeFailed`] if the user cancels, the
    /// hardware key is absent, or the attestor has no proof mechanism.
    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        let _ = (candidate, challenge);
        Err(AttestorError::ChallengeFailed(format!(
            "{} cannot produce evidence",
            self.name()
        )))
    }

    /// Checks liveness and staleness of the given candidate.
    ///
    /// Called periodically to detect when a hardware-presence assertion has
    /// expired or the underlying source has disconnected.
    async fn freshness(&self, candidate: &Candidate) -> Result<FreshnessResult, AttestorError> {
        let _ = candidate;
        Ok(FreshnessResult::Unavailable)
    }
}
