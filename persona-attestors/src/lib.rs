//! Attestor plugin trait and identity source implementations.

pub mod did_key;
pub mod fido2;
pub mod goa;
pub mod gpg;
pub mod oidc;
pub mod piv;
pub mod ssh;
pub mod tailscale;

pub use did_key::DidKeyAttestor;
pub use fido2::Fido2Attestor;
pub use goa::GoaAttestor;
pub use gpg::GpgAttestor;
pub use oidc::OidcCachedAttestor;
pub use piv::PivAttestor;
pub use ssh::SshAgentAttestor;
pub use tailscale::TailscaleAttestor;

pub mod registry;
pub use registry::probe_sources;

use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId};
use std::fmt;

/// A single identity claim discovered by an attestor.
///
/// Carries the source name, assurance level, presence level, and enough
/// identity metadata for the daemon to construct a SPIFFE SVID.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Claim {
    /// Attestor source name, e.g. "tailscale", "fido2", "ssh-agent".
    pub source: String,
    /// Identity assurance level for this claim.
    pub assurance: IdentityAssurance,
    /// Current presence level for this claim.
    pub presence: PresenceLevel,
    /// The SPIFFE ID this claim corresponds to.
    pub spiffe_id: SpiffeId,
    /// Human-readable display name, e.g. "mark@example.com".
    pub display_name: String,
}

impl Claim {
    /// Construct a new [`Claim`].
    pub fn new(
        source: impl Into<String>,
        assurance: IdentityAssurance,
        presence: PresenceLevel,
        spiffe_id: SpiffeId,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            assurance,
            presence,
            spiffe_id,
            display_name: display_name.into(),
        }
    }
}

/// A signed cryptographic assertion produced by prove().
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SignedAssertion {
    /// Raw bytes of the signed assertion (format is attestor-specific).
    pub bytes: Vec<u8>,
    /// MIME type or format descriptor, e.g. "application/cbor+fido2".
    pub format: String,
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

    /// Discovers available identity claims from this source.
    ///
    /// Returns an empty Vec if no claims are currently available (not an error).
    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError>;

    /// Produces a signed cryptographic proof for the given claim and challenge.
    ///
    /// `challenge` is a freshly-generated nonce. The attestor signs it with
    /// the key material backing the claim.
    ///
    /// ## Errors
    /// Returns [`AttestorError::ChallengeFailed`] if the user cancels or the
    /// hardware key is not present.
    async fn prove(
        &self,
        claim: &Claim,
        challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError>;

    /// Checks liveness and staleness of the given claim.
    ///
    /// Called periodically to detect when a hardware-presence claim has expired
    /// or the underlying source has disconnected.
    async fn freshness(&self, claim: &Claim) -> Result<FreshnessResult, AttestorError>;
}
