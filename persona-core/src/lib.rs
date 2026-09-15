//! Shared persona types: SPIFFE IDs, assurance levels, presence model, trust domains.

pub mod assurance;
pub mod audience;
pub mod consumer;
pub mod hvid;
pub mod pseudonym;
pub mod signer;
pub mod spiffe_id;
pub mod trust_bundle;

pub use assurance::{AssuranceError, IdentityAssurance, PresenceLevel};
pub use audience::{AudienceExtensions, AudienceParseError};
pub use consumer::ConsumerIdentity;
pub use hvid::{PersonaClaims, PresenceInfo};
pub use signer::{SignerError, SvidSigner};
pub use spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
pub use trust_bundle::{TrustBundle, TrustBundleStore};
