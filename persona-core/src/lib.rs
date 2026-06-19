//! Shared persona types: SPIFFE IDs, assurance levels, presence model, trust domains.

pub mod assurance;
pub mod spiffe_id;

pub use assurance::{AssuranceError, IdentityAssurance, PresenceLevel};
pub use spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
