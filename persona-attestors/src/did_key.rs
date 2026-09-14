//! DID attestor — discovers did:key identifiers from environment configuration.
//!
//! No network I/O. Reads PERSONA_DID_KEYS (whitespace-separated did:key URIs).
// ponytail: did:web HTTP resolution | upgrade path: reqwest + did-web resolver once networking is desired

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

/// Attestor that returns did:key identifiers configured via PERSONA_DID_KEYS.
#[derive(Debug)]
pub struct DidKeyAttestor;

impl DidKeyAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if PERSONA_DID_KEYS is set and contains at least one did:key URI.
    pub fn is_available() -> bool {
        std::env::var("PERSONA_DID_KEYS")
            .map(|v| v.split_whitespace().any(|s| s.starts_with("did:key:")))
            .unwrap_or(false)
    }
}

impl Default for DidKeyAttestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the first 8 bytes of SHA-256(did) as a 16-char hex string.
fn did_short_id(did: &str) -> String {
    let hash = Sha256::digest(did.as_bytes());
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses a whitespace-separated list of DIDs, returning only valid did:key URIs.
fn parse_did_keys_from(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|s| s.starts_with("did:key:"))
        .map(str::to_owned)
        .collect()
}

fn parse_did_keys() -> Vec<String> {
    let raw = std::env::var("PERSONA_DID_KEYS").unwrap_or_default();
    parse_did_keys_from(&raw)
}

#[async_trait]
impl Attestor for DidKeyAttestor {
    fn name(&self) -> &str {
        "did:key"
    }

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        let claims = parse_did_keys()
            .into_iter()
            .map(|did| {
                let short = did_short_id(&did);
                Claim::new(
                    "did:key",
                    IdentityAssurance::Iaa1,
                    PresenceLevel::None,
                    SpiffeId::new(TrustDomain::SshLocal, format!("did/{short}")),
                    did.clone(),
                )
            })
            .collect();
        Ok(claims)
    }

    async fn prove(
        &self,
        _claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        // ponytail: did:key signing not yet implemented | upgrade: resolve key material and sign with ed25519 or p256
        Err(AttestorError::ChallengeFailed(
            "did:key signing not yet implemented".into(),
        ))
    }

    async fn freshness(&self, _claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        if Self::is_available() {
            Ok(FreshnessResult::Fresh)
        } else {
            Ok(FreshnessResult::Unavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_did_key() {
        let dids = parse_did_keys_from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(dids.len(), 1);
        assert!(dids[0].starts_with("did:key:"));
    }

    #[test]
    fn parse_multiple_did_keys() {
        let dids = parse_did_keys_from(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK did:key:z6MkiTBz1234",
        );
        assert_eq!(dids.len(), 2);
        assert!(dids.iter().all(|d| d.starts_with("did:key:")));
    }

    #[test]
    fn parse_empty_returns_empty() {
        assert!(parse_did_keys_from("").is_empty());
    }

    #[test]
    fn parse_ignores_non_did_key_entries() {
        let dids = parse_did_keys_from("did:web:example.com did:key:z6MkhaX did:ethr:0x123");
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], "did:key:z6MkhaX");
    }

    #[test]
    fn did_short_id_is_stable() {
        let a = did_short_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let b = did_short_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn did_short_id_differs_for_different_dids() {
        let a = did_short_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let b = did_short_id("did:key:z6MkiTBz1234");
        assert_ne!(a, b);
    }
}
