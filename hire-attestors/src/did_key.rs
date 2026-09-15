//! DID attestor — discovers did:key identifiers from environment configuration.
//!
//! No network I/O. Reads HIRE_DID_KEYS (whitespace-separated did:key URIs).
// ponytail: did:web HTTP resolution | upgrade path: reqwest + did-web resolver once networking is desired

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{Attestor, AttestorError, Candidate, SelfAssertedDomain};

/// Attestor that returns did:key identifiers configured via HIRE_DID_KEYS.
#[derive(Debug)]
pub struct DidKeyAttestor;

impl DidKeyAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if HIRE_DID_KEYS is set and contains at least one did:key URI.
    pub fn is_available() -> bool {
        std::env::var("HIRE_DID_KEYS")
            .map(|v| v.split_whitespace().any(|s| s.starts_with("did:key:")))
            .unwrap_or(false)
    }
}

impl Default for DidKeyAttestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns SHA-256(did) as a 64-char hex string.
///
/// The whole digest: this is the authorization subject, and a truncation to 8
/// bytes puts a birthday collision at 2^32.
fn did_id(did: &str) -> String {
    let hash = Sha256::digest(did.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses a whitespace-separated list of DIDs, returning only valid did:key URIs.
fn parse_did_keys_from(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|s| s.starts_with("did:key:"))
        .map(str::to_owned)
        .collect()
}

fn parse_did_keys() -> Vec<String> {
    let raw = std::env::var("HIRE_DID_KEYS").unwrap_or_default();
    parse_did_keys_from(&raw)
}

#[async_trait]
impl Attestor for DidKeyAttestor {
    fn name(&self) -> &str {
        "did:key"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        // ponytail: did:key candidates sit under ssh.local | ceiling: the
        //   PersonalDid trust domain is never used | upgrade path: switch the
        //   domain once the DID is actually resolved rather than string-matched
        let candidates = parse_did_keys()
            .into_iter()
            .map(|did| {
                let id = did_id(&did);
                Candidate::new(
                    "did:key",
                    SelfAssertedDomain::SshLocal,
                    format!("did/{id}"),
                    did.clone(),
                )
            })
            .collect();
        Ok(candidates)
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
    fn did_id_is_stable() {
        let a = did_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let b = did_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes = 64 hex chars
                                 // Oracle: printf '%s' "<did>" | sha256sum, cross-checked against
                                 // openssl dgst -sha256.
        assert_eq!(
            a,
            "8551f404ecfe6403c2fe960ab267cd8c74a9a0701628ce24b1753946f2ebb16e"
        );
    }

    #[test]
    fn did_id_differs_for_different_dids() {
        let a = did_id("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let b = did_id("did:key:z6MkiTBz1234");
        assert_ne!(a, b);
    }
}
