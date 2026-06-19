//! HKDF-SHA256 pseudonym derivation for per-consumer identity blinding.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a stable per-consumer pseudonym via HKDF-SHA256.
///
/// `ikm` is the root identity key material.
/// `trust_domain` is used as the HKDF salt.
/// `consumer_app_id` is used as the HKDF info string.
///
/// Returns 32 bytes encoded as a lowercase hex string (64 characters).
pub fn derive_pseudonym(ikm: &[u8], trust_domain: &str, consumer_app_id: &str) -> String {
    let hk = Hkdf::<Sha256>::new(Some(trust_domain.as_bytes()), ikm);
    let mut okm = [0u8; 32];
    hk.expand(consumer_app_id.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").unwrap();
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Full cross-validated test vectors (openssl kdf -kdfopt digest:SHA2-256 ...) are
    // TODO: compute via `openssl kdf` once OpenSSL 3.x KDF CLI is available in CI and hardcode
    // the hex here.  Until then the tests below verify correctness properties that do not
    // require an external oracle.

    #[test]
    fn output_is_64_hex_chars() {
        let out = derive_pseudonym(b"ikm", "example.com", "com.example.app");
        assert_eq!(out.len(), 64, "expected 64 hex chars, got {}", out.len());
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()), "not lowercase hex: {out}");
    }

    #[test]
    fn deterministic() {
        let a = derive_pseudonym(b"secret-ikm", "tailscale", "com.example.app");
        let b = derive_pseudonym(b"secret-ikm", "tailscale", "com.example.app");
        assert_eq!(a, b);
    }

    #[test]
    fn different_consumer_ids_produce_different_pseudonyms() {
        let a = derive_pseudonym(b"ikm", "example.com", "com.app.one");
        let b = derive_pseudonym(b"ikm", "example.com", "com.app.two");
        assert_ne!(a, b);
    }

    #[test]
    fn different_trust_domains_produce_different_pseudonyms() {
        let a = derive_pseudonym(b"ikm", "domain-a.example", "com.app");
        let b = derive_pseudonym(b"ikm", "domain-b.example", "com.app");
        assert_ne!(a, b);
    }

    #[test]
    fn different_ikm_produces_different_pseudonyms() {
        let a = derive_pseudonym(b"ikm-alice", "example.com", "com.app");
        let b = derive_pseudonym(b"ikm-bob", "example.com", "com.app");
        assert_ne!(a, b);
    }
}
