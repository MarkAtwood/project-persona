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

    #[test]
    fn known_vector_v1() {
        // oracle: python3 -c "
        // from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        // from cryptography.hazmat.primitives import hashes
        // hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
        //             salt=b'example.com', info=b'com.example.app')
        // print(hkdf.derive(b'secret-ikm').hex())"
        let got = derive_pseudonym(b"secret-ikm", "example.com", "com.example.app");
        assert_eq!(
            got,
            "219792b31e1c5054b9dd68b70a7f94320098a61b2f8481915828aafd5aec7be0"
        );
    }

    #[test]
    fn known_vector_v2() {
        // oracle: python3 -c "
        // hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
        //             salt=b'tailscale', info=b'com.example.app')
        // print(hkdf.derive(b'secret-ikm').hex())"
        let got = derive_pseudonym(b"secret-ikm", "tailscale", "com.example.app");
        assert_eq!(
            got,
            "e7464bdc10f6fc78c94c3fab9bbb044506f2662fdfdc6b1d53f69f038804fa91"
        );
    }

    #[test]
    fn known_vector_v3() {
        // oracle: python3 -c "
        // hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
        //             salt=b'example.com', info=b'com.app.one')
        // print(hkdf.derive(b'ikm').hex())"
        let got = derive_pseudonym(b"ikm", "example.com", "com.app.one");
        assert_eq!(
            got,
            "157b585e2f388f205942c9c2b53c47fef0e07f8e4f20bc44d29bbdcea2c0ae22"
        );
    }

    #[test]
    fn output_is_64_hex_chars() {
        let out = derive_pseudonym(b"ikm", "example.com", "com.example.app");
        assert_eq!(out.len(), 64, "expected 64 hex chars, got {}", out.len());
        assert!(
            out.chars().all(|c| c.is_ascii_hexdigit()),
            "not lowercase hex: {out}"
        );
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
