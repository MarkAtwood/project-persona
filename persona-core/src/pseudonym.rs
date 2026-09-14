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

use crate::consumer::ConsumerIdentity;
use crate::spiffe_id::SpiffeId;

/// The SPIFFE ID a given consumer sees for a given root identity.
///
/// `ikm` is the daemon's per-process pseudonym key. It is `&[u8; 32]` rather
/// than `&[u8]` so that `ikm ‖ root_uri` is unambiguous by construction: a
/// variable-length prefix would let two different (key, root) pairs produce the
/// same material. Binding the root matters because one daemon can hold claims
/// for more than one root identity, and without it a consumer would receive the
/// same pseudonym for the user's SSH identity and their PIV identity.
///
/// Crate-private on purpose. The only public entry point is
/// `SvidSigner::pseudonymous_id`, which supplies a secret `ikm`. A public
/// function taking arbitrary key material would invite a caller to pass
/// something public — the root URI, the trust domain — and HKDF over public
/// inputs is not pseudonymity: any consumer could then recompute every other
/// consumer's pseudonym offline.
pub(crate) fn derive_pseudonymous_id(
    ikm: &[u8; 32],
    root: &SpiffeId,
    consumer: &ConsumerIdentity,
) -> SpiffeId {
    let root_uri = root.uri();
    let mut material = Vec::with_capacity(ikm.len() + root_uri.len());
    material.extend_from_slice(ikm);
    material.extend_from_slice(root_uri.as_bytes());
    let hkdf_id = derive_pseudonym(
        &material,
        &root.trust_domain.to_string(),
        &consumer.selector_key(),
    );
    SpiffeId::pseudonymous(root.trust_domain.clone(), &hkdf_id)
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

    use crate::consumer::ConsumerIdentity;
    use crate::spiffe_id::{SpiffeId, TrustDomain};
    use std::str::FromStr as _;

    fn root() -> SpiffeId {
        SpiffeId::new(TrustDomain::SshLocal, "user/testuser")
    }

    #[test]
    fn distinct_consumers_get_distinct_pseudonymous_ids() {
        let a = derive_pseudonymous_id(
            &[7u8; 32],
            &root(),
            &ConsumerIdentity::BinarySha256([1u8; 32]),
        );
        let b = derive_pseudonymous_id(
            &[7u8; 32],
            &root(),
            &ConsumerIdentity::BinarySha256([2u8; 32]),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_consumer_gets_the_same_pseudonymous_id() {
        let c = ConsumerIdentity::BinarySha256([3u8; 32]);
        assert_eq!(
            derive_pseudonymous_id(&[7u8; 32], &root(), &c),
            derive_pseudonymous_id(&[7u8; 32], &root(), &c),
        );
    }

    #[test]
    fn a_different_key_yields_a_different_pseudonymous_id() {
        // The privacy property: without the daemon's secret, the pseudonym is
        // not computable from the root identity and consumer alone.
        let c = ConsumerIdentity::BinarySha256([3u8; 32]);
        assert_ne!(
            derive_pseudonymous_id(&[7u8; 32], &root(), &c),
            derive_pseudonymous_id(&[8u8; 32], &root(), &c),
        );
    }

    #[test]
    fn a_different_root_yields_a_different_pseudonymous_id() {
        let c = ConsumerIdentity::BinarySha256([3u8; 32]);
        let other = SpiffeId::new(TrustDomain::SshLocal, "user/someone-else");
        assert_ne!(
            derive_pseudonymous_id(&[7u8; 32], &root(), &c),
            derive_pseudonymous_id(&[7u8; 32], &other, &c),
        );
    }

    #[test]
    fn the_pseudonymous_id_does_not_carry_the_root_path() {
        let id = derive_pseudonymous_id(
            &[7u8; 32],
            &root(),
            &ConsumerIdentity::BinarySha256([3u8; 32]),
        );
        assert!(
            !id.uri().contains("user/testuser"),
            "root leaked: {}",
            id.uri()
        );
        assert_ne!(id, root());
    }

    #[test]
    fn every_path_segment_is_a_legal_spiffe_segment() {
        // Regression test for using `selector_key()` — which contains `:` — as a
        // path component. Catches an illegal URI before it can be signed.
        let id = derive_pseudonymous_id(
            &[7u8; 32],
            &root(),
            &ConsumerIdentity::MacosBundleId {
                bundle_id: "com.example.app".into(),
                team_id: "ABCDE12345".into(),
            },
        );
        let uri = id.uri();
        assert_eq!(SpiffeId::from_str(&uri).expect("must round-trip"), id);
        for seg in id.path.split('/') {
            assert!(!seg.is_empty(), "empty path segment in {uri}");
            assert!(
                seg.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
                "illegal SPIFFE path segment {seg:?} in {uri}"
            );
        }
    }
}
