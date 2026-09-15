//! HKDF-SHA256 pseudonym derivation for per-consumer identity blinding.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::consumer::ConsumerIdentity;
use crate::spiffe_id::{SpiffeId, TrustDomain};

/// Scheme label and version prefixed to the HKDF `info` input.
///
/// A pseudonym is the stable per-consumer identity a relying application keys
/// its user records on, so the exact bytes fed to HKDF are a wire commitment
/// from the first release: change them and every downstream application sees
/// all of its users as new users, with no way to notice and no way to serve
/// both schemes while it migrates.
///
/// The version makes that change expressible instead of silent. Two schemes
/// derived under different labels are unrelated, so `v2` can be derived
/// alongside `v1` and an application can accept both during a migration.
///
/// Bump this only together with a deliberate change to the derivation, and
/// treat everything it covers as frozen: the salt (the trust domain's string
/// form), the `info` layout below, the KDF, and every format string in
/// [`ConsumerIdentity::selector_key`].
const SCHEME: &str = "hire-pseudonym-v1:";

/// Derives a stable per-consumer pseudonym via HKDF-SHA256.
///
/// The trust domain is the HKDF salt and the consumer is the HKDF `info`,
/// prefixed with [`SCHEME`]. Both arrive as their own types rather than as two
/// adjacent `&str` parameters: salt and info are semantically opposite, and a
/// call that swapped them used to compile, never error, and return a
/// well-formed pseudonym that was simply wrong and stably wrong. Nothing above
/// this function could have detected it, because the only property anything
/// checks is determinism.
///
/// Taking `&ConsumerIdentity` also removes an unenforced coupling: the caller
/// used to be expected, but never required, to pass `selector_key()`.
///
/// Returns the raw 32 bytes. Crate-private, like [`derive_pseudonymous_id`] and
/// for the same reason: a public function taking arbitrary key material invites
/// a caller to pass something public, and HKDF over public inputs is not
/// pseudonymity. [`crate::SvidSigner::pseudonymous_id`] is the only entry point.
pub(crate) fn derive_pseudonym(
    ikm: &[u8],
    trust_domain: &TrustDomain,
    consumer: &ConsumerIdentity,
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(trust_domain.to_string().as_bytes()), ikm);
    let mut okm = [0u8; 32];
    hk.expand(
        format!("{SCHEME}{}", consumer.selector_key()).as_bytes(),
        &mut okm,
    )
    .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// The SPIFFE ID a given consumer sees for a given root identity.
///
/// `ikm` is the daemon's per-process pseudonym key. It is `&[u8; 32]` rather
/// than `&[u8]` so that `ikm ‖ root_uri` is unambiguous by construction: a
/// variable-length prefix would let two different (key, root) pairs produce the
/// same material. Binding the root matters because one daemon can hold claims
/// for more than one root identity, and without it a consumer would receive the
/// same pseudonym for the user's SSH identity and their PIV identity.
pub(crate) fn derive_pseudonymous_id(
    ikm: &[u8; 32],
    root: &SpiffeId,
    consumer: &ConsumerIdentity,
) -> SpiffeId {
    let root_uri = root.uri();
    let mut material = Vec::with_capacity(ikm.len() + root_uri.len());
    material.extend_from_slice(ikm);
    material.extend_from_slice(root_uri.as_bytes());
    let okm = derive_pseudonym(&material, &root.trust_domain, consumer);
    SpiffeId::pseudonymous(root.trust_domain.clone(), &hex(&okm))
}

/// Lowercase hex, the form a pseudonym takes in a SPIFFE path.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    /// Vectors from pyca/cryptography, which is a different HKDF implementation
    /// from the one under test:
    ///
    /// ```text
    /// python3 -c "
    /// from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    /// from cryptography.hazmat.primitives import hashes
    /// print(HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=INFO)
    ///       .derive(IKM).hex())"
    /// ```
    ///
    /// `INFO` is the scheme label followed by the consumer's selector key, so
    /// these also pin the label: dropping it changes every one of them.
    #[test]
    fn known_vector_org_oidc_binary_consumer() {
        // salt=b"example.com"
        // info=b"hire-pseudonym-v1:binary_sha256:" + b"ab"*32
        let got = derive_pseudonym(
            b"secret-ikm",
            &TrustDomain::OrgOidc("example.com".into()),
            &ConsumerIdentity::BinarySha256([0xab; 32]),
        );
        assert_eq!(
            hex(&got),
            "3200c8d15c6e187ee34b50a34bf055533350c68aebb6644d2e8fe4aa89cdfa3b"
        );
    }

    #[test]
    fn known_vector_tailscale_macos_consumer() {
        // salt=b"tailscale"
        // info=b"hire-pseudonym-v1:macos:bundle_id:com.example.app:team_id:ABCDE12345"
        let got = derive_pseudonym(
            b"secret-ikm",
            &TrustDomain::Tailscale,
            &ConsumerIdentity::MacosBundleId {
                bundle_id: "com.example.app".into(),
                team_id: "ABCDE12345".into(),
            },
        );
        assert_eq!(
            hex(&got),
            "f6e2eceb0996627a38cae52a3a941c12eecfec3a1d0828163808db133944c17f"
        );
    }

    #[test]
    fn known_vector_ssh_local_flatpak_consumer() {
        // salt=b"ssh.local"
        // info=b"hire-pseudonym-v1:flatpak:app:org.gnome.Gedit"
        let got = derive_pseudonym(
            b"ikm",
            &TrustDomain::SshLocal,
            &ConsumerIdentity::FlatpakApp("org.gnome.Gedit".into()),
        );
        assert_eq!(
            hex(&got),
            "9c21e702df5b78608e3a9f7b943b6b709d3cd5d5e0cdba489bab36ddbcbefadd"
        );
    }

    #[test]
    fn the_scheme_label_is_part_of_the_derivation() {
        // The same inputs with the label omitted, computed by the same external
        // oracle. A pseudonym that matched this would mean the label had fallen
        // out of the info input and the version could never be bumped.
        let unversioned = "b2f13ec714e5e28bdfff08a00a411df23c4fd35083857be052c24d371c145767";
        let got = derive_pseudonym(
            b"secret-ikm",
            &TrustDomain::OrgOidc("example.com".into()),
            &ConsumerIdentity::BinarySha256([0xab; 32]),
        );
        assert_ne!(
            hex(&got),
            unversioned,
            "the scheme label is not being mixed in"
        );
    }

    #[test]
    fn output_is_64_hex_chars() {
        let out = hex(&derive_pseudonym(
            b"ikm",
            &TrustDomain::SshLocal,
            &ConsumerIdentity::SnapName("firefox".into()),
        ));
        assert_eq!(out.len(), 64, "expected 64 hex chars, got {}", out.len());
        assert!(
            out.chars().all(|c| c.is_ascii_hexdigit()),
            "not lowercase hex: {out}"
        );
    }

    #[test]
    fn deterministic() {
        let c = ConsumerIdentity::SnapName("firefox".into());
        assert_eq!(
            derive_pseudonym(b"secret-ikm", &TrustDomain::Tailscale, &c),
            derive_pseudonym(b"secret-ikm", &TrustDomain::Tailscale, &c),
        );
    }

    #[test]
    fn different_consumers_produce_different_pseudonyms() {
        let td = TrustDomain::OrgOidc("example.com".into());
        assert_ne!(
            derive_pseudonym(b"ikm", &td, &ConsumerIdentity::SnapName("one".into())),
            derive_pseudonym(b"ikm", &td, &ConsumerIdentity::SnapName("two".into())),
        );
    }

    #[test]
    fn different_trust_domains_produce_different_pseudonyms() {
        let c = ConsumerIdentity::SnapName("firefox".into());
        assert_ne!(
            derive_pseudonym(b"ikm", &TrustDomain::OrgOidc("domain-a.example".into()), &c),
            derive_pseudonym(b"ikm", &TrustDomain::OrgOidc("domain-b.example".into()), &c),
        );
    }

    #[test]
    fn different_ikm_produces_different_pseudonyms() {
        let td = TrustDomain::SshLocal;
        let c = ConsumerIdentity::SnapName("firefox".into());
        assert_ne!(
            derive_pseudonym(b"ikm-alice", &td, &c),
            derive_pseudonym(b"ikm-bob", &td, &c),
        );
    }

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
