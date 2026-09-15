//! Trust bundles: the verification material a consumer needs to check an SVID.
//!
//! One [`TrustBundle`] per trust domain, held in a [`TrustBundleStore`] that the
//! daemon populates at startup and the FetchJWTBundles and FetchX509Bundles RPCs
//! read.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::DecodingKey;
use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use crate::{SvidSigner, TrustDomain};

/// A single trust bundle for one trust domain.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// The trust domain this bundle is the verification material for.
    pub trust_domain: TrustDomain,
    /// DER-encoded X.509 CA certificates for this trust domain.
    pub x509_authorities: Vec<Vec<u8>>,
    /// JWKS JSON for this trust domain (JWT verification).
    pub jwt_authorities: serde_json::Value,
}

impl TrustBundle {
    /// The bundle for a trust domain this daemon is itself the authority for.
    ///
    /// The JWT authority is `signer`'s JWKS. There is no X.509 authority:
    /// `sign_x509_svid` returns `NotImplemented` and no CA certificate exists
    /// anywhere in this workspace, so `x509_authorities` is empty and a
    /// conforming consumer correctly rejects every X509-SVID. The raw EC point
    /// this field used to carry was not a certificate at all and could only
    /// ever produce an ASN.1 parse error (persona-5s4b.60).
    ///
    /// This is the only constructor. Four call sites used to assemble the pair
    /// by hand and all four were wrong in the same way; one constructor removes
    /// the possibility instead of documenting against it.
    ///
    /// ponytail: one key, no X.509 authority, no rollover window | ceiling: a
    ///   restart invalidates every outstanding token, and a consumer caching
    ///   this JWKS sees a kid miss with no refresh signal | upgrade path:
    ///   publish the issuing CA certificate here when persona-4qm lands X.509
    ///   issuance, and publish the outgoing and incoming JWKs together across a
    ///   rotation
    pub fn local(trust_domain: TrustDomain, signer: &SvidSigner) -> Self {
        Self {
            trust_domain,
            x509_authorities: Vec::new(),
            jwt_authorities: signer.jwks(),
        }
    }

    /// The published key with this `kid`, as a verification key.
    ///
    /// Selection is by `kid` and nothing else: this daemon puts a `kid` on
    /// every token it signs and in every JWK it publishes, so a kid that names
    /// no key is a miss, not a reason to try the others.
    ///
    /// The coordinate lengths are checked here because
    /// `DecodingKey::from_ec_components` does not check them — it concatenates
    /// `0x04 || x || y` whatever their length, so a truncated coordinate in a
    /// bundle would yield a silently wrong key rather than an error. Today
    /// every bundle is built by `local` above; a federated bundle will not be.
    pub fn jwt_decoding_key(&self, kid: &str) -> Option<DecodingKey> {
        let jwks: JwkSet = serde_json::from_value(self.jwt_authorities.clone()).ok()?;
        let jwk = jwks.find(kid)?;
        match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(ec)
                if ec.curve == EllipticCurve::P256
                    && B64URL.decode(&ec.x).is_ok_and(|b| b.len() == 32)
                    && B64URL.decode(&ec.y).is_ok_and(|b| b.len() == 32) =>
            {
                DecodingKey::from_jwk(jwk).ok()
            }
            _ => None,
        }
    }
}

/// Thread-safe store of trust bundles keyed by trust domain.
///
/// Populated at daemon startup from the local CA key and any federated sources.
/// Read by FetchJWTBundles and FetchX509Bundles RPCs.
///
/// Lock poisoning is not a failure mode here. The guarded sections below run no
/// user code -- a map insert and a clone of the values -- so nothing under the
/// lock can panic and leave the map torn. A poisoned flag can therefore only
/// have been set by a panic elsewhere in the process, and refusing to serve
/// bundles because of it would turn one unrelated panic into a daemon that
/// fails every FetchJWTBundles and FetchX509Bundles call from then on. The
/// guards are taken with `unwrap_or_else(PoisonError::into_inner)`, which
/// removes the failure mode rather than documenting it.
#[derive(Debug, Default)]
pub struct TrustBundleStore {
    bundles: RwLock<HashMap<String, TrustBundle>>,
}

impl TrustBundleStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the bundle for a trust domain.
    pub fn upsert(&self, bundle: TrustBundle) {
        let key = bundle.trust_domain.to_string();
        self.bundles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, bundle);
    }

    /// The bundle for one trust domain, cloned.
    ///
    /// Takes the `TrustDomain` rather than the string it is stored under: the
    /// key is this type's `Display` form, and a caller that had to reproduce it
    /// would need to know that `PersonalDid(x)` keys as `personal.{x}` and
    /// `PivIssuer(x)` as `piv.{x}`. That is the store's business, not the
    /// caller's.
    ///
    /// Two trust domains whose `Display` forms collide share an entry here.
    /// That is persona-5s4b.37 and is deliberately not decided in this function:
    /// the key is derived exactly as `upsert` derives it, so lookups agree with
    /// insertions whatever .37 settles on.
    pub fn get(&self, trust_domain: &TrustDomain) -> Option<TrustBundle> {
        self.bundles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&trust_domain.to_string())
            .cloned()
    }

    /// Every bundle currently held, cloned.
    pub fn snapshot(&self) -> Vec<TrustBundle> {
        self.bundles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_panic_elsewhere_does_not_stop_the_store_serving_bundles() {
        // The store is shared across every gRPC handler, so taking the guards
        // with .expect() meant one unrelated panic anywhere in the process
        // turned every later FetchJWTBundles call into a daemon panic. The
        // spawned thread below prints a panic message; that is the test doing
        // its job, not a failure.
        let store = Arc::new(TrustBundleStore::new());
        let signer = SvidSigner::new().expect("signer");
        store.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));

        let poisoner = Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.bundles.write().expect("uncontended");
            panic!("poisoning the lock the way an unrelated bug would");
        })
        .join();
        assert!(
            store.bundles.is_poisoned(),
            "precondition: the lock must actually be poisoned"
        );

        assert_eq!(
            store.snapshot().len(),
            1,
            "a poisoned flag must not lose the bundles already held"
        );
        store.upsert(TrustBundle::local(TrustDomain::Tailscale, &signer));
        assert_eq!(
            store.snapshot().len(),
            2,
            "the store must still accept bundles after an unrelated panic"
        );
    }

    #[test]
    fn a_bundle_is_found_by_the_trust_domain_it_was_stored_under() {
        // The caller passes the TrustDomain; reproducing its Display form is
        // the store's business. persona-grpc's ValidateJWTSVID used to spell
        // out `.get(&claimed.trust_domain.to_string())` at its call site.
        let store = TrustBundleStore::new();
        let signer = SvidSigner::new().expect("signer");
        store.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));

        let found = store
            .get(&TrustDomain::SshLocal)
            .expect("the bundle just inserted must be findable");
        assert_eq!(found.trust_domain, TrustDomain::SshLocal);
        assert!(
            store.get(&TrustDomain::Tailscale).is_none(),
            "a trust domain with no bundle is a miss"
        );
    }

    #[test]
    fn a_bundle_is_stored_under_its_own_trust_domain() {
        let store = TrustBundleStore::new();
        let signer = SvidSigner::new().expect("signer");
        store.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));
        store.upsert(TrustBundle::local(TrustDomain::Tailscale, &signer));
        let mut domains: Vec<String> = store
            .snapshot()
            .iter()
            .map(|b| b.trust_domain.to_string())
            .collect();
        domains.sort();
        assert_eq!(domains, ["ssh.local", "tailscale"]);

        // upsert replaces rather than accumulates.
        store.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));
        assert_eq!(store.snapshot().len(), 2);
    }

    #[test]
    fn local_bundle_publishes_a_jwt_authority_and_no_x509_authority() {
        let signer = SvidSigner::new().unwrap();
        let bundle = TrustBundle::local(TrustDomain::SshLocal, &signer);
        assert!(
            bundle.x509_authorities.is_empty(),
            "no CA certificate exists to publish while sign_x509_svid is unimplemented"
        );
        assert!(
            bundle.jwt_decoding_key(&signer.kid()).is_some(),
            "the published bundle must carry the key this signer signs with"
        );
        assert!(
            bundle.jwt_decoding_key("not-a-published-kid").is_none(),
            "selection is by kid: an unknown kid is a miss, not a fallback"
        );
    }
}
