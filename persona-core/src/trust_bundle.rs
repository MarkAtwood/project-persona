use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::DecodingKey;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::{SvidSigner, TrustDomain};

/// A single trust bundle for one trust domain.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TrustBundle {
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
#[derive(Debug, Default)]
pub struct TrustBundleStore {
    bundles: RwLock<HashMap<String, TrustBundle>>,
}

impl TrustBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the bundle for a trust domain.
    pub fn upsert(&self, bundle: TrustBundle) {
        let key = bundle.trust_domain.to_string();
        self.bundles
            .write()
            .expect("trust bundle lock poisoned")
            .insert(key, bundle);
    }

    /// Get a snapshot of all current bundles.
    pub fn snapshot(&self) -> Vec<TrustBundle> {
        self.bundles
            .read()
            .expect("trust bundle lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Get a single bundle by trust domain string key.
    pub fn get(&self, trust_domain: &str) -> Option<TrustBundle> {
        self.bundles
            .read()
            .expect("trust bundle lock poisoned")
            .get(trust_domain)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
