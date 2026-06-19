//! SVID signing engine: ephemeral ECDSA P-256 keypair, JWT-SVID and X.509-SVID issuance.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    #[error("key generation failed: {0}")]
    KeyGen(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

impl From<ring::error::Unspecified> for SignerError {
    fn from(e: ring::error::Unspecified) -> Self {
        SignerError::Sign(e.to_string())
    }
}

impl From<ring::error::KeyRejected> for SignerError {
    fn from(e: ring::error::KeyRejected) -> Self {
        SignerError::KeyGen(e.to_string())
    }
}

// ── JWT claims ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    spiffe_id: String,
    persona: serde_json::Value,
}

// ── SvidSigner ────────────────────────────────────────────────────────────────

/// Holds an ephemeral ECDSA P-256 keypair generated at daemon start.
/// The keypair is never persisted; it is discarded when the process exits.
pub struct SvidSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
    public_key_der: Vec<u8>,
    /// PKCS#8 DER bytes kept for jsonwebtoken ES256 signing.
    pkcs8_der: Vec<u8>,
}

impl SvidSigner {
    /// Generate a fresh ephemeral keypair.
    pub fn new() -> Result<Self, SignerError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        let pkcs8_der = pkcs8.as_ref().to_vec();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)?;
        let public_key_der = key_pair.public_key().as_ref().to_vec();
        Ok(Self {
            key_pair,
            rng,
            public_key_der,
            pkcs8_der,
        })
    }

    /// DER-encoded public key for JWKS / trust-bundle publication.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    // ── JWT-SVID ──────────────────────────────────────────────────────────────

    /// Sign a JWT-SVID (ES256).  TTL: 5 minutes.
    ///
    /// * `spiffe_id`   – full SPIFFE URI, e.g. `spiffe://example.org/workload`
    /// * `audiences`   – one or more audience strings
    /// * `persona_ext` – arbitrary persona claims serialised as JSON
    pub fn sign_jwt_svid(
        &self,
        spiffe_id: &str,
        audiences: &[&str],
        persona_ext: serde_json::Value,
    ) -> Result<String, SignerError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();
        let claims = JwtClaims {
            sub: spiffe_id.to_owned(),
            aud: audiences.iter().map(|s| s.to_string()).collect(),
            exp: now + 300, // 5 minutes
            iat: now,
            spiffe_id: spiffe_id.to_owned(),
            persona: persona_ext,
        };
        let key = EncodingKey::from_ec_der(&self.pkcs8_der);
        let token = encode(&Header::new(Algorithm::ES256), &claims, &key)?;
        Ok(token)
    }

    // ── X.509-SVID ────────────────────────────────────────────────────────────

    // ponytail: stub X.509 signer | upgrade to x509-cert + p256 when ring/RustCrypto interop is resolved
    /// Sign an X.509-SVID with URI SAN = `spiffe_id`.  TTL: 1 hour.
    ///
    /// Currently stubbed: blocked on ring ↔ x509-cert key-type interop (persona-4qm).
    pub fn sign_x509_svid(&self, _spiffe_id: &str) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::NotImplemented("x509_svid".into()))
    }

    // ── Raw ring signing (internal use / future mTLS) ─────────────────────────

    /// Sign arbitrary bytes with the ephemeral key (ECDSA P-256 fixed).
    pub fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let sig = self.key_pair.sign(&self.rng, message)?;
        Ok(sig.as_ref().to_vec())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generates_keypair() {
        let signer = SvidSigner::new().expect("keypair generation failed");
        assert!(!signer.public_key_der().is_empty());
    }

    #[test]
    fn sign_jwt_svid_produces_three_part_token() {
        let signer = SvidSigner::new().unwrap();
        let token = signer
            .sign_jwt_svid(
                "spiffe://example.org/workload",
                &["api.example.org"],
                serde_json::json!({"level": "asserted"}),
            )
            .unwrap();
        // A compact JWS has exactly three dot-separated parts.
        assert_eq!(token.split('.').count(), 3, "expected compact JWS format");
    }

    #[test]
    fn sign_x509_svid_returns_not_implemented() {
        let signer = SvidSigner::new().unwrap();
        match signer.sign_x509_svid("spiffe://example.org/workload") {
            Err(SignerError::NotImplemented(_)) => {}
            other => panic!("expected NotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn sign_raw_produces_signature() {
        let signer = SvidSigner::new().unwrap();
        let msg = b"hello persona";
        let sig = signer.sign_raw(msg).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn jwt_svid_claims_are_correct() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let signer = SvidSigner::new().unwrap();
        let spiffe_id = "spiffe://example.org/workload";
        let audience = "api.example.org";
        let persona_val = serde_json::json!({"level": "asserted"});

        let token = signer
            .sign_jwt_svid(spiffe_id, &[audience], persona_val.clone())
            .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();

        assert_eq!(claims["sub"].as_str().unwrap(), spiffe_id);
        assert!(
            claims["aud"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(audience)),
            "audience not found in aud claim"
        );
        assert!(
            claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap(),
            "exp must be after iat"
        );
        assert_eq!(claims["spiffe_id"].as_str().unwrap(), spiffe_id);
        assert_eq!(claims["persona"], persona_val);
    }

    #[test]
    fn sign_raw_verifies_with_ring() {
        use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

        let signer = SvidSigner::new().unwrap();
        let msg = b"hello persona";
        let sig = signer.sign_raw(msg).unwrap();

        let pub_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, signer.public_key_der());
        pub_key
            .verify(msg, &sig)
            .expect("signature verification failed");
    }
}
