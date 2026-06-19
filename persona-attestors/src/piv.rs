//! PIV/smartcard attestor via PKCS#11.
//!
//! Requires the `pkcs11` feature. Without it, returns empty/unavailable on all ops.
// ponytail: full PKCS#11 slot enumeration and certificate parsing | upgrade path:
//   use cryptoki crate when pkcs11 feature enabled

use async_trait::async_trait;

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

/// Attestor for PIV smartcards via PKCS#11.
///
/// Requires the `pkcs11` feature and a connected PIV card.
/// Assurance: Iaa3 (hardware-bound key, user presence required).
/// Presence: Hardware (PIV slot 9A PIN/touch assertion).
#[derive(Debug)]
pub struct PivAttestor;

impl PivAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if PKCS#11 feature is enabled and at least one PIV slot is reachable.
    pub fn is_available() -> bool {
        #[cfg(feature = "pkcs11")]
        {
            // ponytail: full smartcard detect not yet implemented | upgrade:
            //   use cryptoki::Pkcs11::new(...) to enumerate slots
            false
        }
        #[cfg(not(feature = "pkcs11"))]
        false
    }
}

impl Default for PivAttestor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attestor for PivAttestor {
    fn name(&self) -> &str {
        "piv"
    }

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        // ponytail: PKCS#11 slot enumeration not yet implemented | upgrade:
        //   C_EnumerateSlots, C_GetCertificate, parse X.509 UPN/email
        Ok(vec![])
    }

    async fn prove(
        &self,
        _claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        // ponytail: PIV slot 9A sign not yet implemented | upgrade:
        //   C_SignInit with CKM_RSA_PKCS or CKM_ECDSA
        Err(AttestorError::ChallengeFailed(
            "PIV signing not yet implemented".into(),
        ))
    }

    async fn freshness(&self, _claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        Ok(FreshnessResult::Unavailable)
    }
}
