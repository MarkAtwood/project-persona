//! FIDO2 hardware attestor — enumerates connected FIDO2 devices.
//!
//! Requires the `fido2` feature. When compiled without it, all methods
//! return empty/unavailable results so the crate still builds everywhere.
// ponytail: full FIDO2 get_assertion for prove() | upgrade path is implementing
//   ctap2 get_assertion with pinUvAuthProtocol once prove() is needed

use async_trait::async_trait;

#[cfg(feature = "fido2")]
use sha2::{Digest, Sha256};

#[cfg(feature = "fido2")]
use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

/// Attestor for FIDO2 hardware authenticators.
///
/// Requires the `fido2` feature and connected FIDO2 devices.
/// Assurance: Iaa3 (hardware-bound + IdP-verified, user presence required).
/// Presence: Hardware (timestamped UP bit assertion).
#[derive(Debug)]
pub struct Fido2Attestor;

impl Fido2Attestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if FIDO2 feature is enabled and at least one device is reachable.
    pub fn is_available() -> bool {
        #[cfg(feature = "fido2")]
        {
            !ctap_hid_fido2::get_fidokey_devices().is_empty()
        }
        #[cfg(not(feature = "fido2"))]
        false
    }
}

impl Default for Fido2Attestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a device path to a short hex identifier for use in the SPIFFE path.
#[cfg(feature = "fido2")]
fn device_path_hash(path: &str) -> String {
    let hash = Sha256::digest(path.as_bytes());
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[async_trait]
impl Attestor for Fido2Attestor {
    fn name(&self) -> &str {
        "fido2"
    }

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        #[cfg(feature = "fido2")]
        {
            let devices = tokio::task::spawn_blocking(ctap_hid_fido2::get_fidokey_devices)
                .await
                .map_err(|e| AttestorError::Unavailable(format!("fido2 task error: {e}")))?;

            let claims = devices
                .into_iter()
                .map(|dev| {
                    let path_key = match &dev.param {
                        ctap_hid_fido2::HidParam::Path(p) => p.clone(),
                        ctap_hid_fido2::HidParam::VidPid { vid, pid } => {
                            format!("{vid:04x}:{pid:04x}")
                        }
                    };
                    let path_hash = device_path_hash(&path_key);
                    let product = if dev.product_string.is_empty() {
                        "Unknown".to_owned()
                    } else {
                        dev.product_string.clone()
                    };
                    Claim {
                        source: "fido2".into(),
                        assurance: IdentityAssurance::Iaa3,
                        presence: PresenceLevel::Hardware,
                        spiffe_id: SpiffeId::new(
                            TrustDomain::SshLocal,
                            format!("fido2/{path_hash}"),
                        ),
                        display_name: format!("FIDO2 {product}"),
                    }
                })
                .collect();

            Ok(claims)
        }

        #[cfg(not(feature = "fido2"))]
        Ok(vec![])
    }

    async fn prove(
        &self,
        _claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        #[cfg(feature = "fido2")]
        {
            // ponytail: full FIDO2 get_assertion not yet implemented | upgrade path:
            //   ctap2 get_assertion with pinUvAuthProtocol
            Err(AttestorError::ChallengeFailed(
                "FIDO2 assertion not yet implemented".into(),
            ))
        }

        #[cfg(not(feature = "fido2"))]
        Err(AttestorError::Unavailable(
            "fido2 feature not compiled in".into(),
        ))
    }

    async fn freshness(&self, _claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        #[cfg(feature = "fido2")]
        {
            // ponytail: track UP timestamp, decay after configurable TTL
            Ok(FreshnessResult::Fresh)
        }

        #[cfg(not(feature = "fido2"))]
        Ok(FreshnessResult::Unavailable)
    }
}
