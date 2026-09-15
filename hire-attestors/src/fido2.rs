//! FIDO2 hardware attestor — enumerates connected FIDO2 devices.
//!
//! Requires the `fido2` feature. When compiled without it, enumerate returns
//! empty so the crate still builds everywhere.
// ponytail: full FIDO2 get_assertion for prove() | upgrade path is implementing
//   ctap2 get_assertion with pinUvAuthProtocol once prove() is needed

use async_trait::async_trait;

#[cfg(feature = "fido2")]
use sha2::{Digest, Sha256};

use crate::{Attestor, AttestorError, Candidate};

#[cfg(feature = "fido2")]
use crate::{AttainableAssurance, ProofCost, SelfAssertedDomain};

/// Attestor for FIDO2 hardware authenticators.
///
/// Requires the `fido2` feature and connected FIDO2 devices.
/// Enumeration finds devices that are plugged in. Assurance and presence would
/// come from a CTAP2 assertion via `prove()`, which is not implemented, so this
/// attestor contributes no level today.
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

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        #[cfg(feature = "fido2")]
        {
            let devices = tokio::task::spawn_blocking(ctap_hid_fido2::get_fidokey_devices)
                .await
                .map_err(|e| AttestorError::Unavailable(format!("fido2 task error: {e}")))?;

            let candidates = devices
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
                    // A device answering a HID enumeration proves only that it is
                    // plugged in. The touch that would buy Hardware presence, and the
                    // attestation that would buy Iaa3, can only come from prove().
                    Candidate::new(
                        "fido2",
                        SelfAssertedDomain::SshLocal,
                        format!("fido2/{path_hash}"),
                        format!("FIDO2 {product}"),
                    )
                    .with_attainable(AttainableAssurance::Iaa3)
                    .with_proof_cost(ProofCost::Interactive)
                })
                .collect();

            Ok(candidates)
        }

        #[cfg(not(feature = "fido2"))]
        Ok(vec![])
    }
}
