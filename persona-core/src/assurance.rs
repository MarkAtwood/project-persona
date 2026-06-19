//! Identity assurance and presence level types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when parsing an assurance or presence string fails.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssuranceError {
    /// The string did not match any known `IdentityAssurance` level.
    #[error("unknown identity assurance level: {0:?}")]
    UnknownAssurance(String),

    /// The string did not match any known `PresenceLevel`.
    #[error("unknown presence level: {0:?}")]
    UnknownPresence(String),
}

/// Identity assurance level, roughly aligned with NIST SP 800-63 AAL tiers.
///
/// Ordered `Iaa1 < Iaa2 < Iaa3`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityAssurance {
    /// Self-asserted: SSH key, GPG key, or DID.
    Iaa1,

    /// IdP-verified: Tailscale OIDC, GNOME Online Accounts.
    Iaa2,

    /// Hardware-bound and IdP-verified: FIDO2, PIV, Windows Hello.
    Iaa3,
}

impl fmt::Display for IdentityAssurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityAssurance::Iaa1 => f.write_str("iaa1"),
            IdentityAssurance::Iaa2 => f.write_str("iaa2"),
            IdentityAssurance::Iaa3 => f.write_str("iaa3"),
        }
    }
}

impl FromStr for IdentityAssurance {
    type Err = AssuranceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iaa1" => Ok(IdentityAssurance::Iaa1),
            "iaa2" => Ok(IdentityAssurance::Iaa2),
            "iaa3" => Ok(IdentityAssurance::Iaa3),
            other => Err(AssuranceError::UnknownAssurance(other.to_owned())),
        }
    }
}

/// Physical/logical presence assertion level.
///
/// Ordered `None < Session < Software < Hardware`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceLevel {
    /// No presence assertion.
    None,

    /// Screen unlocked at login (session-level).
    Session,

    /// TOTP or password re-entry (software-level).
    Software,

    /// FIDO2 UP, Windows Hello, TouchID, or PIV PIN — timestamped,
    /// hardware-backed.
    Hardware,
}

impl fmt::Display for PresenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresenceLevel::None => f.write_str("none"),
            PresenceLevel::Session => f.write_str("session"),
            PresenceLevel::Software => f.write_str("software"),
            PresenceLevel::Hardware => f.write_str("hardware"),
        }
    }
}

impl FromStr for PresenceLevel {
    type Err = AssuranceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(PresenceLevel::None),
            "session" => Ok(PresenceLevel::Session),
            "software" => Ok(PresenceLevel::Software),
            "hardware" => Ok(PresenceLevel::Hardware),
            other => Err(AssuranceError::UnknownPresence(other.to_owned())),
        }
    }
}
