//! JWT-SVID `persona` extension claims.

use crate::IdentityAssurance;
use serde::{Deserialize, Serialize};

/// Presence attestation info embedded in a JWT-SVID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceInfo {
    /// Whether the user was physically present at attestation time.
    pub present: bool,
    /// Attestation mechanism, e.g. `"fido2_up"`, `"windows_hello"`, `"touchid"`, `"piv_pin"`.
    pub attested_by: String,
    /// RFC 3339 timestamp when presence was attested.
    pub attested_at: String,
    /// RFC 3339 timestamp when the hardware presence attestation expires.
    pub present_until: String,
}

/// The `persona` extension object carried in a JWT-SVID payload.
///
/// Serialises to the exact JSON shape required by the spec.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaClaims {
    /// Trust domain root this identity was issued under.
    pub root_trust_domain: String,
    /// Ordered list of identity source descriptors.
    pub sources: Vec<String>,
    /// Identity assurance level.
    pub identity_assurance: IdentityAssurance,
    /// Presence attestation detail.
    pub presence: PresenceInfo,
    /// Authentication methods used (e.g. `["fido2", "totp"]`).
    pub auth_methods: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_persona_claims() {
        let claims = PersonaClaims {
            root_trust_domain: "example.com".into(),
            sources: vec!["tailscale".into()],
            identity_assurance: IdentityAssurance::Iaa3,
            presence: PresenceInfo {
                present: true,
                attested_by: "fido2_up".into(),
                attested_at: "2026-06-19T00:00:00Z".into(),
                present_until: "2026-06-19T01:00:00Z".into(),
            },
            auth_methods: vec!["fido2".into()],
        };

        let json = serde_json::to_string(&claims).unwrap();
        let back: PersonaClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims, back);
    }

    #[test]
    fn presence_level_in_claims_serialises_lowercase() {
        // IdentityAssurance::Iaa3 must serialise as "iaa3"
        let claims = PersonaClaims {
            root_trust_domain: "t".into(),
            sources: vec![],
            identity_assurance: IdentityAssurance::Iaa2,
            presence: PresenceInfo {
                present: false,
                attested_by: "".into(),
                attested_at: "".into(),
                present_until: "".into(),
            },
            auth_methods: vec![],
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iaa2\""), "got: {json}");
    }
}
