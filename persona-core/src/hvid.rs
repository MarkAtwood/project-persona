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
    /// Unix seconds when the daemon observed the evidence behind the presence
    /// level. Not a proof that a human was verifiably at the keyboard then.
    pub attested_at: u64,
    /// Unix seconds after which the observation asserts no presence.
    /// [`PresenceInfo::attested_at`] plus the daemon's fixed presence TTL.
    pub present_until: u64,
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

impl PersonaClaims {
    /// Builds the `persona` extension object.
    ///
    /// `sources` and `auth_methods` are both `Vec<String>` and sit next to each
    /// other in meaning, so transposing them compiles. `sources` names where the
    /// identity came from (`"tailscale"`, `"piv-smartcard"`); `auth_methods`
    /// names how the user authenticated (`"tailscale_oidc"`, `"fido2_up"`).
    pub fn new(
        root_trust_domain: String,
        sources: Vec<String>,
        identity_assurance: IdentityAssurance,
        presence: PresenceInfo,
        auth_methods: Vec<String>,
    ) -> Self {
        Self {
            root_trust_domain,
            sources,
            identity_assurance,
            presence,
            auth_methods,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the `persona` extension printed in SPEC-HIA.md, "HVID Extension
    /// (Human Verifiable Identity Document)". Values and types are transcribed
    /// from that document, not from this crate.
    ///
    /// The key sets are compared for equality in both directions, so a field
    /// added to the wire fails here as loudly as one removed.
    #[test]
    fn serialises_to_the_spec_shape() {
        let value = serde_json::to_value(PersonaClaims::new(
            "example.com".into(),
            vec!["tailscale".into(), "piv-smartcard".into()],
            IdentityAssurance::Iaa3,
            PresenceInfo {
                present: true,
                attested_by: "fido2_up".into(),
                attested_at: 1_745_999_640,
                present_until: 1_745_999_940,
            },
            vec!["tailscale_oidc".into(), "fido2_up".into()],
        ))
        .unwrap();

        let obj = value
            .as_object()
            .expect("persona extension is a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "auth_methods",
                "identity_assurance",
                "presence",
                "root_trust_domain",
                "sources",
            ]
        );

        assert_eq!(obj["root_trust_domain"], serde_json::json!("example.com"));
        assert_eq!(
            obj["sources"],
            serde_json::json!(["tailscale", "piv-smartcard"])
        );
        assert_eq!(obj["identity_assurance"], serde_json::json!("iaa3"));
        assert_eq!(
            obj["auth_methods"],
            serde_json::json!(["tailscale_oidc", "fido2_up"])
        );

        let presence = obj["presence"]
            .as_object()
            .expect("presence is a JSON object");
        let mut presence_keys: Vec<&str> = presence.keys().map(String::as_str).collect();
        presence_keys.sort_unstable();
        assert_eq!(
            presence_keys,
            ["attested_at", "attested_by", "present", "present_until"]
        );

        assert_eq!(presence["present"], serde_json::json!(true));
        assert_eq!(presence["attested_by"], serde_json::json!("fido2_up"));

        // The spec prints these unquoted. A string here would still round-trip
        // through serde and still deserialise, so only a type check catches it.
        assert_eq!(presence["attested_at"].as_u64(), Some(1_745_999_640));
        assert_eq!(presence["present_until"].as_u64(), Some(1_745_999_940));
    }

    #[test]
    fn roundtrip_persona_claims() {
        let claims = PersonaClaims {
            root_trust_domain: "example.com".into(),
            sources: vec!["tailscale".into()],
            identity_assurance: IdentityAssurance::Iaa3,
            presence: PresenceInfo {
                present: true,
                attested_by: "fido2_up".into(),
                attested_at: 1_750_291_200,
                present_until: 1_750_291_500,
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
                attested_at: 0,
                present_until: 0,
            },
            auth_methods: vec![],
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iaa2\""), "got: {json}");
    }
}
