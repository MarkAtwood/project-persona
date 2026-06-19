//! Audience string parsing with optional `persona_` extension parameters.

use std::str::FromStr;

use crate::PresenceLevel;

/// Parsed persona extensions extracted from an audience string.
///
/// Audience strings may carry optional structured extensions as query parameters:
/// ```text
/// https://example.com?persona_require_presence=hardware&persona_max_age=300
/// ```
///
/// `persona_` parameters are stripped from the returned `audience` field; all
/// other query parameters are preserved.
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceExtensions {
    /// The bare audience URL with `persona_` query parameters removed.
    pub audience: String,
    /// Required presence level. Defaults to [`PresenceLevel::None`] when absent
    /// or unrecognised.
    pub require_presence: PresenceLevel,
    /// Maximum age in seconds since last presence attestation. `None` means no
    /// constraint.
    pub max_age_secs: Option<u64>,
}

/// Error returned when an audience string cannot be parsed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AudienceParseError {
    /// `persona_max_age` was present but could not be parsed as a `u64`.
    #[error("invalid persona_max_age value: {0}")]
    InvalidMaxAge(String),
}

impl AudienceExtensions {
    /// Parse an audience string, extracting `persona_` extension parameters.
    ///
    /// `persona_` query params are stripped from the returned [`AudienceExtensions::audience`].
    /// All other query params remain in the audience URL.
    ///
    /// # Errors
    ///
    /// Returns [`AudienceParseError::InvalidMaxAge`] if `persona_max_age` is
    /// present but not a valid `u64`.
    // ponytail: string split is sufficient | upgrade to url crate if multi-value params needed
    pub fn parse(raw: &str) -> Result<Self, AudienceParseError> {
        let (base, query) = match raw.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (raw, None),
        };

        let mut require_presence = PresenceLevel::None;
        let mut max_age_secs: Option<u64> = None;
        let mut kept_params: Vec<&str> = Vec::new();

        if let Some(q) = query {
            for param in q.split('&').filter(|s| !s.is_empty()) {
                if let Some(val) = param.strip_prefix("persona_require_presence=") {
                    require_presence = PresenceLevel::from_str(val)
                        .unwrap_or(PresenceLevel::None);
                } else if let Some(val) = param.strip_prefix("persona_max_age=") {
                    max_age_secs = Some(
                        val.parse::<u64>()
                            .map_err(|_| AudienceParseError::InvalidMaxAge(val.to_owned()))?,
                    );
                } else {
                    kept_params.push(param);
                }
            }
        }

        let audience = if kept_params.is_empty() {
            base.to_owned()
        } else {
            format!("{}?{}", base, kept_params.join("&"))
        };

        Ok(AudienceExtensions {
            audience,
            require_presence,
            max_age_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_url_no_extensions() {
        let ext = AudienceExtensions::parse("https://example.com").unwrap();
        assert_eq!(ext.audience, "https://example.com");
        assert_eq!(ext.require_presence, PresenceLevel::None);
        assert_eq!(ext.max_age_secs, None);
    }

    #[test]
    fn hardware_presence_and_max_age() {
        let ext = AudienceExtensions::parse(
            "https://example.com?persona_require_presence=hardware&persona_max_age=300",
        )
        .unwrap();
        assert_eq!(ext.audience, "https://example.com");
        assert_eq!(ext.require_presence, PresenceLevel::Hardware);
        assert_eq!(ext.max_age_secs, Some(300));
    }

    #[test]
    fn non_persona_params_are_kept() {
        let ext = AudienceExtensions::parse(
            "https://example.com?foo=bar&persona_require_presence=software&baz=qux",
        )
        .unwrap();
        assert_eq!(ext.audience, "https://example.com?foo=bar&baz=qux");
        assert_eq!(ext.require_presence, PresenceLevel::Software);
    }

    #[test]
    fn unknown_presence_level_defaults_to_none() {
        let ext = AudienceExtensions::parse(
            "https://example.com?persona_require_presence=biometric",
        )
        .unwrap();
        assert_eq!(ext.require_presence, PresenceLevel::None);
    }

    #[test]
    fn invalid_max_age_returns_error() {
        let err = AudienceExtensions::parse(
            "https://example.com?persona_max_age=notanumber",
        )
        .unwrap_err();
        assert!(matches!(err, AudienceParseError::InvalidMaxAge(_)));
    }

    #[test]
    fn only_persona_params_no_other_query() {
        let ext = AudienceExtensions::parse(
            "https://example.com?persona_max_age=60",
        )
        .unwrap();
        assert_eq!(ext.audience, "https://example.com");
        assert_eq!(ext.max_age_secs, Some(60));
    }
}
