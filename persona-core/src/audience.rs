//! Audience string parsing with optional `persona_` extension parameters.

use std::str::FromStr;

use crate::PresenceLevel;

/// Parsed persona extensions extracted from an audience string.
///
/// Audience strings may carry optional structured extensions as query parameters:
/// ```text
/// https://example.com?persona_require_presence=hardware
/// ```
///
/// The `persona_` query-parameter namespace is reserved and closed: every
/// `persona_` parameter is either implemented here or rejected. Nothing in that
/// namespace is ignored, so a caller is never told yes to a requirement this
/// daemon did not evaluate. `persona_` parameters are stripped from the returned
/// `audience` field; all other query parameters are preserved.
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceExtensions {
    /// The bare audience URL with `persona_` query parameters removed.
    pub audience: String,
    /// Required presence level. Defaults to [`PresenceLevel::None`] when absent.
    /// An unrecognised value is a parse error, never a default.
    pub require_presence: PresenceLevel,
}

/// Error returned when an audience string cannot be parsed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AudienceParseError {
    /// `persona_require_presence` named a level this daemon does not implement.
    #[error("unknown persona_require_presence value: {0}")]
    UnknownPresence(String),
    /// A policy name was written without its `persona_` prefix.
    #[error("{0} must be written persona_{0}; refusing to ignore a presence requirement")]
    UnprefixedExtension(String),

    /// A `persona_` parameter this daemon does not implement was present.
    #[error("unsupported persona extension: {0}")]
    UnsupportedExtension(String),
}

/// Policy names that mean something only with the `persona_` prefix.
///
/// Written bare they would be treated as ordinary query parameters and gate
/// nothing, so they are refused rather than kept.
fn is_unprefixed_policy_name(param: &str) -> bool {
    let name = param.split_once('=').map_or(param, |(n, _)| n);
    matches!(name, "require_presence" | "max_age")
}

impl AudienceExtensions {
    /// Parse an audience string, extracting `persona_` extension parameters.
    ///
    /// `persona_` query params are stripped from the returned
    /// [`AudienceExtensions::audience`]. All other query params remain in the
    /// audience URL.
    ///
    /// A repeated `persona_require_presence` raises the requirement and never
    /// relaxes one already named, so the within-string rule is the same
    /// strictest-wins rule the caller applies across audiences.
    ///
    /// # Errors
    ///
    /// - [`AudienceParseError::UnknownPresence`] if `persona_require_presence`
    ///   names a level this daemon does not implement.
    /// - [`AudienceParseError::UnprefixedExtension`] if a policy name appears
    ///   without its `persona_` prefix, which would otherwise be kept as an
    ///   ordinary query parameter and silently gate nothing.
    /// - [`AudienceParseError::UnsupportedExtension`] for any other `persona_`
    ///   parameter. `persona_max_age` is refused here: a [`crate::PresenceLevel`]
    ///   arrives with no attestation timestamp, so the daemon cannot bound
    ///   presence freshness and will not accept a parameter it would ignore.
    // ponytail: string split is sufficient | upgrade to url crate if multi-value params needed
    pub fn parse(raw: &str) -> Result<Self, AudienceParseError> {
        let (base, query) = match raw.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (raw, None),
        };

        let mut require_presence = PresenceLevel::None;
        let mut kept_params: Vec<&str> = Vec::new();

        if let Some(q) = query {
            for param in q.split('&').filter(|s| !s.is_empty()) {
                if let Some(val) = param.strip_prefix("persona_require_presence=") {
                    let level = PresenceLevel::from_str(val)
                        .map_err(|_| AudienceParseError::UnknownPresence(val.to_owned()))?;
                    require_presence = require_presence.max(level);
                } else if param.starts_with("persona_") {
                    let name = param.split_once('=').map_or(param, |(n, _)| n);
                    return Err(AudienceParseError::UnsupportedExtension(name.to_owned()));
                } else if is_unprefixed_policy_name(param) {
                    // A policy name written without the `persona_` prefix. Keeping it
                    // would put a security parameter in the ordinary-query bucket, so
                    // the daemon would apply no gate, issue the token, and sign the
                    // caller's own requirement into `aud` as though it had been
                    // honoured. That is the fail-open this parser exists to remove,
                    // reachable by a spelling slip. Refuse instead.
                    let name = param.split_once('=').map_or(param, |(n, _)| n);
                    return Err(AudienceParseError::UnprefixedExtension(name.to_owned()));
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
    }

    #[test]
    fn hardware_presence_is_parsed() {
        let ext =
            AudienceExtensions::parse("https://example.com?persona_require_presence=hardware")
                .unwrap();
        assert_eq!(ext.audience, "https://example.com");
        assert_eq!(ext.require_presence, PresenceLevel::Hardware);
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
    fn unknown_presence_level_is_rejected() {
        let err =
            AudienceExtensions::parse("https://example.com?persona_require_presence=biometric")
                .unwrap_err();
        assert!(matches!(err, AudienceParseError::UnknownPresence(_)));
    }

    #[test]
    fn capitalised_presence_level_is_rejected() {
        let err =
            AudienceExtensions::parse("https://example.com?persona_require_presence=Hardware")
                .unwrap_err();
        assert!(matches!(err, AudienceParseError::UnknownPresence(_)));
    }

    #[test]
    fn empty_presence_value_is_rejected() {
        let err =
            AudienceExtensions::parse("https://example.com?persona_require_presence=").unwrap_err();
        assert!(matches!(err, AudienceParseError::UnknownPresence(_)));
    }

    #[test]
    fn repeated_presence_key_takes_the_strictest() {
        let strict_last = AudienceExtensions::parse(
            "https://example.com?persona_require_presence=none&persona_require_presence=hardware",
        )
        .unwrap();
        let strict_first = AudienceExtensions::parse(
            "https://example.com?persona_require_presence=hardware&persona_require_presence=none",
        )
        .unwrap();
        assert_eq!(strict_last.require_presence, PresenceLevel::Hardware);
        assert_eq!(strict_first.require_presence, PresenceLevel::Hardware);
    }

    #[test]
    fn max_age_is_refused_as_unsupported() {
        let err = AudienceExtensions::parse("https://example.com?persona_max_age=300").unwrap_err();
        assert!(matches!(err, AudienceParseError::UnsupportedExtension(_)));
    }

    #[test]
    fn unknown_persona_parameter_is_rejected() {
        let err =
            AudienceExtensions::parse("https://example.com?persona_require_tpm=true").unwrap_err();
        assert!(matches!(err, AudienceParseError::UnsupportedExtension(_)));
    }

    #[test]
    fn only_persona_params_no_other_query() {
        let ext = AudienceExtensions::parse("https://example.com?persona_require_presence=session")
            .unwrap();
        assert_eq!(ext.audience, "https://example.com");
        assert_eq!(ext.require_presence, PresenceLevel::Session);
    }

    #[test]
    fn unprefixed_require_presence_is_refused_not_kept() {
        // Documented for a while as `require_presence=hardware`. Without the prefix it
        // would land in the ordinary-query bucket and gate nothing, so a caller asking
        // for hardware presence would be issued a token with none.
        let err = AudienceExtensions::parse("https://app.example?require_presence=hardware")
            .expect_err("a bare policy name must not be silently kept");
        assert!(
            matches!(err, AudienceParseError::UnprefixedExtension(ref n) if n == "require_presence"),
            "got {err:?}"
        );
    }

    #[test]
    fn unprefixed_max_age_is_refused_not_kept() {
        let err = AudienceExtensions::parse("https://app.example?max_age=60")
            .expect_err("a bare policy name must not be silently kept");
        assert!(
            matches!(err, AudienceParseError::UnprefixedExtension(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn ordinary_query_params_are_still_kept() {
        // The guard names two policy words only; unrelated query params pass through.
        let ext = AudienceExtensions::parse("https://app.example?tenant=acme&region=eu")
            .expect("ordinary params must survive");
        assert_eq!(ext.audience, "https://app.example?tenant=acme&region=eu");
        assert_eq!(ext.require_presence, PresenceLevel::None);
    }
}
