//! The `hint` tag on a JWT-SVID: what a caller reads to choose among several.
//!
//! `proto/spiffe/workload/workload.proto` defines `hint` as operator guidance
//! "when more than one SVID is returned", and the hire-jl4j decision makes it
//! NORMATIVE: the order SVIDs arrive in is documented but advisory, and this
//! tag is what a caller gates on. So it has to be machine-readable, and it has
//! to say enough to choose with.
//!
//! ```text
//! source=tailscale&identity_assurance=iaa2&presence=none&age=3
//! ```
//!
//! NO NEW VOCABULARY. Every name here is one a caller already meets somewhere
//! else: `source` and `identity_assurance` are field names in the `hire` claim
//! block, `presence` takes the same four values as `hire_require_presence` in
//! an audience string, and `age` is in seconds like `hire_max_age`. A caller
//! reading the tag and a caller decoding the token learn the same things by the
//! same names, which is the only reason a second encoding is tolerable at all.
//!
//! FOUR FIELDS, NOT ONE NUMBER. hire-3tly.5 holds that presence is at least
//! three independent axes and that a stale hardware touch and a live session
//! have no honest ordering, so nothing here reduces to a score. A caller that
//! wants "hardware presence, under a minute old" reads two fields and decides;
//! it is not told which SVID is "best".
//!
//! `source` NAMES THE ATTESTOR, not the authentication method. `Claim::source()`
//! is what the daemon actually has, and `auth_methods` in the claim block is
//! today the same single-element expression as `sources` — hire-5s4b.129 is the
//! bead that separates them. This tag deliberately does not race that: when
//! `auth_methods` becomes a distinct thing, adding it here is a new key, not a
//! change to the meaning of this one.
//!
//! The query-parameter shape matches the audience-extension syntax this crate
//! already parses, rather than inventing a third spelling.

use std::fmt;
use std::str::FromStr;

use crate::{IdentityAssurance, PresenceLevel};

/// The machine-readable `hint` on an issued JWT-SVID.
///
/// Public fields and no `#[non_exhaustive]`, matching [`AudienceExtensions`]
/// next door: both are parsed value types a caller is meant to read field by
/// field, and both are built by name, so a field added later stops the
/// construction sites compiling rather than being silently defaulted.
///
/// [`AudienceExtensions`]: crate::AudienceExtensions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvidHint {
    /// The attestor that produced the claim, e.g. `"tailscale"`, `"gpg"`.
    pub source: String,
    /// The tier the evidence established.
    pub identity_assurance: IdentityAssurance,
    /// The presence level the evidence established, after TTL decay.
    pub presence: PresenceLevel,
    /// Age in whole seconds of the observation behind the claim, at issuance.
    pub age: u64,
}

/// Error returned when a `hint` cannot be parsed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HintParseError {
    /// A key appeared that this encoding does not define.
    #[error("unknown hint key: {0}")]
    UnknownKey(String),
    /// A key appeared twice, so which value applies is undefined.
    #[error("repeated hint key: {0}")]
    RepeatedKey(String),
    /// A required key was absent.
    #[error("hint is missing {0}")]
    Missing(&'static str),
    /// A value was not of the form its key requires.
    #[error("hint {key} is not valid: {value}")]
    BadValue {
        /// The key whose value did not parse.
        key: String,
        /// The value as it appeared.
        value: String,
    },
}

impl fmt::Display for SvidHint {
    /// Writes the tag in the documented field order.
    ///
    /// The order is fixed so two daemons emit byte-identical tags for identical
    /// claims, which keeps the tag usable as a map key. [`FromStr`] does not
    /// depend on it: a parser that required an order would break the first time
    /// a field was added.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={}&identity_assurance={}&presence={}&age={}",
            self.source, self.identity_assurance, self.presence, self.age
        )
    }
}

impl FromStr for SvidHint {
    type Err = HintParseError;

    /// Parses a tag, refusing anything it does not fully understand.
    ///
    /// An unknown key is an error rather than something to skip, for the reason
    /// the `hire_` audience namespace is closed: a caller gating on this tag
    /// must never be told yes by a daemon that carried a field the caller could
    /// not see. A repeated key is an error for the same reason — first-wins and
    /// last-wins are both defensible, which is what makes silently picking one
    /// indefensible.
    ///
    /// # Errors
    ///
    /// - [`HintParseError::UnknownKey`] for a key this encoding does not define.
    /// - [`HintParseError::RepeatedKey`] for a key that appears twice.
    /// - [`HintParseError::Missing`] when any of the four fields is absent.
    /// - [`HintParseError::BadValue`] when a value does not parse as its key
    ///   requires.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let mut source: Option<String> = None;
        let mut identity_assurance: Option<IdentityAssurance> = None;
        let mut presence: Option<PresenceLevel> = None;
        let mut age: Option<u64> = None;

        for param in raw.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = param
                .split_once('=')
                .ok_or_else(|| HintParseError::UnknownKey(param.to_owned()))?;
            let bad = || HintParseError::BadValue {
                key: key.to_owned(),
                value: value.to_owned(),
            };
            let repeated = || HintParseError::RepeatedKey(key.to_owned());

            match key {
                "source" => {
                    if source.replace(value.to_owned()).is_some() {
                        return Err(repeated());
                    }
                }
                "identity_assurance" => {
                    if identity_assurance
                        .replace(value.parse().map_err(|_| bad())?)
                        .is_some()
                    {
                        return Err(repeated());
                    }
                }
                "presence" => {
                    if presence
                        .replace(value.parse().map_err(|_| bad())?)
                        .is_some()
                    {
                        return Err(repeated());
                    }
                }
                "age" => {
                    if age.replace(value.parse().map_err(|_| bad())?).is_some() {
                        return Err(repeated());
                    }
                }
                other => return Err(HintParseError::UnknownKey(other.to_owned())),
            }
        }

        Ok(SvidHint {
            source: source.ok_or(HintParseError::Missing("source"))?,
            identity_assurance: identity_assurance
                .ok_or(HintParseError::Missing("identity_assurance"))?,
            presence: presence.ok_or(HintParseError::Missing("presence"))?,
            age: age.ok_or(HintParseError::Missing("age"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(source: &str, assurance: &str, presence: &str, age: u64) -> SvidHint {
        SvidHint {
            source: source.to_owned(),
            identity_assurance: assurance.parse().unwrap(),
            presence: presence.parse().unwrap(),
            age,
        }
    }

    /// One tag per source that can actually prove today, written out as a
    /// caller would see it. These are the acceptance criterion of hire-jl4j.1
    /// and they double as the documentation of the encoding.
    #[test]
    fn tags_for_every_provable_source() {
        let cases = [
            (
                hint("tailscale", "iaa2", "none", 3),
                "source=tailscale&identity_assurance=iaa2&presence=none&age=3",
            ),
            (
                hint("unix", "iaa1", "none", 0),
                "source=unix&identity_assurance=iaa1&presence=none&age=0",
            ),
            (
                hint("ssh-agent", "iaa1", "none", 0),
                "source=ssh-agent&identity_assurance=iaa1&presence=none&age=0",
            ),
            (
                hint("gpg", "iaa1", "none", 1),
                "source=gpg&identity_assurance=iaa1&presence=none&age=1",
            ),
            (
                // A source name containing a colon, which is why values are not
                // further escaped: `&` and `=` are the only characters that
                // would break parsing and no attestor name contains either.
                hint("did:key", "iaa1", "none", 0),
                "source=did:key&identity_assurance=iaa1&presence=none&age=0",
            ),
            (
                // Not reachable today -- no attestor establishes presence -- and
                // written down anyway, because this is the case the tag exists
                // for: a caller gating on hardware presence reads two fields.
                hint("fido2", "iaa3", "hardware", 12),
                "source=fido2&identity_assurance=iaa3&presence=hardware&age=12",
            ),
        ];

        for (parsed, encoded) in cases {
            assert_eq!(parsed.to_string(), encoded, "encode");
            assert_eq!(encoded.parse::<SvidHint>().unwrap(), parsed, "decode");
        }
    }

    #[test]
    fn field_order_does_not_matter_when_parsing() {
        let forwards = "source=gpg&identity_assurance=iaa1&presence=none&age=7";
        let backwards = "age=7&presence=none&identity_assurance=iaa1&source=gpg";
        assert_eq!(
            forwards.parse::<SvidHint>().unwrap(),
            backwards.parse::<SvidHint>().unwrap()
        );
        // But encoding has exactly one spelling, so the tag is a usable key.
        assert_eq!(backwards.parse::<SvidHint>().unwrap().to_string(), forwards);
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        // The closed-namespace rule the audience parser already applies: a
        // caller gating on this tag must never be told yes by a daemon that
        // carried a field the caller could not see.
        let extra = "source=gpg&identity_assurance=iaa1&presence=none&age=0&attested_by=nobody";
        assert_eq!(
            extra.parse::<SvidHint>().unwrap_err(),
            HintParseError::UnknownKey("attested_by".to_owned())
        );
        assert!(matches!(
            "source".parse::<SvidHint>().unwrap_err(),
            HintParseError::UnknownKey(_)
        ));
    }

    #[test]
    fn a_repeated_key_is_refused_rather_than_resolved() {
        // First-wins and last-wins are both defensible, which is exactly what
        // makes silently picking one indefensible -- and the interesting case
        // is an appended `presence=hardware` raising what a caller reads.
        let doubled = "source=gpg&identity_assurance=iaa1&presence=none&age=0&presence=hardware";
        assert_eq!(
            doubled.parse::<SvidHint>().unwrap_err(),
            HintParseError::RepeatedKey("presence".to_owned())
        );
    }

    #[test]
    fn every_field_is_required() {
        let full = "source=gpg&identity_assurance=iaa1&presence=none&age=0";
        for (drop, name) in [
            ("source=gpg&", "source"),
            ("identity_assurance=iaa1&", "identity_assurance"),
            ("presence=none&", "presence"),
            ("&age=0", "age"),
        ] {
            let partial = full.replace(drop, "");
            assert_ne!(partial, full, "fixture edit did not apply for {name}");
            assert_eq!(
                partial.parse::<SvidHint>().unwrap_err(),
                HintParseError::Missing(name),
            );
        }
    }

    #[test]
    fn a_value_outside_its_vocabulary_is_refused() {
        // `iaa4` and `present` are the plausible mistakes: a tier this daemon
        // does not implement, and the boolean from the claim block's
        // `presence.present` written where a level belongs.
        for (raw, key) in [
            (
                "source=gpg&identity_assurance=iaa4&presence=none&age=0",
                "identity_assurance",
            ),
            (
                "source=gpg&identity_assurance=iaa1&presence=present&age=0",
                "presence",
            ),
            (
                "source=gpg&identity_assurance=iaa1&presence=none&age=-1",
                "age",
            ),
            (
                "source=gpg&identity_assurance=iaa1&presence=none&age=",
                "age",
            ),
        ] {
            let err = raw.parse::<SvidHint>().unwrap_err();
            assert!(
                matches!(&err, HintParseError::BadValue { key: k, .. } if k == key),
                "{raw} gave {err:?}"
            );
        }
    }
}
