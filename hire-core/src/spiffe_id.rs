//! SPIFFE ID types and trust domain model.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when parsing a SPIFFE URI fails.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SpiffeIdError {
    /// The URI did not start with the `spiffe://` scheme.
    #[error("missing spiffe:// scheme")]
    MissingScheme,

    /// The URI had no trust domain component.
    #[error("missing trust domain")]
    MissingTrustDomain,

    /// The path component was absent (must have at least one `/`).
    #[error("missing path")]
    MissingPath,

    /// The authority named no trust domain this daemon knows.
    ///
    /// Carries the authority as it appeared. It is attacker-supplied in the one
    /// place a SPIFFE ID is parsed from outside — `ValidateJWTSVID` reads it
    /// out of an unverified token — so it belongs in a log, never in a reply.
    #[error("unknown trust domain: {0}")]
    UnknownTrustDomain(String),

    /// The authority contained a character a SPIFFE trust domain may not.
    #[error("illegal character in trust domain: {0}")]
    IllegalTrustDomain(String),
}

/// The trust domain portion of a SPIFFE ID.
///
/// EVERY VARIANT OWNS A RESERVED AUTHORITY, and that is what makes [`Display`]
/// injective: two distinct trust domains cannot share a string form, so
/// `id.uri().parse()` gives back the trust domain it started with. Before
/// hire-5s4b.37, `OrgOidc` displayed as the bare issuer domain and swallowed
/// every authority that matched no other rule, so `OrgOidc("tailscale")` came
/// back as `Tailscale` and an IdP at `piv.acme.example` minted SPIFFE IDs that
/// anyone re-parsing read as a PIV smart-card domain — a different and
/// higher-trust source. The string goes into the SVID subject and into the
/// trust-bundle key, so the collision was reachable from a cached token's `iss`.
///
/// An authority in no reserved namespace is therefore not one of ours and does
/// not parse. That is a constraint rather than a gap: hire has no bundle for a
/// domain it did not mint, so the alternative is a value that parses and then
/// fails at the next step. SPIFFE Federation, when it lands, adds a variant
/// with its own reserved prefix — which is what `#[non_exhaustive]` is for.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TrustDomain {
    /// Tailscale network identity (`tailscale`).
    Tailscale,

    /// Organisation OIDC IdP, identified by its domain (`oidc.{domain}`).
    OrgOidc(String),

    /// Personal DID-based identity (`personal.{did}`).
    PersonalDid(String),

    /// PIV smart-card issuer (`piv.{issuer}`).
    PivIssuer(String),

    /// Locally-enrolled SSH key (`ssh.local`).
    SshLocal,

    /// Locally-enrolled PGP key (`pgp.local`).
    PgpLocal,
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustDomain::Tailscale => f.write_str("tailscale"),
            TrustDomain::OrgOidc(domain) => write!(f, "oidc.{domain}"),
            TrustDomain::PersonalDid(did) => write!(f, "personal.{did}"),
            TrustDomain::PivIssuer(issuer) => write!(f, "piv.{issuer}"),
            TrustDomain::SshLocal => f.write_str("ssh.local"),
            TrustDomain::PgpLocal => f.write_str("pgp.local"),
        }
    }
}

/// A SPIFFE ID of the form `spiffe://{trust_domain}/{path}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    /// The trust domain authority component.
    pub trust_domain: TrustDomain,

    /// The path component (everything after the trust-domain slash, without a
    /// leading `/`).
    pub path: String,
}

impl SpiffeId {
    /// Construct a new `SpiffeId` from a trust domain and path.
    ///
    /// `path` should not include a leading `/`.
    pub fn new(trust_domain: TrustDomain, path: impl Into<String>) -> Self {
        SpiffeId {
            trust_domain,
            path: path.into(),
        }
    }

    /// Returns the canonical SPIFFE URI, e.g. `spiffe://tailscale/user/alice`.
    pub fn uri(&self) -> String {
        format!("spiffe://{}/{}", self.trust_domain, self.path)
    }

    /// Extracts the source name from a `via/{source}` tail segment in the path.
    ///
    /// Returns `Some(source)` if the path ends with `via/{source}`, otherwise
    /// `None`. `via` must be a whole path segment: `user/trivia/x` is not a
    /// provenance-bearing path and yields `None`.
    ///
    /// This names the identity source that produced a claim, and a `SpiffeId`
    /// can be parsed from a URI this daemon did not mint, so the segment
    /// boundary is what stops an arbitrary tail segment being read as a source.
    pub fn provenance(&self) -> Option<&str> {
        let (prefix, source) = self.path.rsplit_once('/')?;
        if prefix == "via" || prefix.ends_with("/via") {
            Some(source)
        } else {
            None
        }
    }

    /// Constructs a pseudonymous `SpiffeId` with path `pseudonym/{hkdf_id}`.
    ///
    /// There is deliberately no `for/{consumer}` tail. `hkdf_id` is already
    /// per-consumer, so the tail would tell the consumer only what it already
    /// knows, while telling every relying party the token is shown to which
    /// binary asked for it. `ConsumerIdentity::selector_key` also contains `:`,
    /// which is not a legal SPIFFE path-segment character.
    ///
    /// This is a documented deviation from SPEC-HIRE.md:79.
    pub fn pseudonymous(trust_domain: TrustDomain, hkdf_id: &str) -> SpiffeId {
        SpiffeId::new(trust_domain, format!("pseudonym/{hkdf_id}"))
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri())
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or(SpiffeIdError::MissingScheme)?;

        let (td_str, path) = rest.split_once('/').ok_or(SpiffeIdError::MissingPath)?;

        if td_str.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }
        if path.is_empty() {
            return Err(SpiffeIdError::MissingPath);
        }

        Ok(SpiffeId::new(td_str.parse()?, path))
    }
}

impl FromStr for TrustDomain {
    type Err = SpiffeIdError;

    /// The exact inverse of [`Display`], and nothing else.
    ///
    /// Public because a trust-domain string is what a caller actually holds:
    /// `TrustBundleStore::get` and the `FetchJWTBundles` map keys hand one
    /// back, and before this there was no way to turn one into a
    /// [`TrustDomain`] at all.
    ///
    /// # Errors
    ///
    /// - [`SpiffeIdError::MissingTrustDomain`] for the empty string.
    /// - [`SpiffeIdError::IllegalTrustDomain`] for anything outside
    ///   `[a-z0-9.-_]`, which is the character set the SPIFFE specification
    ///   allows in a trust domain. Checked before the namespace match, so an
    ///   authority carrying a `/` or a `%` is refused as malformed rather than
    ///   being reported as an unknown domain.
    /// - [`SpiffeIdError::UnknownTrustDomain`] for a well-formed authority in
    ///   no reserved namespace, and for a reserved prefix with nothing after it
    ///   (`oidc.` names no issuer).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b))
        {
            return Err(SpiffeIdError::IllegalTrustDomain(s.to_owned()));
        }

        let unknown = || SpiffeIdError::UnknownTrustDomain(s.to_owned());
        match s {
            "tailscale" => Ok(TrustDomain::Tailscale),
            "ssh.local" => Ok(TrustDomain::SshLocal),
            "pgp.local" => Ok(TrustDomain::PgpLocal),
            // `split_once`, not `strip_prefix`: the remainder must be non-empty
            // and the prefix must be a whole label, so `personalx.example` is
            // unknown rather than a DID called `x.example`.
            other => match other.split_once('.') {
                Some(("personal", did)) if !did.is_empty() => {
                    Ok(TrustDomain::PersonalDid(did.to_owned()))
                }
                Some(("piv", issuer)) if !issuer.is_empty() => {
                    Ok(TrustDomain::PivIssuer(issuer.to_owned()))
                }
                Some(("oidc", domain)) if !domain.is_empty() => {
                    Ok(TrustDomain::OrgOidc(domain.to_owned()))
                }
                _ => Err(unknown()),
            },
        }
    }
}

#[cfg(test)]
mod trust_domain_tests {
    use super::*;

    /// Every variant, each with a remainder chosen to be another variant's
    /// namespace where one exists. Adding a variant without adding it here
    /// leaves its string form untested — which is the failure this bead is
    /// about, so the list is written out rather than derived.
    fn every_variant() -> Vec<TrustDomain> {
        vec![
            TrustDomain::Tailscale,
            TrustDomain::SshLocal,
            TrustDomain::PgpLocal,
            TrustDomain::OrgOidc("example.com".into()),
            // The three collisions hire-5s4b.37 names. Each one used to display
            // as another variant's reserved form and parse back as that variant.
            TrustDomain::OrgOidc("tailscale".into()),
            TrustDomain::OrgOidc("personal.example".into()),
            TrustDomain::OrgOidc("piv.acme.example".into()),
            TrustDomain::PersonalDid("example".into()),
            TrustDomain::PivIssuer("acme.example".into()),
        ]
    }

    #[test]
    fn the_string_form_round_trips() {
        for td in every_variant() {
            let rendered = td.to_string();
            assert_eq!(
                rendered.parse::<TrustDomain>().expect(&rendered),
                td,
                "{rendered}"
            );
        }
    }

    #[test]
    fn the_string_form_is_injective() {
        // The property behind the round trip: no two trust domains share a
        // string. A round trip alone would still pass if two variants mapped to
        // one string and that string parsed back to one of them.
        let mut rendered: Vec<String> = every_variant().iter().map(|td| td.to_string()).collect();
        let before = rendered.len();
        rendered.sort();
        rendered.dedup();
        assert_eq!(
            rendered.len(),
            before,
            "two trust domains share a string form"
        );
    }

    #[test]
    fn an_issuer_cannot_name_another_variants_namespace() {
        // The reachable case: oidc.rs takes `iss` out of a cached token, so the
        // domain is attacker-influenced. An IdP at piv.acme.example must not
        // mint SPIFFE IDs a relying party reads as a PIV smart-card domain.
        let id = SpiffeId::new(TrustDomain::OrgOidc("piv.acme.example".into()), "user/mark");
        let reparsed: SpiffeId = id.uri().parse().expect("must parse");
        assert_eq!(reparsed, id);
        assert_ne!(
            reparsed.trust_domain,
            TrustDomain::PivIssuer("acme.example".into())
        );
    }

    #[test]
    fn an_authority_in_no_reserved_namespace_does_not_parse() {
        // What used to be swallowed as OrgOidc. hired holds no bundle for a
        // domain it did not mint, so parsing it would only defer the failure.
        for authority in [
            "example.com",
            "localhost",
            "tailscale.com",
            "personal",
            "piv",
        ] {
            assert_eq!(
                authority.parse::<TrustDomain>().unwrap_err(),
                SpiffeIdError::UnknownTrustDomain(authority.to_owned()),
                "{authority}"
            );
        }
        // A reserved prefix naming nothing, and a prefix that is not a whole
        // label: `personalx.example` is not a DID called `x.example`.
        for authority in [
            "oidc.",
            "personal.",
            "piv.",
            "personalx.example",
            "oidcx.example",
        ] {
            assert!(
                matches!(
                    authority.parse::<TrustDomain>(),
                    Err(SpiffeIdError::UnknownTrustDomain(_))
                ),
                "{authority}"
            );
        }
    }

    #[test]
    fn an_authority_outside_the_spiffe_character_set_is_malformed() {
        // Refused as malformed rather than reported as unknown, so a caller can
        // tell "not a trust domain at all" from "not one of ours". Uppercase is
        // the interesting one: SPIFFE trust domains are lowercase, and a parser
        // that case-folded would make `OIDC.example.com` a second spelling of a
        // domain and break injectivity through the back door.
        for authority in [
            "OIDC.example.com",
            "oidc.Example.com",
            "oidc.a/b",
            "oidc.a%2fb",
        ] {
            assert_eq!(
                authority.parse::<TrustDomain>().unwrap_err(),
                SpiffeIdError::IllegalTrustDomain(authority.to_owned()),
                "{authority}"
            );
        }
        assert_eq!(
            "".parse::<TrustDomain>().unwrap_err(),
            SpiffeIdError::MissingTrustDomain
        );
    }

    #[test]
    fn spiffe_id_parsing_refuses_an_unknown_authority() {
        // The one place a SPIFFE ID is parsed from outside is ValidateJWTSVID,
        // reading it out of an unverified token.
        assert_eq!(
            "spiffe://example.com/user/mark"
                .parse::<SpiffeId>()
                .unwrap_err(),
            SpiffeIdError::UnknownTrustDomain("example.com".to_owned())
        );
        assert!("spiffe://oidc.example.com/user/mark"
            .parse::<SpiffeId>()
            .is_ok());
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    /// URIs quoted verbatim from SPEC-HIRE.md, which defines the path form as
    /// `spiffe://{trust-domain}/user/{sub}/via/{source}` at line 69.
    #[test]
    fn reads_the_source_from_the_forms_the_spec_gives() {
        for (uri, source) in [
            // SPEC-HIRE.md:74
            (
                "spiffe://oidc.example.com/user/mark/via/google-workspace",
                "google-workspace",
            ),
            // SPEC-HIRE.md:77
            (
                "spiffe://oidc.example.com/user/mark/via/piv-smartcard",
                "piv-smartcard",
            ),
            // SPEC-HIRE.md:653
            (
                "spiffe://oidc.example.com/user/mark/via/tailscale",
                "tailscale",
            ),
        ] {
            let id = SpiffeId::from_str(uri).expect("the spec's own URI must parse");
            assert_eq!(id.provenance(), Some(source), "{uri}");
        }
    }

    #[test]
    fn reads_the_source_the_oidc_attestor_actually_mints() {
        // hire-attestors/src/oidc.rs:80 builds "user/{sub}/via/oidc-cached".
        let id = SpiffeId::new(
            TrustDomain::OrgOidc("example.com".into()),
            "user/mark/via/oidc-cached",
        );
        assert_eq!(id.provenance(), Some("oidc-cached"));
    }

    #[test]
    fn via_alone_is_a_prefix() {
        let id = SpiffeId::new(TrustDomain::SshLocal, "via/ssh-agent");
        assert_eq!(id.provenance(), Some("ssh-agent"));
    }

    #[test]
    fn a_segment_merely_ending_in_via_is_not_a_provenance_marker() {
        // The predicate used to be prefix.ends_with("via"), which is true of any
        // segment with that suffix. provenance() names the identity source that
        // produced a claim, and a SpiffeId can be parsed from a URI this daemon
        // did not mint, so these must not report a source.
        for path in ["user/trivia/x", "user/alice/servia/bob", "user/bolivia/c"] {
            let id = SpiffeId::new(TrustDomain::SshLocal, path);
            assert_eq!(id.provenance(), None, "{path} has no via/ segment");
        }
    }

    #[test]
    fn a_path_with_no_via_segment_has_no_provenance() {
        for path in [
            "user/alice",
            "alice",
            "pseudonym/abcdef",
            "user/alice/for/app",
        ] {
            let id = SpiffeId::new(TrustDomain::SshLocal, path);
            assert_eq!(id.provenance(), None, "{path}");
        }
    }
}
