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
}

/// The trust domain portion of a SPIFFE ID.
///
/// Each variant maps to a canonical string form used in the URI authority.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TrustDomain {
    /// Tailscale network identity (`tailscale`).
    Tailscale,

    /// Organisation OIDC IdP, identified by its domain (e.g. `example.com`).
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
            TrustDomain::OrgOidc(domain) => f.write_str(domain),
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
    /// Returns `Some("source")` if the path ends with `via/{source}`, otherwise
    /// `None`.
    pub fn provenance(&self) -> Option<&str> {
        let (prefix, source) = self.path.rsplit_once('/')?;
        if prefix.ends_with("via") || prefix == "via" {
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
    /// This is a documented deviation from SPEC-HIA.md:79.
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

        let trust_domain = parse_trust_domain(td_str);
        Ok(SpiffeId::new(trust_domain, path))
    }
}

/// Heuristic parse of a trust-domain string into the appropriate variant.
///
/// Because the serialised form is lossy for `OrgOidc` vs bare strings, we use
/// structural prefixes to distinguish variants.
fn parse_trust_domain(s: &str) -> TrustDomain {
    match s {
        "tailscale" => TrustDomain::Tailscale,
        "ssh.local" => TrustDomain::SshLocal,
        "pgp.local" => TrustDomain::PgpLocal,
        other => {
            if let Some(did) = other.strip_prefix("personal.") {
                TrustDomain::PersonalDid(did.to_owned())
            } else if let Some(issuer) = other.strip_prefix("piv.") {
                TrustDomain::PivIssuer(issuer.to_owned())
            } else {
                TrustDomain::OrgOidc(other.to_owned())
            }
        }
    }
}
