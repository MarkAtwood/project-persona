//! Discovery output ([`Candidate`]) and proof output ([`Claim`]).
//!
//! `Claim` lives in this module rather than in `lib.rs`, and that placement is
//! the security boundary. Rust privacy is "visible in the defining module and
//! all its descendants": private fields on a struct declared in the crate root
//! stay writable from `fido2.rs`, because every attestor module is a descendant
//! of the root. Declared here, the attestor modules are siblings and a struct
//! literal is `error[E0451]: field ... is private`.
//!
//! Do not move `Claim` back into `lib.rs`. Nothing fails loudly if you do; the
//! guarantee just silently disappears.

use std::time::SystemTime;

use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::SignedAssertion;

/// A trust domain an attestor may name about itself with no evidence at all.
///
/// Deliberately narrower than [`TrustDomain`]: the issuer-anchored variants
/// (`OrgOidc`, `PivIssuer`) are absent, because naming an issuer is a claim
/// about a third party and may come only from verified evidence. This is why
/// `oidc.rs` can no longer write `TrustDomain::OrgOidc(extract_domain(&iss))`
/// in `enumerate()` — the variant does not exist here (persona-5s4b.55).
///
/// A future `TrustDomain` variant is unavailable to candidates until someone
/// adds it here deliberately. That failure mode is closed, which is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAssertedDomain {
    /// Tailscale network identity.
    Tailscale,
    /// Locally-enrolled SSH key.
    SshLocal,
    /// Locally-enrolled PGP key.
    PgpLocal,
    /// Personal DID-based identity.
    PersonalDid(String),
}

impl From<SelfAssertedDomain> for TrustDomain {
    fn from(d: SelfAssertedDomain) -> Self {
        match d {
            SelfAssertedDomain::Tailscale => TrustDomain::Tailscale,
            SelfAssertedDomain::SshLocal => TrustDomain::SshLocal,
            SelfAssertedDomain::PgpLocal => TrustDomain::PgpLocal,
            SelfAssertedDomain::PersonalDid(did) => TrustDomain::PersonalDid(did),
        }
    }
}

/// An identity an attestor can see. Discovery is not proof: a candidate has no
/// assurance and no presence, because nothing has been verified yet.
///
/// Fields are public on purpose. A candidate carries nothing privileged, so
/// there is nothing here to protect; its *shape* is the constraint.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Attestor source name, e.g. `"tailscale"`, `"fido2"`, `"ssh-agent"`.
    pub source: String,
    /// The self-asserted trust domain this candidate would sit under.
    pub domain: SelfAssertedDomain,
    /// SPIFFE path component, without a leading `/`.
    pub path: String,
    /// Human-readable display name.
    pub display_name: String,
}

impl Candidate {
    /// Construct a new [`Candidate`].
    pub fn new(
        source: impl Into<String>,
        domain: SelfAssertedDomain,
        path: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            domain,
            path: path.into(),
            display_name: display_name.into(),
        }
    }

    /// The SPIFFE ID this candidate would map to if nothing further is proven.
    ///
    /// A proven [`Claim`] may sit under a different trust domain: a verified
    /// token re-anchors it to the issuer. See [`Claim::derive`].
    pub fn spiffe_id(&self) -> SpiffeId {
        SpiffeId::new(self.domain.clone().into(), self.path.clone())
    }
}

/// A signature over a daemon-generated challenge by the key a candidate names.
///
/// Establishes possession and nothing more, so this is the one evidence payload
/// with an ungated constructor: it maps to the floor tier, and no gate can lower
/// a floor. An attestor that has already discovered an identity is entitled to
/// self-assert it; this type only forces that assertion to arrive through
/// `prove()` rather than through `enumerate()`.
#[derive(Debug, Clone)]
pub struct ChallengeSignature {
    assertion: SignedAssertion,
}

impl ChallengeSignature {
    /// Wrap a signed assertion produced in response to a challenge.
    ///
    /// This constructor is public, unlike those of [`VerifiedToken`] and
    /// [`HardwareTouch`], so an attestor inside this workspace can build one without
    /// the signature having been checked against anything. That is deliberate and it is
    /// the weakest point of the type: it buys the floor tier only, `Iaa1` with no
    /// presence, and it keeps the end-to-end issuance path testable while no attestor
    /// can really prove. `Iaa2` and `Iaa3` stay unreachable from outside this module
    /// because their payloads have no public constructor.
    ///
    /// Verifying the assertion against the challenge is persona-5s4b.116.
    pub fn new(assertion: SignedAssertion) -> Self {
        Self { assertion }
    }

    /// The underlying signed assertion.
    pub fn assertion(&self) -> &SignedAssertion {
        &self.assertion
    }
}

/// An identity token whose signature was checked against the issuer's key.
///
/// There is deliberately no public constructor: nothing in this workspace can
/// verify a token signature yet, so nothing may claim it did. The unit tests in
/// this module build one by struct literal, because they are a descendant of
/// this module — that is the only construction path today.
///
/// ponytail: no verifying constructor until there is a verifier | ceiling: Iaa2
/// and issuer-anchored trust domains are unreachable, so oidc contributes at the
/// floor at best | upgrade path: add
/// `pub fn verify(raw: &str, key: &DecodingKey, v: &Validation) -> Result<Self, _>`
/// here, next to the JWKS cache that makes it possible — and nowhere else.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    issuer_domain: String,
}

impl VerifiedToken {
    /// The issuer domain taken from the token's verified `iss` claim.
    pub fn issuer_domain(&self) -> &str {
        &self.issuer_domain
    }
}

/// An authenticator assertion whose user-present bit was observed set, and the
/// moment the daemon observed it.
///
/// No public constructor, for the same reason as [`VerifiedToken`]: no attestor
/// can obtain a hardware assertion yet.
///
/// ponytail: no constructor until an authenticator can actually be driven |
/// ceiling: `PresenceLevel::Hardware` and Iaa3 are unreachable | upgrade path:
/// add one constructor per authenticator family here — CTAP2 (`rpIdHash[32] ||
/// flags[1] || signCount[4]`, UP is bit 0 of flags) and PKCS#11 slot 9A have
/// different witnesses, so do not force one byte layout on both.
#[derive(Debug, Clone)]
pub struct HardwareTouch {
    touched_at: SystemTime,
}

impl HardwareTouch {
    /// When the daemon observed the touch.
    pub fn touched_at(&self) -> SystemTime {
        self.touched_at
    }
}

/// Verified evidence supporting a candidate, produced by
/// [`Attestor::prove`](crate::Attestor::prove).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Evidence {
    /// The candidate's key signed our challenge.
    Possession(ChallengeSignature),
    /// An identity provider vouched for the candidate, signature checked.
    IdpVerified(VerifiedToken),
    /// A human touched an authenticator.
    HardwarePresence(HardwareTouch),
}

impl Evidence {
    /// The single place a piece of evidence is mapped to a tier.
    ///
    /// Private, so no caller can supply or bypass the mapping. Exhaustive, so
    /// adding a variant without deciding its tier is a compile error.
    fn tier(&self) -> (IdentityAssurance, PresenceLevel) {
        match self {
            // A signature proves possession of a key, not who holds it.
            Evidence::Possession(_) => (IdentityAssurance::Iaa1, PresenceLevel::None),
            // A verified token names a human, but proves nothing about *now*.
            Evidence::IdpVerified(_) => (IdentityAssurance::Iaa2, PresenceLevel::Session),
            // A touch proves a human is present, but not which human.
            Evidence::HardwarePresence(_) => (IdentityAssurance::Iaa1, PresenceLevel::Hardware),
        }
    }
}

/// A proven identity claim.
///
/// Every field is private and [`Claim::derive`] is the only constructor. Its
/// signature contains no [`IdentityAssurance`] and no [`PresenceLevel`], so
/// there is no parameter through which a level can be supplied.
#[derive(Debug, Clone)]
pub struct Claim {
    source: String,
    assurance: IdentityAssurance,
    presence: PresenceLevel,
    spiffe_id: SpiffeId,
    display_name: String,
}

impl Claim {
    /// Derive a claim from a candidate and the evidence proving it.
    ///
    /// Returns `None` when there is no evidence. Discovery alone entitles a
    /// candidate to nothing — not even the lowest tier — so the daemon declines
    /// rather than issuing a credential nobody proved.
    pub fn derive(candidate: &Candidate, evidence: &[Evidence]) -> Option<Claim> {
        let (first, rest) = evidence.split_first()?;

        let (mut assurance, mut presence) = first.tier();
        for e in rest {
            let (a, p) = e.tier();
            assurance = assurance.max(a);
            presence = presence.max(p);
        }

        // SPEC-HIA.md: Iaa3 is "hardware-bound *and* IdP-verified". It is the
        // one tier no single piece of evidence reaches, so it is a rule over the
        // fold rather than a fourth variant — a combined variant would multiply
        // combinatorially the moment a fourth evidence kind appears.
        if presence >= PresenceLevel::Hardware && assurance >= IdentityAssurance::Iaa2 {
            assurance = IdentityAssurance::Iaa3;
        }

        // persona-5s4b.55: an issuer-anchored trust domain may come only from a
        // verified token. Otherwise the candidate's self-asserted domain stands.
        let trust_domain = evidence
            .iter()
            .find_map(|e| match e {
                Evidence::IdpVerified(t) => {
                    Some(TrustDomain::OrgOidc(t.issuer_domain().to_owned()))
                }
                _ => None,
            })
            .unwrap_or_else(|| candidate.domain.clone().into());

        // ponytail: the SPIFFE path always comes from the candidate, even when a
        // verified token is present | ceiling: a verified subject cannot yet
        // correct a self-asserted path | upgrade path: carry `sub` on
        // `VerifiedToken` and prefer it here once a verifying constructor exists.
        Some(Claim {
            source: candidate.source.clone(),
            assurance,
            presence,
            spiffe_id: SpiffeId::new(trust_domain, candidate.path.clone()),
            display_name: candidate.display_name.clone(),
        })
    }

    /// Attestor source name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Derived identity assurance level.
    pub fn assurance(&self) -> IdentityAssurance {
        self.assurance
    }

    /// Derived presence level.
    pub fn presence(&self) -> PresenceLevel {
        self.presence
    }

    /// The SPIFFE ID this claim corresponds to.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> Candidate {
        Candidate::new("test", SelfAssertedDomain::SshLocal, "user/alice", "Alice")
    }

    fn possession() -> Evidence {
        Evidence::Possession(ChallengeSignature::new(SignedAssertion::new(
            b"sig".to_vec(),
            "application/test",
        )))
    }

    // This module is a descendant of `claim`, so it may build the gated payloads
    // by struct literal. That is deliberate: it lets the tier table be tested in
    // full today, while no attestor can reach Iaa2, Iaa3 or Hardware.
    fn verified_token(issuer: &str) -> Evidence {
        Evidence::IdpVerified(VerifiedToken {
            issuer_domain: issuer.to_owned(),
        })
    }

    fn hardware_touch() -> Evidence {
        Evidence::HardwarePresence(HardwareTouch {
            touched_at: SystemTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn no_evidence_yields_no_claim() {
        assert!(Claim::derive(&candidate(), &[]).is_none());
    }

    #[test]
    fn possession_alone_is_the_floor() {
        let c = Claim::derive(&candidate(), &[possession()]).unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::None);
    }

    #[test]
    fn touch_alone_is_hardware_presence_but_not_iaa3() {
        let c = Claim::derive(&candidate(), &[hardware_touch()]).unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::Hardware);
    }

    #[test]
    fn verified_token_alone_is_iaa2_session() {
        let c = Claim::derive(&candidate(), &[verified_token("example.com")]).unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa2);
        assert_eq!(c.presence(), PresenceLevel::Session);
    }

    #[test]
    fn touch_plus_verified_token_is_iaa3() {
        let c = Claim::derive(
            &candidate(),
            &[hardware_touch(), verified_token("example.com")],
        )
        .unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa3);
        assert_eq!(c.presence(), PresenceLevel::Hardware);
    }

    #[test]
    fn verified_issuer_anchors_the_trust_domain() {
        let c = Claim::derive(&candidate(), &[verified_token("example.com")]).unwrap();
        assert_eq!(
            c.spiffe_id().trust_domain,
            TrustDomain::OrgOidc("example.com".into())
        );
        assert_eq!(c.spiffe_id().path, "user/alice");
    }

    #[test]
    fn without_a_verified_token_the_domain_stays_self_asserted() {
        let c = Claim::derive(&candidate(), &[possession()]).unwrap();
        assert_eq!(c.spiffe_id().trust_domain, TrustDomain::SshLocal);
    }

    #[test]
    fn a_claims_display_and_source_come_from_the_candidate() {
        let c = Claim::derive(&candidate(), &[possession()]).unwrap();
        assert_eq!(c.source(), "test");
        assert_eq!(c.display_name(), "Alice");
    }
}
