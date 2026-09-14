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

use std::time::{Duration, SystemTime};

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
    observed_at: SystemTime,
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
    ///
    /// The observation instant is taken here rather than passed in: the
    /// signature is produced during the request that consumes it, so "now" is
    /// the truthful answer and there is no earlier moment to name.
    pub fn new(assertion: SignedAssertion) -> Self {
        Self {
            assertion,
            observed_at: SystemTime::now(),
        }
    }

    /// The underlying signed assertion.
    pub fn assertion(&self) -> &SignedAssertion {
        &self.assertion
    }

    /// When the daemon observed the signature come back from the key.
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
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
    /// When the issuer says the human authenticated — never when the daemon
    /// read the token.
    ///
    /// A verifying constructor must build this from the token's `auth_time`,
    /// and must refuse to build a `VerifiedToken` at all when `auth_time` is
    /// absent. Stamping `SystemTime::now()` here would make every cached token
    /// permanently session-fresh, which is persona-ogiv's bug restored on the
    /// OIDC path, beside a type that looks like it prevents exactly that.
    authenticated_at: SystemTime,
}

impl VerifiedToken {
    /// The issuer domain taken from the token's verified `iss` claim.
    pub fn issuer_domain(&self) -> &str {
        &self.issuer_domain
    }

    /// When the issuer says the human authenticated.
    pub fn authenticated_at(&self) -> SystemTime {
        self.authenticated_at
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
    ///
    /// The moment the authenticator reported user presence, not the moment this
    /// value was constructed. An attestor that caches an assertion and
    /// re-stamps it on each request reintroduces the defect this field exists
    /// to remove, one layer down and invisibly.
    ///
    /// ponytail: wall clock only | ceiling: a touch cached across a suspend or
    /// an NTP step is dated by a clock that may have moved, and `Instant`
    /// advances by roughly zero across a lid close on Linux
    /// (`CLOCK_MONOTONIC`) and Darwin (`CLOCK_UPTIME_RAW`), so the wall clock
    /// is the one that is right about a suspend and wrong about a step |
    /// upgrade path: when an attestor first caches an assertion across
    /// requests, pair an `Instant` on at observation and take
    /// `wall_age.max(mono_age)` — older wins, which fails closed both ways.
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
    ///
    /// The observation instant is part of the tier, not a fourth value folded
    /// beside it. A presence level is a statement about a moment; separate the
    /// two and the fold will pair one item's level with another item's clock.
    fn tier(&self) -> (IdentityAssurance, PresenceLevel, SystemTime) {
        match self {
            // A signature proves possession of a key, not who holds it.
            Evidence::Possession(s) => (
                IdentityAssurance::Iaa1,
                PresenceLevel::None,
                s.observed_at(),
            ),
            // A verified token names a human, and dates the session it opened.
            Evidence::IdpVerified(t) => (
                IdentityAssurance::Iaa2,
                PresenceLevel::Session,
                t.authenticated_at(),
            ),
            // A touch proves a human was present at a moment, but not which human.
            Evidence::HardwarePresence(h) => (
                IdentityAssurance::Iaa1,
                PresenceLevel::Hardware,
                h.touched_at(),
            ),
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
    attested_at: SystemTime,
}

impl Claim {
    /// Derive a claim from a candidate and the evidence proving it.
    ///
    /// Returns `None` when there is no evidence. Discovery alone entitles a
    /// candidate to nothing — not even the lowest tier — so the daemon declines
    /// rather than issuing a credential nobody proved.
    pub fn derive(candidate: &Candidate, evidence: &[Evidence]) -> Option<Claim> {
        let (first, rest) = evidence.split_first()?;

        let (mut assurance, mut presence, mut attested_at) = first.tier();
        for e in rest {
            let (a, p, t) = e.tier();
            assurance = assurance.max(a);
            // Presence and its observation move together. Folding the instants
            // independently with `max` would let a `Possession` produced this
            // millisecond — which carries no presence at all — re-date a
            // four-minute-old touch: persona-ogiv's defect, one layer down. A
            // tie takes the newer, because a second genuine touch is a second
            // genuine observation.
            if p > presence || (p == presence && t > attested_at) {
                presence = p;
                attested_at = t;
            }
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
            attested_at,
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

    /// When the daemon observed the evidence that set [`Claim::presence`].
    ///
    /// It means exactly that and no more: the daemon saw this evidence at this
    /// instant. It is not proof that a human was verifiably at the keyboard
    /// then, and it is exactly as trustworthy as the attestor that produced the
    /// evidence.
    pub fn attested_at(&self) -> SystemTime {
        self.attested_at
    }

    /// Age of the observation at `now`, or `None` when it is in the future.
    ///
    /// `None` is the fail-shut answer to a clock that stepped backwards or an
    /// attestor that dated evidence forwards: an age that cannot be measured
    /// satisfies no bound. `unwrap_or_default()` — the idiom persona-ogiv
    /// deletes from `persona-grpc/src/service.rs` — would call a forward-dated
    /// attestation maximally fresh, which is the fail-open this field exists to
    /// remove.
    ///
    /// `now` is a parameter so the comparison is a pure function of two
    /// instants, testable against fixed constants with no clock seam and no
    /// sleep.
    pub fn age_at(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.attested_at).ok()
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
    fn verified_token(issuer: &str, at: SystemTime) -> Evidence {
        Evidence::IdpVerified(VerifiedToken {
            issuer_domain: issuer.to_owned(),
            authenticated_at: at,
        })
    }

    fn hardware_touch(at: SystemTime) -> Evidence {
        Evidence::HardwarePresence(HardwareTouch { touched_at: at })
    }

    /// A fixed instant, so every freshness assertion is arithmetic over
    /// constants the test chose rather than over a clock it read.
    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
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
        let c = Claim::derive(&candidate(), &[hardware_touch(epoch_plus(1_000))]).unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::Hardware);
    }

    #[test]
    fn verified_token_alone_is_iaa2_session() {
        let c = Claim::derive(
            &candidate(),
            &[verified_token("example.com", epoch_plus(1_000))],
        )
        .unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa2);
        assert_eq!(c.presence(), PresenceLevel::Session);
    }

    #[test]
    fn touch_plus_verified_token_is_iaa3() {
        let c = Claim::derive(
            &candidate(),
            &[
                hardware_touch(epoch_plus(1_000)),
                verified_token("example.com", epoch_plus(1_000)),
            ],
        )
        .unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa3);
        assert_eq!(c.presence(), PresenceLevel::Hardware);
    }

    #[test]
    fn verified_issuer_anchors_the_trust_domain() {
        let c = Claim::derive(
            &candidate(),
            &[verified_token("example.com", epoch_plus(1_000))],
        )
        .unwrap();
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

    // ── Observation time ──────────────────────────────────────────────────

    #[test]
    fn age_at_measures_a_past_attestation() {
        let c = Claim::derive(&candidate(), &[hardware_touch(epoch_plus(1_000))]).unwrap();
        assert_eq!(c.age_at(epoch_plus(1_600)), Some(Duration::from_secs(600)));
    }

    #[test]
    fn a_future_attestation_has_no_measurable_age() {
        // A clock that stepped backwards, or an attestor that dated evidence
        // forwards. `unwrap_or_default()` would call this maximally fresh.
        let c = Claim::derive(&candidate(), &[hardware_touch(epoch_plus(10_000))]).unwrap();
        assert_eq!(c.age_at(epoch_plus(9_000)), None);
    }

    #[test]
    fn a_touch_dates_the_claim() {
        let c = Claim::derive(&candidate(), &[hardware_touch(epoch_plus(1_000))]).unwrap();
        assert_eq!(c.attested_at(), epoch_plus(1_000));
    }

    #[test]
    fn the_observation_follows_the_evidence_that_set_the_presence_level() {
        // A newer token must not re-date an older touch: the touch is what set
        // `Hardware`, so the touch supplies the instant.
        for evidence in [
            vec![
                hardware_touch(epoch_plus(1_000)),
                verified_token("example.com", epoch_plus(9_000)),
            ],
            vec![
                verified_token("example.com", epoch_plus(9_000)),
                hardware_touch(epoch_plus(1_000)),
            ],
        ] {
            let c = Claim::derive(&candidate(), &evidence).unwrap();
            assert_eq!(c.presence(), PresenceLevel::Hardware);
            assert_eq!(c.attested_at(), epoch_plus(1_000));
        }
    }

    #[test]
    fn a_fresh_signature_does_not_refresh_a_stale_touch() {
        // `possession()` stamps SystemTime::now(), decades after the touch.
        for evidence in [
            vec![hardware_touch(epoch_plus(1_000)), possession()],
            vec![possession(), hardware_touch(epoch_plus(1_000))],
        ] {
            let c = Claim::derive(&candidate(), &evidence).unwrap();
            assert_eq!(c.attested_at(), epoch_plus(1_000));
        }
    }

    #[test]
    fn two_touches_take_the_newer() {
        for evidence in [
            vec![
                hardware_touch(epoch_plus(1_000)),
                hardware_touch(epoch_plus(2_000)),
            ],
            vec![
                hardware_touch(epoch_plus(2_000)),
                hardware_touch(epoch_plus(1_000)),
            ],
        ] {
            let c = Claim::derive(&candidate(), &evidence).unwrap();
            assert_eq!(c.attested_at(), epoch_plus(2_000));
        }
    }

    #[test]
    fn possession_alone_dates_the_claim_from_the_signature() {
        // Brackets the clock rather than using it as an oracle.
        let before = SystemTime::now();
        let c = Claim::derive(&candidate(), &[possession()]).unwrap();
        let after = SystemTime::now();
        assert!(c.attested_at() >= before && c.attested_at() <= after);
    }
}
