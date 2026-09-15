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

use ed25519_dalek::{Signature, VerifyingKey};
use hire_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::ssh::{read_string, spiffe_path, SSH_ED25519};
use crate::{AttestorError, SignedAssertion};

fn malformed() -> AttestorError {
    AttestorError::ChallengeFailed("malformed ssh-agent blob".into())
}

/// A trust domain an attestor may name about itself with no evidence at all.
///
/// Deliberately narrower than [`TrustDomain`]: the issuer-anchored variants
/// (`OrgOidc`, `PivIssuer`) are absent, because naming an issuer is a claim
/// about a third party and may come only from verified evidence. This is why
/// `oidc.rs` can no longer write `TrustDomain::OrgOidc(extract_domain(&iss))`
/// in `enumerate()` — the variant does not exist here (hire-5s4b.55).
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
/// Establishes possession and nothing more: `Iaa1`, with no presence. A
/// signature proves that a key is reachable, not that a human asked for it —
/// an agent key with no passphrase signs with no prompt at all.
///
/// The challenge it verified against is retained, because verification inside
/// an attestor proves only that *some* challenge was answered. The attestor
/// chooses which one, so a cached triple passes every signature check.
/// [`Claim::derive`] is what makes it *this* request's challenge.
#[derive(Debug, Clone)]
pub struct ChallengeSignature {
    assertion: SignedAssertion,
    challenge: Vec<u8>,
    observed_at: SystemTime,
}

impl ChallengeSignature {
    /// Check an ssh-agent signature, and witness it only if every part holds.
    ///
    /// This is the only constructor, so `Evidence::Possession` cannot be
    /// self-asserted by an attestor inside this workspace. That is what
    /// hire-5s4b.116 closes, and it is why the previous `new` is gone rather
    /// than merely narrowed: a verified path an attestor may *choose* is a
    /// convention, and the next attestor omits it while the type still claims
    /// the signature was checked.
    ///
    /// Four checks, and dropping any one makes the other three prove nothing:
    ///
    /// 1. the blob hashes to the key the candidate names — without this, the
    ///    proof is of *some* key in the agent;
    /// 2. the blob is `ssh-ed25519` with a 32-byte point and no trailing bytes;
    /// 3. the signature names the same algorithm and carries exactly 64 bytes;
    /// 4. the signature verifies over *this* challenge.
    ///
    /// Raw blobs are taken rather than parsed values on purpose. If the caller
    /// parsed, it could hand over a blob whose fingerprint matches the candidate
    /// and a public key that did not come from it.
    ///
    /// The observation instant is taken here rather than passed in: the
    /// signature is produced during the request that consumes it, so "now" is
    /// the truthful answer and there is no earlier moment to name.
    ///
    /// ponytail: ssh-ed25519 only | ceiling: an agent holding only ecdsa or rsa
    ///   keys yields no claim | upgrade path: a sibling constructor per key
    ///   family, here and nowhere else.
    ///
    /// ## Errors
    /// Returns [`AttestorError::ChallengeFailed`] if any check fails. No variant
    /// of failure yields evidence.
    pub fn verify_ssh_ed25519(
        candidate: &Candidate,
        challenge: &[u8],
        key_blob: &[u8],
        signature: &[u8],
    ) -> Result<Self, AttestorError> {
        if spiffe_path(key_blob) != candidate.path {
            return Err(AttestorError::ChallengeFailed(
                "ssh-agent signed with a key the candidate does not name".into(),
            ));
        }

        let (algorithm, rest) = read_string(key_blob).ok_or_else(malformed)?;
        let (point, rest) = read_string(rest).ok_or_else(malformed)?;
        if algorithm != SSH_ED25519 || !rest.is_empty() {
            return Err(AttestorError::ChallengeFailed(format!(
                "unsupported ssh key type {}",
                String::from_utf8_lossy(algorithm)
            )));
        }
        let point = <&[u8; 32]>::try_from(point).map_err(|_| malformed())?;
        let key = VerifyingKey::from_bytes(point).map_err(|_| {
            AttestorError::ChallengeFailed("ssh-agent key is not a valid ed25519 point".into())
        })?;

        let (sig_algorithm, rest) = read_string(signature).ok_or_else(malformed)?;
        let (sig_bytes, rest) = read_string(rest).ok_or_else(malformed)?;
        if sig_algorithm != algorithm || !rest.is_empty() {
            return Err(malformed());
        }
        let sig_bytes = <&[u8; 64]>::try_from(sig_bytes).map_err(|_| malformed())?;

        // verify_strict, not verify: it rejects small-order R, small-order
        // public keys and non-canonical encodings, and it is inherent, so no
        // trait import. Stricter and fewer imports — no tradeoff to weigh.
        // The blob came off a socket.
        key.verify_strict(challenge, &Signature::from_bytes(sig_bytes))
            .map_err(|_| {
                AttestorError::ChallengeFailed(
                    "ssh-agent signature does not verify over the challenge".into(),
                )
            })?;

        Ok(Self {
            assertion: SignedAssertion::new(
                sig_bytes.to_vec(),
                "application/vnd.hire.ssh-ed25519-signature",
            ),
            challenge: challenge.to_vec(),
            observed_at: SystemTime::now(),
        })
    }

    /// The underlying signed assertion.
    pub fn assertion(&self) -> &SignedAssertion {
        &self.assertion
    }

    /// The challenge this signature was verified against.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
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
    /// permanently session-fresh, which is hire-ogiv's bug restored on the
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

/// The kernel's answer to which account a process runs under, and the moment
/// the daemon asked.
///
/// There is no key material and no signature here because there are none to
/// have: the operating system is the entire authority. Do not hand it a
/// [`SignedAssertion`](crate::SignedAssertion) for symmetry with
/// [`ChallengeSignature`] — that constructor is public, so the bytes would be
/// forgeable by anyone and `assertion()` would start lying across the enum.
///
/// Unlike [`VerifiedToken`] and [`HardwareTouch`] this observation can actually
/// be made today, so it has a constructor. The constructor is crate-visible, so
/// no downstream crate can state an account the kernel never named.
///
/// It records *which* account, because this is the one variant with no secret
/// and no challenge behind it. Without that field the observation says only
/// "some account was asked about", which is true of every account at once — and
/// a value obtained legitimately from [`Attestor::prove`](crate::Attestor::prove)
/// could be paired with any candidate at all. [`Evidence::binds_to`] compares it.
#[derive(Debug, Clone)]
pub struct PlatformIdentity {
    account: String,
    asked_at: SystemTime,
}

impl PlatformIdentity {
    /// Record that the daemon asked the kernel which account it runs under, and
    /// got `account` — a SPIFFE path component, as it would appear on a
    /// [`Candidate`].
    ///
    /// Infallible, alone among the payloads in this module: a process always
    /// runs under an account and the kernel cannot refuse the question. The
    /// instant is stamped here rather than passed in, so nothing can re-date a
    /// cached answer.
    pub(crate) fn observe(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            asked_at: SystemTime::now(),
        }
    }

    /// The account the kernel named, as a SPIFFE path component.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// When the daemon asked the kernel which account it runs under.
    ///
    /// It dates a question, not a person. Nobody was observed doing anything at
    /// this instant: the account was there before it and is there after it, and
    /// asking again a second later moves the timestamp without anything having
    /// happened. Reading it the way [`HardwareTouch::touched_at`] is read — as
    /// the moment a human was seen — is exactly the confusion the accompanying
    /// [`PresenceLevel::None`] exists to prevent.
    pub fn asked_at(&self) -> SystemTime {
        self.asked_at
    }
}

/// Evidence supporting a candidate, produced by
/// [`Attestor::prove`](crate::Attestor::prove).
///
/// Not every variant is cryptographic. A variant means that something outside
/// this process attested the candidate; what that is worth is the tier it maps
/// to, never the mere fact that evidence exists.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Evidence {
    /// The candidate's key signed our challenge.
    Possession(ChallengeSignature),
    /// An identity provider vouched for the candidate, signature checked.
    IdpVerified(VerifiedToken),
    /// A human touched an authenticator.
    HardwarePresence(HardwareTouch),
    /// The operating system named the account this process runs under.
    PlatformAssertion(PlatformIdentity),
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
            // The kernel names the account a process runs under. That is not a
            // human being present, and it is not a check on who holds the
            // account — only that something outside this process said so.
            Evidence::PlatformAssertion(p) => {
                (IdentityAssurance::Iaa1, PresenceLevel::None, p.asked_at())
            }
        }
    }

    /// Whether this evidence answers the challenge that opened this request.
    ///
    /// Exhaustive, so a new variant forces the question rather than defaulting
    /// to "bound". Only possession is challenge-bound today.
    ///
    /// A `PlatformAssertion` is unbound and always will be: the kernel answers
    /// the same question however it is asked, so there is no nonce for it to
    /// carry. What that costs is the binding, not freshness — the assertion is
    /// observed afresh inside the `prove` it answers, so there is nothing
    /// stale to replay.
    ///
    /// ponytail: possession only | ceiling: nothing binds a future
    ///   `VerifiedToken` to this request | upgrade path: when a verifying
    ///   constructor for it lands it carries the token's `nonce`, compared here.
    fn binds_to(&self, candidate: &Candidate, challenge: &[u8]) -> bool {
        match self {
            Evidence::Possession(s) => s.challenge() == challenge,
            // Nothing binds this one to the request, so it must at least be
            // bound to the subject. A `PlatformIdentity` is obtainable by any
            // caller of `prove` and carries no secret; without this comparison
            // a legitimately obtained one re-wraps onto an arbitrary candidate
            // and mints a claim for an account nobody asked the kernel about.
            Evidence::PlatformAssertion(p) => p.account() == candidate.path,
            Evidence::IdpVerified(_) | Evidence::HardwarePresence(_) => true,
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
    /// Returns `None` when no evidence answers `challenge` *for this candidate*.
    /// Discovery alone entitles a candidate to nothing; evidence answering some
    /// *other* challenge is a replay, not evidence; and evidence about some
    /// other subject is neither.
    ///
    /// The challenge is a parameter rather than something the caller is trusted
    /// to check, because the attestor is the party a replay would arrive from
    /// and there must be no `derive` that skips the comparison. Plain `==`: the
    /// challenge is a public nonce and this is a freshness check, not a MAC.
    ///
    /// Where a source is available whenever the machine is — `unix` on any
    /// Unix box — `None` is unreachable in practice and the daemon issues on
    /// every request. Holding a credential therefore says nothing on its own;
    /// the assurance field is what a consumer has to read.
    pub fn derive(candidate: &Candidate, challenge: &[u8], evidence: &[Evidence]) -> Option<Claim> {
        let evidence: Vec<&Evidence> = evidence
            .iter()
            .filter(|e| e.binds_to(candidate, challenge))
            .collect();
        let (first, rest) = evidence.split_first()?;

        let (mut assurance, mut presence, mut attested_at) = first.tier();
        for e in rest {
            let (a, p, t) = e.tier();
            assurance = assurance.max(a);
            // Presence and its observation move together. Folding the instants
            // independently with `max` would let a `Possession` produced this
            // millisecond — which carries no presence at all — re-date a
            // four-minute-old touch: hire-ogiv's defect, one layer down. A
            // tie takes the newer, because a second genuine touch is a second
            // genuine observation.
            if p > presence || (p == presence && t > attested_at) {
                presence = p;
                attested_at = t;
            }
        }

        // SPEC-HIRE.md: Iaa3 is "hardware-bound *and* IdP-verified". It is the
        // one tier no single piece of evidence reaches, so it is a rule over the
        // fold rather than a fourth variant — a combined variant would multiply
        // combinatorially the moment a fourth evidence kind appears.
        if presence >= PresenceLevel::Hardware && assurance >= IdentityAssurance::Iaa2 {
            assurance = IdentityAssurance::Iaa3;
        }

        // hire-5s4b.55: an issuer-anchored trust domain may come only from a
        // verified token. Iterating the *filtered* evidence, not the argument:
        // a replayed token must not re-anchor the domain either.
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

    /// When the daemon observed the evidence that set [`Claim::presence`], or
    /// the sole evidence when only one piece survived the challenge filter.
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
    /// satisfies no bound. `unwrap_or_default()` — the idiom hire-ogiv
    /// deletes from `hire-grpc/src/service.rs` — would call a forward-dated
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

    /// The challenge every `Claim::derive` call in this module answers.
    const TEST_CHALLENGE: &[u8] = b"the challenge this request opened";

    /// Possession evidence bound to [`TEST_CHALLENGE`].
    ///
    /// A struct literal, as the `verified_token` and `hardware_touch` helpers
    /// below already are — this module is a descendant of `claim`. What is
    /// under test here is the tier table and the challenge filter, not the
    /// signature check; that has its own module, against RFC 8032 and pyca.
    fn possession() -> Evidence {
        possession_over(TEST_CHALLENGE)
    }

    fn possession_over(challenge: &[u8]) -> Evidence {
        Evidence::Possession(ChallengeSignature {
            assertion: SignedAssertion::new(b"sig".to_vec(), "application/test"),
            challenge: challenge.to_vec(),
            observed_at: SystemTime::now(),
        })
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

    fn platform_assertion(at: SystemTime) -> Evidence {
        platform_assertion_for(candidate().path, at)
    }

    fn platform_assertion_for(account: impl Into<String>, at: SystemTime) -> Evidence {
        Evidence::PlatformAssertion(PlatformIdentity {
            account: account.into(),
            asked_at: at,
        })
    }

    /// A fixed instant, so every freshness assertion is arithmetic over
    /// constants the test chose rather than over a clock it read.
    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn no_evidence_yields_no_claim() {
        assert!(Claim::derive(&candidate(), TEST_CHALLENGE, &[]).is_none());
    }

    #[test]
    fn possession_alone_is_the_floor() {
        let c = Claim::derive(&candidate(), TEST_CHALLENGE, &[possession()]).unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::None);
    }

    #[test]
    fn touch_alone_is_hardware_presence_but_not_iaa3() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[hardware_touch(epoch_plus(1_000))],
        )
        .unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::Hardware);
    }

    #[test]
    fn verified_token_alone_is_iaa2_session() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
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
            TEST_CHALLENGE,
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
            TEST_CHALLENGE,
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
        let c = Claim::derive(&candidate(), TEST_CHALLENGE, &[possession()]).unwrap();
        assert_eq!(c.spiffe_id().trust_domain, TrustDomain::SshLocal);
    }

    #[test]
    fn a_claims_display_and_source_come_from_the_candidate() {
        let c = Claim::derive(&candidate(), TEST_CHALLENGE, &[possession()]).unwrap();
        assert_eq!(c.source(), "test");
        assert_eq!(c.display_name(), "Alice");
    }

    // ── Observation time ──────────────────────────────────────────────────

    #[test]
    fn age_at_measures_a_past_attestation() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[hardware_touch(epoch_plus(1_000))],
        )
        .unwrap();
        assert_eq!(c.age_at(epoch_plus(1_600)), Some(Duration::from_secs(600)));
    }

    #[test]
    fn a_future_attestation_has_no_measurable_age() {
        // A clock that stepped backwards, or an attestor that dated evidence
        // forwards. `unwrap_or_default()` would call this maximally fresh.
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[hardware_touch(epoch_plus(10_000))],
        )
        .unwrap();
        assert_eq!(c.age_at(epoch_plus(9_000)), None);
    }

    #[test]
    fn a_touch_dates_the_claim() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[hardware_touch(epoch_plus(1_000))],
        )
        .unwrap();
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
            let c = Claim::derive(&candidate(), TEST_CHALLENGE, &evidence).unwrap();
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
            let c = Claim::derive(&candidate(), TEST_CHALLENGE, &evidence).unwrap();
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
            let c = Claim::derive(&candidate(), TEST_CHALLENGE, &evidence).unwrap();
            assert_eq!(c.attested_at(), epoch_plus(2_000));
        }
    }

    #[test]
    fn a_platform_assertion_is_the_floor_and_asserts_no_presence() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[platform_assertion(epoch_plus(10))],
        )
        .unwrap();
        assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
        assert_eq!(c.presence(), PresenceLevel::None);
        assert_eq!(c.attested_at(), epoch_plus(10));
    }

    #[test]
    fn a_platform_assertion_does_not_re_date_a_touch() {
        let c = Claim::derive(
            &candidate(),
            TEST_CHALLENGE,
            &[
                hardware_touch(epoch_plus(10)),
                platform_assertion(epoch_plus(900)),
            ],
        )
        .unwrap();
        assert_eq!(c.presence(), PresenceLevel::Hardware);
        assert_eq!(c.attested_at(), epoch_plus(10));
    }

    #[test]
    fn possession_alone_dates_the_claim_from_the_signature() {
        // Brackets the clock rather than using it as an oracle.
        let before = SystemTime::now();
        let c = Claim::derive(&candidate(), TEST_CHALLENGE, &[possession()]).unwrap();
        let after = SystemTime::now();
        assert!(c.attested_at() >= before && c.attested_at() <= after);
    }

    // ── The challenge filter (hire-5s4b.116) ───────────────────────────

    #[test]
    fn evidence_answering_another_challenge_is_not_evidence() {
        // The attestor is the party a replay arrives from, so `derive` asks
        // the question rather than trusting that its caller did.
        assert!(Claim::derive(
            &candidate(),
            b"this request",
            &[possession_over(b"some other")]
        )
        .is_none());
    }

    #[test]
    fn the_filter_drops_the_replayed_proof_and_keeps_the_fresh_one() {
        // Mandatory pair with the test above: without it, a filter that
        // discarded everything would pass that one. Both orders, so the
        // outcome cannot depend on which proof the fold starts from.
        for evidence in [
            vec![possession_over(b"some other"), possession()],
            vec![possession(), possession_over(b"some other")],
        ] {
            let c = Claim::derive(&candidate(), TEST_CHALLENGE, &evidence)
                .expect("the proof answering this challenge must survive");
            assert_eq!(c.assurance(), IdentityAssurance::Iaa1);
            assert_eq!(c.presence(), PresenceLevel::None);
        }
    }

    /// hire-ouo5.1: a platform assertion is refused for an account it does
    /// not name.
    ///
    /// `PlatformIdentity` cannot be forged — the field is private and the
    /// constructor is crate-visible — but it need not be forged to be misused.
    /// It is the one payload with no secret and no challenge behind it, so any
    /// caller of `prove` legitimately obtains one, and before this check
    /// `Claim::derive` would pair it with whatever candidate it was handed:
    ///
    /// ```text
    /// prove() -> PlatformIdentity{unix/1000} + Candidate{unix/0, "root"}
    ///   -> Some(spiffe://ssh.local/unix/0 name=root)
    /// ```
    ///
    /// Demonstrated against the real crate from an external consumer before the
    /// account field existed. The unforgeability the module header promises is
    /// what fails if this test is deleted.
    #[test]
    fn a_platform_assertion_is_refused_for_an_account_it_does_not_name() {
        let root = Candidate::new("unix", SelfAssertedDomain::SshLocal, "unix/0", "root");
        let harvested = platform_assertion_for("unix/1000", SystemTime::now());

        assert!(
            Claim::derive(&root, TEST_CHALLENGE, std::slice::from_ref(&harvested)).is_none(),
            "evidence naming unix/1000 minted a claim for unix/0"
        );

        // The same value still works for the account it actually names, so the
        // check discriminates rather than rejecting the variant outright.
        let owner = Candidate::new("unix", SelfAssertedDomain::SshLocal, "unix/1000", "mark");
        let claim = Claim::derive(&owner, TEST_CHALLENGE, &[harvested])
            .expect("the account the kernel named must still derive");
        assert_eq!(
            claim.spiffe_id().to_string(),
            "spiffe://ssh.local/unix/1000"
        );
    }
}

/// Signature verification, checked against oracles this workspace did not write.
///
/// Two of them, both named acceptable by the project's test-vector rule. The
/// RFC 8032 section 7.1 rows are transcribed out of the RFC text; nothing on
/// this machine produced those signature bytes. The remaining fixtures come
/// from pyca/cryptography, which also recorded its own verdict on each row at
/// generation time. The generator is
/// `hire-attestors/tests/fixtures/gen_ssh_fixtures.py`; regenerating these
/// with hire would turn the oracle into a mirror.
///
/// Where the two disagree, dalek's `verify_strict` is the stricter one — it
/// refuses small-order points and non-canonical encodings that pyca accepts —
/// so a row expecting `Err` against a pyca `Ok` is correct, not a defect.
#[cfg(test)]
mod ssh_ed25519_verification {
    use super::*;

    /// Decode a hex fixture. Bytes in, bytes out, no crate.
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex fixture has an odd length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex fixture is not hex"))
            .collect()
    }

    fn candidate_naming(path: &str) -> Candidate {
        Candidate::new("ssh-agent", SelfAssertedDomain::SshLocal, path, "Test Key")
    }

    // Generated fixtures. Fingerprints were computed with hashlib and base64,
    // not with `spiffe_path`, so the expected path is not the code's own output.
    const KEY_A_PATH: &str = "key/hypfbr3urYfzkHDZVEL25Nfwd0reLKQq+dAsi48SBq4";
    const KEY_A_BLOB: &str = "0000000b7373682d6564323535313900000020db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d";
    const KEY_A_SIG: &str = "0000000b7373682d656432353531390000004024aa9e2c440f78a2fe6d110f539179631c6265229b7b083bfb22a5cb7cc40a4dcfe99e0a0323d787d709f94241b10a4808002f06f04d4b421ee324b2eae04c06";
    const KEY_B_PATH: &str = "key/ZsrOVCtcb1bouzun0GIHz5vL5oCjVhVIQ3jfIBIgZ8g";
    const KEY_B_BLOB: &str = "0000000b7373682d65643235353139000000202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
    const KEY_B_SIG: &str = "0000000b7373682d65643235353139000000401bbdbb894c1f0026792d3cba5c74eed9e8c00d09680de18e8aea654ebb007f77a642da6cae45a6c782601b719acf972a984486fcf1a8e89e416f1a4679608c0e";
    const CHALLENGE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const ECDSA_PATH: &str = "key/tqnTrJ8h0Tph2jhd1rW9SOLL+jq2kKxUvzS0Wg2A190";
    const ECDSA_BLOB: &str = "0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041040050a4e9d0bdd2c23ddd8c8f01b8414133c5c7126a8913040dd84a2f2669eae9816511317b14463b5462f8cb47a7b63a66f4fe2a528189b74f1b83fdf00388a5";

    /// One RFC 8032 section 7.1 row: expected path, key blob, message,
    /// signature. The message stands in for the challenge: Ed25519 signs
    /// whatever it is handed, and the agent hands it the challenge raw.
    type Vector = (&'static str, &'static str, &'static str, &'static str);

    fn rfc8032_vectors() -> Vec<Vector> {
        vec![
            // TEST 1
            (
                "key/bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
                "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "0000000b7373682d6564323535313900000040e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            // TEST 2
            (
                "key/F34nin7tcaYH6WR5LSWSfj6weFBPfBpuyUUoPFP9YjA",
                "0000000b7373682d65643235353139000000203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "0000000b7373682d656432353531390000004092a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            // TEST 3
            (
                "key/s3Z2A+mldeflHo5TMMEUA7MlkMg96xvtqH9DGLHHZmE",
                "0000000b7373682d6564323535313900000020fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "0000000b7373682d65643235353139000000406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            // TEST SHA(abc)
            (
                "key/LuQFmSsJbAkjYpb1LObnHa6mOAGiucbY/zOy8nrd28I",
                "0000000b7373682d6564323535313900000020ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "0000000b7373682d6564323535313900000040dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ]
    }

    #[test]
    fn rfc_8032_vectors_verify() {
        for (path, blob, message, signature) in rfc8032_vectors() {
            let evidence = ChallengeSignature::verify_ssh_ed25519(
                &candidate_naming(path),
                &hex(message),
                &hex(blob),
                &hex(signature),
            )
            .unwrap_or_else(|e| panic!("RFC 8032 vector {path} must verify: {e}"));
            assert_eq!(evidence.challenge(), hex(message));
        }
    }

    #[test]
    fn an_rfc_vector_with_one_message_byte_flipped_is_refused() {
        for (path, blob, message, signature) in rfc8032_vectors() {
            let mut tampered = hex(message);
            // The empty-message vector has no byte to flip; extend it instead,
            // which is the same falsification with one fewer special case.
            tampered.push(0x01);
            assert!(ChallengeSignature::verify_ssh_ed25519(
                &candidate_naming(path),
                &tampered,
                &hex(blob),
                &hex(signature),
            )
            .is_err());
        }
    }

    #[test]
    fn a_genuine_signature_over_this_challenge_verifies() {
        let evidence = ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(KEY_A_PATH),
            &hex(CHALLENGE),
            &hex(KEY_A_BLOB),
            &hex(KEY_A_SIG),
        )
        .expect("pyca signed this challenge with this key");
        assert_eq!(evidence.challenge(), hex(CHALLENGE));
        assert_eq!(
            evidence.assertion().format,
            "application/vnd.hire.ssh-ed25519-signature"
        );
    }

    #[test]
    fn a_signature_over_a_different_challenge_is_refused() {
        let mut other = hex(CHALLENGE);
        other[0] ^= 0x01;
        assert!(ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(KEY_A_PATH),
            &other,
            &hex(KEY_A_BLOB),
            &hex(KEY_A_SIG),
        )
        .is_err());
    }

    #[test]
    fn a_genuine_signature_by_another_key_is_refused() {
        // Key B's signature over the same challenge is perfectly valid. It is
        // refused because the candidate names key A: without the fingerprint
        // check, this would prove possession of *some* key in the agent.
        let err = ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(KEY_A_PATH),
            &hex(CHALLENGE),
            &hex(KEY_B_BLOB),
            &hex(KEY_B_SIG),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("the candidate does not name"),
            "must refuse at the fingerprint binding, got: {err}"
        );
    }

    #[test]
    fn key_bs_own_signature_verifies_for_key_b() {
        // The negative above is only evidence if the same bytes pass when the
        // candidate names the key that produced them.
        ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(KEY_B_PATH),
            &hex(CHALLENGE),
            &hex(KEY_B_BLOB),
            &hex(KEY_B_SIG),
        )
        .expect("key B's signature must verify for key B");
    }

    #[test]
    fn an_ecdsa_key_is_refused_by_name() {
        // The refusal message is the user-visible contract of the ed25519-only
        // constraint: an operator learns which algorithm was declined.
        let err = ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(ECDSA_PATH),
            &hex(CHALLENGE),
            &hex(ECDSA_BLOB),
            &hex(KEY_A_SIG),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("ecdsa-sha2-nistp256"),
            "the refusal must name the algorithm, got: {err}"
        );
    }

    #[test]
    fn malformed_blobs_are_refused_and_never_panic() {
        let sig = hex(KEY_A_SIG);
        let blob = hex(KEY_A_BLOB);
        let challenge = hex(CHALLENGE);
        let candidate = candidate_naming(KEY_A_PATH);

        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty signature", vec![]),
            ("truncated length prefix", sig[..3].to_vec()),
            (
                "length prefix promising more than is there",
                sig[..8].to_vec(),
            ),
            (
                "trailing bytes after the sigblob",
                [sig.clone(), vec![0u8]].concat(),
            ),
        ];
        // A 63-byte and a 65-byte signature body, reframed honestly so the
        // length prefix agrees with the body: the check under test is the
        // 64-byte requirement, not the framing.
        for len in [63usize, 65] {
            let mut body = sig[19..].to_vec();
            body.resize(len, 0);
            let mut reframed = sig[..15].to_vec();
            reframed.extend_from_slice(&(len as u32).to_be_bytes());
            reframed.extend_from_slice(&body);
            cases.push(("wrong signature length", reframed));
        }

        for (name, candidate_sig) in cases {
            assert!(
                ChallengeSignature::verify_ssh_ed25519(
                    &candidate,
                    &challenge,
                    &blob,
                    &candidate_sig
                )
                .is_err(),
                "{name} must be refused"
            );
        }

        // And the same on the key side: a blob whose fingerprint still matches
        // the candidate but whose body is truncated.
        let short = blob[..blob.len() - 1].to_vec();
        assert!(
            ChallengeSignature::verify_ssh_ed25519(
                &candidate_naming(&spiffe_path(&short)),
                &challenge,
                &short,
                &sig
            )
            .is_err(),
            "a truncated key blob must be refused"
        );
    }

    #[test]
    fn an_all_zero_public_key_is_refused() {
        // A small-order point. `verify_strict` refuses it; a plain `verify`
        // would not, and pyca does not either.
        let blob = [
            &(11u32.to_be_bytes())[..],
            b"ssh-ed25519",
            &(32u32.to_be_bytes())[..],
            &[0u8; 32][..],
        ]
        .concat();
        assert!(ChallengeSignature::verify_ssh_ed25519(
            &candidate_naming(&spiffe_path(&blob)),
            &hex(CHALLENGE),
            &blob,
            &hex(KEY_A_SIG),
        )
        .is_err());
    }
}
