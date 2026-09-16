use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::{Request, Response, Status};

use hire_attestors::{Attestor, Claim};
use hire_core::{
    AudienceExtensions, HireClaims, PresenceInfo, PresenceLevel, SvidSigner, TrustBundleStore,
    TrustDomain,
};

use crate::consumer_attest::PeerIdentity;
use crate::workload::{
    spiffe_workload_api_server::SpiffeWorkloadApi, JwtBundlesRequest, JwtBundlesResponse,
    JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest, ValidateJwtsvidResponse,
    WitBundlesRequest, WitBundlesResponse, WitsvidRequest, WitsvidResponse, X509BundlesRequest,
    X509BundlesResponse, X509svidRequest, X509svidResponse,
};

/// The verified JWT payload, as the `google.protobuf.Struct` the response field
/// is typed as.
///
/// A consumer that validates through this RPC rather than decoding the token
/// itself reads the whole payload here or nowhere: `spiffe_id` alone cannot
/// distinguish an identity an IdP verified from one `getuid()` asserted, and
/// `identity_assurance` is the field that can. Returning `None` would leave
/// that consumer no choice but to abandon this RPC and verify against
/// FetchJWTBundles by hand.
///
/// `None` only when the payload is not a JSON object, which a decoded JWT
/// cannot be.
fn claims_struct(payload: &serde_json::Value) -> Option<prost_types::Struct> {
    payload.as_object().map(struct_from_map)
}

/// One JSON object as one protobuf `Struct`.
fn struct_from_map(map: &serde_json::Map<String, serde_json::Value>) -> prost_types::Struct {
    prost_types::Struct {
        fields: map
            .iter()
            .map(|(name, value)| (name.clone(), json_to_protobuf(value)))
            .collect(),
    }
}

/// One JSON value as one protobuf `Value`.
///
/// A number too large for an f64 becomes its decimal string rather than a
/// rounded double: protobuf has no integer value kind, and a silently rounded
/// `exp` is worse than one the consumer has to parse.
fn json_to_protobuf(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => match n.as_f64() {
            Some(f) => Kind::NumberValue(f),
            None => Kind::StringValue(n.to_string()),
        },
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(items) => Kind::ListValue(prost_types::ListValue {
            values: items.iter().map(json_to_protobuf).collect(),
        }),
        serde_json::Value::Object(map) => Kind::StructValue(struct_from_map(map)),
    };
    prost_types::Value { kind: Some(kind) }
}

pub struct WorkloadApiService {
    pub signer: Arc<SvidSigner>,
    pub bundles: Arc<TrustBundleStore>,
    pub attestors: Vec<Arc<dyn Attestor>>,
}

impl WorkloadApiService {
    pub fn new(
        signer: Arc<SvidSigner>,
        bundles: Arc<TrustBundleStore>,
        attestors: Vec<Arc<dyn Attestor>>,
    ) -> Self {
        Self {
            signer,
            bundles,
            attestors,
        }
    }
}

/// How long a presence observation is honoured before it asserts nothing.
///
/// Fixed, daemon-wide, and not extendable by anything a caller does — SPEC-HIRE
/// "a fixed TTL from the last hardware attestation, not extended by
/// keyboard/mouse activity".
///
/// Deliberately NOT the same quantity as the JWT `exp` in
/// `hire-core/src/signer.rs`, which bounds how long a credential may be
/// replayed. The two are equal today by coincidence and must not be folded into
/// one constant; after hire-ogiv they diverge for the first time, and a
/// consumer will see `present_until < exp` for an aged observation.
///
/// ponytail: one daemon-wide TTL | ceiling: not per-attestor and not
/// configurable, so a source that knows its own hardware TTL is shorter cannot
/// say so | upgrade path: `Attestor::presence_ttl()`, consulted where the
/// evidence is produced.
const PRESENCE_TTL: Duration = Duration::from_secs(300);

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send + 'static>>;

/// Whether an observation of measured `age` satisfies the caller's bound.
///
/// The caller's bound is refused outright rather than decayed, so a named
/// parameter is never silently a no-op. Strictly younger, so `hire_max_age=0`
/// is a deterministic refusal with no special case for zero. An unmeasurable age
/// (`None`, from `Claim::age_at` on a forward-dated observation) satisfies no
/// bound. An absent bound is satisfied by anything, including an unmeasurable age
/// — naming no bound asks no question.
///
/// A named function rather than an inline `if`, because no end-to-end test can
/// put an observation of a chosen age in front of it: `observed_at` is stamped
/// when the signature is verified, so every claim the RPC can reach is fresh.
/// The boundaries are tested here instead, over both arguments directly.
fn within_max_age(age: Option<Duration>, max_age: Option<Duration>) -> bool {
    match max_age {
        Some(max_age) => age.is_some_and(|age| age < max_age),
        None => true,
    }
}

/// A fresh 32-byte challenge, handed to `prove()` so that an attestor which signs it
/// produces something specific to this request rather than replayable.
///
/// The binding is checked in two places, and both are required. The attestor verifies
/// the signature against this challenge and the key its candidate names —
/// `ChallengeSignature::verify_ssh_ed25519` is the only way to build possession
/// evidence, so there is no unchecked path. `Claim::derive` is then given the same
/// challenge and discards evidence that answers a different one, because the attestor
/// is the party a replay would arrive from. hire-5s4b.116.
fn new_challenge() -> Result<[u8; 32], Status> {
    use rand_core::{OsRng, RngCore as _};
    let mut buf = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| Status::internal("challenge generation failed"))?;
    Ok(buf)
}

/// Bundle map key. The proto documents all four bundle maps as "keyed by the
/// SPIFFE ID of the trust domain"; `TrustDomain::Display` renders the bare
/// authority, which is not a SPIFFE ID.
fn bundle_key(trust_domain: &TrustDomain) -> String {
    format!("spiffe://{trust_domain}")
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream = BoxStream<X509svidResponse>;
    type FetchX509BundlesStream = BoxStream<X509BundlesResponse>;
    type FetchJWTBundlesStream = BoxStream<JwtBundlesResponse>;
    type FetchWITSVIDStream = BoxStream<WitsvidResponse>;
    type FetchWITBundlesStream = BoxStream<WitBundlesResponse>;

    // hire-4qm: X.509-SVID issuance not yet implemented
    async fn fetch_x509svid(
        &self,
        _req: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        Err(Status::unimplemented(
            "X.509-SVID issuance not yet implemented",
        ))
    }

    // hire-rbu: Return X.509 bundles for all active trust domains
    async fn fetch_x509_bundles(
        &self,
        _req: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        // A trust domain appears here only if it actually has an X.509
        // authority. None does: X509-SVID issuance is unimplemented and no CA
        // certificate exists, so this map is empty today. An empty proto3 map
        // is indistinguishable on the wire from an absent one and makes a
        // conforming consumer reject every X509-SVID, which is the true answer.
        // A zero-length blob would instead claim "here is the DER bundle" and
        // hand over a non-document; the signer's raw EC point, which this used
        // to publish, is not a certificate at all (hire-5s4b.60). The filter
        // is the general rule and not a hardcoded emptiness: the day a real CA
        // certificate lands in `x509_authorities`, the entry appears with no
        // further change here.
        let bundles = self
            .bundles
            .snapshot()
            .into_iter()
            .filter(|b| !b.x509_authorities.is_empty())
            .map(|b| (bundle_key(&b.trust_domain), b.x509_authorities.concat()))
            .collect();
        let response = X509BundlesResponse {
            crl: vec![],
            bundles,
        };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // hire-rbu: Return JWKS bundles for all active trust domains
    async fn fetch_jwt_bundles(
        &self,
        _req: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        let mut bundles = std::collections::HashMap::new();
        for b in self.bundles.snapshot() {
            // Not `unwrap_or_default()`: that turned a serialisation failure
            // into a published *empty* bundle, which is the silent failure
            // these issues are about.
            let jwks = serde_json::to_vec(&b.jwt_authorities)
                .map_err(|_| Status::internal("trust bundle is not serialisable"))?;
            bundles.insert(bundle_key(&b.trust_domain), jwks);
        }
        let response = JwtBundlesResponse { bundles };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // hire-rrv: JWT-SVID issuance
    async fn fetch_jwtsvid(
        &self,
        req: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        use crate::workload::Jwtsvid;

        // Consumer attestation, before anything else is parsed. A caller the
        // daemon cannot name learns nothing further — not whether the audience was
        // well formed, not whether this user has any identity at all.
        //
        // tonic installs the per-connection ConnectInfo into every request's
        // extensions, so this is the identity determined at accept. `None` is the
        // default for any transport that does not attest, and it denies: a listener
        // added later without an AttestedStream wrapper fails shut, not open.
        let Some(consumer) = req
            .extensions()
            .get::<PeerIdentity>()
            .and_then(PeerIdentity::get)
            .cloned()
        else {
            let reason = "consumer could not be attested";
            tracing::info!(event = "svid_denied", reason);
            return Err(Status::unauthenticated(reason));
        };

        let req = req.into_inner();
        if req.audience.is_empty() {
            let reason = "audience must not be empty";
            tracing::info!(event = "svid_denied", reason);
            return Err(Status::invalid_argument(reason));
        }

        // Every audience carries its own policy, so every audience is parsed
        // and the request is gated on the strictest requirement any of them
        // names. `max` is commutative, so the outcome cannot depend on argument
        // order, and `PresenceLevel::None` is the least element and is what an
        // audience naming no policy contributes — so no audience an attacker
        // adds, in any position, can lower the bar.
        let exts = req
            .audience
            .iter()
            .map(|a| AudienceExtensions::parse(a.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                let reason = e.to_string();
                tracing::info!(event = "svid_denied", reason = %reason);
                Status::invalid_argument(reason)
            })?;
        let require_presence = exts
            .iter()
            .fold(PresenceLevel::None, |acc, e| acc.max(e.require_presence));

        // The tightest bound any audience names. `min` is commutative, so the
        // outcome cannot depend on argument order, and an audience naming no
        // bound contributes nothing — so no audience an attacker adds, in any
        // position, can loosen a bound another audience named. Mirror image of
        // the `max` fold over require_presence.
        let max_age = exts.iter().filter_map(|e| e.max_age).min();

        let challenge = new_challenge()?;

        // Discover candidates, then ask each attestor to prove one. Assurance
        // exists only on the far side of prove(): a candidate with no evidence
        // yields no claim at all.
        //
        // ponytail: every candidate is proved on every request | ceiling: once a
        //   hardware attestor can prompt, this is one touch per candidate per RPC
        //   | upgrade path: cache the proven Claim for the presence TTL, keyed by
        //   spiffe_id, and prove lazily in descending attainable tier
        let mut best: Option<Claim> = None;
        for attestor in &self.attestors {
            let candidates = match attestor.enumerate().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(name = attestor.name(), err = %e, "attestor enumerate failed");
                    continue;
                }
            };
            for candidate in candidates {
                let evidence = match attestor.prove(&candidate, &challenge).await {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::debug!(
                            name = attestor.name(),
                            err = %e,
                            "attestor cannot prove candidate"
                        );
                        continue;
                    }
                };
                let Some(claim) = Claim::derive(&candidate, &challenge, &evidence) else {
                    continue;
                };
                if best
                    .as_ref()
                    .is_none_or(|b| claim.assurance() > b.assurance())
                {
                    best = Some(claim);
                }
            }
        }

        let claim = best.ok_or_else(|| {
            let reason = "no identity claims available";
            tracing::info!(event = "svid_denied", reason);
            Status::unauthenticated(reason)
        })?;

        // ponytail: no clock seam. Unit tests pass `now` explicitly to
        //   Claim::age_at, so the fold and the age arithmetic are exercised
        //   against fixed constants. The end-to-end tests cannot do that — the
        //   clock is read here, inside the RPC — so they hold one observation
        //   and wait for it to genuinely age, which costs a few seconds of
        //   wall time in hire-grpc/tests/e2e.rs.
        //   | ceiling: those waits are real sleeps, so the suite is that much
        //   slower and is sensitive to a heavily loaded machine; and nothing
        //   tests an actual NTP step or a suspend/resume
        //   | upgrade path: a `now: fn() -> SystemTime` field on
        //   WorkloadApiService defaulting to SystemTime::now, which would let
        //   those tests move the clock instead of waiting. Not worth a field on
        //   a production type until the waits actually hurt.
        let now = SystemTime::now();
        let age = claim.age_at(now);

        if !within_max_age(age, max_age) {
            // The measured age is not in the reason: it is a per-human value
            // and this string goes to the consumer. The bound is the caller's
            // own parameter, so naming it tells a colluder nothing.
            let reason = "presence observation is older than the requested hire_max_age";
            tracing::info!(event = "svid_denied", reason);
            return Err(Status::unauthenticated(reason));
        }

        // The daemon's own TTL, applied as decay rather than as a second refusal
        // path: past the TTL the claim asserts no presence, and the gate below —
        // and the `Ord` on PresenceLevel it rests on — keeps doing all the work.
        let presence = if age.is_some_and(|age| age < PRESENCE_TTL) {
            claim.presence()
        } else {
            PresenceLevel::None
        };

        // Presence gate. `require_presence` is the strictest level named by any
        // audience, so satisfying it satisfies every audience the token names.
        if require_presence > presence {
            let reason = format!(
                "required presence level not satisfied (need {require_presence:?}, have {presence:?})"
            );
            tracing::info!(event = "svid_denied", reason = %reason);
            return Err(Status::unauthenticated(reason));
        }

        // Both published instants are whole Unix seconds and both are functions
        // of the observation, not of the clock at request time, so re-requesting
        // cannot move them. Truncation is the fail-closed direction: attested_at
        // reads up to a second older than it was and present_until up to a
        // second shorter, never the reverse. A pre-epoch observation publishes
        // as 0, which is honestly "maximally old" — unlike the
        // `unwrap_or_default()` this replaces, where zero meant "now".
        //
        // hire-5s4b.118, accepted and bounded: two consumers served from one
        // observation receive byte-identical values here, so this is a join key
        // across their distinct pseudonyms, stable for the whole presence
        // window. It is published anyway. Withholding it leaves a consumer
        // unable to judge freshness for itself and forced to trust a TTL it
        // cannot check, which is hearsay one layer down. Whole seconds is the
        // floor: finer resolution buys a JWT consumer nothing and multiplies the
        // linkage.
        let attested_at = claim
            .attested_at()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let present_until = attested_at.saturating_add(PRESENCE_TTL.as_secs());

        // Built through the type that defines the wire format, so a field added
        // to `HireClaims` stops compiling here instead of silently vanishing
        // from the token.
        let hire_ext = serde_json::to_value(HireClaims::new(
            claim.spiffe_id().trust_domain.to_string(),
            vec![claim.source().to_owned()],
            claim.assurance(),
            PresenceInfo {
                present: presence != PresenceLevel::None,
                attested_by: claim.source().to_owned(),
                attested_at,
                present_until,
            },
            vec![claim.source().to_owned()],
        ))
        .expect("HireClaims serialises as JSON");

        // The root identity is an input to derivation and never an output. There
        // is no branch here that can emit claim.spiffe_id().uri().
        let spiffe_id_str = self
            .signer
            .pseudonymous_id(claim.spiffe_id(), &consumer)
            .uri();
        let audiences: Vec<&str> = exts.iter().map(|e| e.audience.as_str()).collect();

        let token = self
            .signer
            .sign_jwt_svid(&spiffe_id_str, &audiences, hire_ext)
            .map_err(|e| {
                let reason = e.to_string();
                tracing::info!(event = "svid_denied", reason = %reason);
                Status::internal(reason)
            })?;

        // Deliberately no root identity here. Logging it beside the pseudonym would
        // write the join table this feature exists to withhold, and hired is a
        // user-session daemon: its log goes to the user journal or to
        // ~/Library/Logs, both readable by every consumer, which all run as that
        // same user. An operator debugging "which application got which identity"
        // gets the consumer and the pseudonym, which is enough to follow a request;
        // the mapping back to the root is the secret.
        tracing::info!(
            event = "svid_issued",
            consumer = %consumer.selector_key(),
            spiffe_id = %spiffe_id_str,
            source = %claim.source(),
            assurance = %claim.assurance(),
            presence = ?presence,
            audiences = ?audiences,
        );

        Ok(Response::new(JwtsvidResponse {
            svids: vec![Jwtsvid {
                spiffe_id: spiffe_id_str,
                svid: token,
                hint: String::new(),
            }],
        }))
    }

    // hire-t67: JWT-SVID validation, against the published trust bundle and
    // nothing else.
    //
    // `self.signer` is deliberately not read in this method. A validator that
    // asks the issuing key whether the issuing key signed something asserts
    // nothing a third party could check, and it keeps passing when the
    // published bundle is empty — which is how hire-5s4b.60 hid behind
    // hire-5s4b.82. The only key material this method may touch is what
    // FetchJWTBundles would hand a consumer.
    async fn validate_jwtsvid(
        &self,
        req: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        use hire_core::SpiffeId;
        use jsonwebtoken::{decode, Algorithm, Validation};

        let req = req.into_inner();
        if req.svid.is_empty() {
            return Err(Status::invalid_argument("svid must not be empty"));
        }
        if req.audience.is_empty() {
            return Err(Status::invalid_argument("audience must not be empty"));
        }

        // One message for every rejection below. "no authority for that trust
        // domain", "no key with that kid" and "bad signature" must not be
        // distinguishable: this RPC is reachable by any attested consumer, and
        // the difference would enumerate which trust domains this daemon holds
        // keys for.
        let reject = || Status::invalid_argument("JWT validation failed");

        // Read before verifying, to choose which published key must verify.
        // Everything obtained here is attacker-controlled and grants nothing:
        // a caller who picks the trust domain and the kid has picked which
        // published key their signature has to satisfy. The verified claims are
        // checked back against this choice below.
        let unverified = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(&req.svid)
            .map_err(|_| reject())?;
        let kid = unverified.header.kid.ok_or_else(reject)?;
        let claimed: SpiffeId = unverified
            .claims
            .get("spiffe_id")
            .and_then(|v| v.as_str())
            .ok_or_else(reject)?
            .parse()
            .map_err(|_| reject())?;

        let decoding_key = self
            .bundles
            .get(&claimed.trust_domain)
            .ok_or_else(reject)?
            .jwt_decoding_key(&kid)
            .ok_or_else(reject)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[&req.audience]);
        // Chosen, not inherited: jsonwebtoken defaults `leeway` to 60, which
        // honours a 300s token for 360s. The daemon and every consumer of this
        // RPC are on the same host behind a Unix socket and read the same
        // clock, so there is no skew to accommodate and no value above zero
        // that can be defended here. It also has to be zero for a short TTL to
        // mean anything: hire-3tly.7.1 gives a source that cannot observe
        // departure a TTL as its entire safety margin, and a 2s token accepted
        // for 62s is not a short TTL.
        //
        // `reject_tokens_expiring_in_less_than` stays 0 deliberately, and it is
        // the opposite question: a token valid at the instant it is checked is
        // valid, and how much of its life a consumer needs left is the
        // consumer's bound to apply, not ours to guess on its behalf.
        validation.leeway = 0;

        // Checks signature, exp and aud.
        let token_data = decode::<serde_json::Value>(&req.svid, &decoding_key, &validation)
            .map_err(|e| {
                tracing::debug!(event = "svid_validation_failed", reason = %e);
                reject()
            })?;

        let spiffe_id: SpiffeId = token_data
            .claims
            .get("spiffe_id")
            .and_then(|v| v.as_str())
            .ok_or_else(reject)?
            .parse()
            .map_err(|_| reject())?;

        // Key selection ran on unverified input; this is where that input stops
        // being trusted. The bundle that verified this token must be the bundle
        // for the trust domain the *verified* claims name.
        if spiffe_id.trust_domain != claimed.trust_domain {
            return Err(reject());
        }

        tracing::info!(
            event = "svid_validated",
            spiffe_id = %spiffe_id,
            audience = %req.audience,
        );

        Ok(Response::new(ValidateJwtsvidResponse {
            spiffe_id: spiffe_id.uri(),
            claims: claims_struct(&token_data.claims),
        }))
    }

    async fn fetch_witsvid(
        &self,
        _req: Request<WitsvidRequest>,
    ) -> Result<Response<Self::FetchWITSVIDStream>, Status> {
        Err(Status::unimplemented("FetchWITSVID not yet implemented"))
    }

    async fn fetch_wit_bundles(
        &self,
        _req: Request<WitBundlesRequest>,
    ) -> Result<Response<Self::FetchWITBundlesStream>, Status> {
        Err(Status::unimplemented("FetchWITBundles not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::{claims_struct, within_max_age};
    use std::time::Duration;

    const BOUND: Duration = Duration::from_secs(60);

    /// The expected value is written out by hand rather than round-tripped, so
    /// the conversion is compared against the protobuf encoding of the payload
    /// and not against itself.
    #[test]
    fn the_validated_payload_reaches_the_consumer_as_a_struct() {
        use prost_types::value::Kind;

        let payload = serde_json::json!({
            "spiffe_id": "spiffe://ssh.local/unix/1000",
            "exp": 1_700_000_000u64,
            "hire": { "identity_assurance": "iaa1", "presence": "none" },
            "aud": ["one", "two"],
        });

        let fields = claims_struct(&payload)
            .expect("a JWT payload is an object")
            .fields;

        assert_eq!(
            fields["spiffe_id"].kind,
            Some(Kind::StringValue("spiffe://ssh.local/unix/1000".to_owned()))
        );
        assert_eq!(fields["exp"].kind, Some(Kind::NumberValue(1_700_000_000.0)));
        assert_eq!(
            fields["aud"].kind,
            Some(Kind::ListValue(prost_types::ListValue {
                values: vec![
                    prost_types::Value {
                        kind: Some(Kind::StringValue("one".to_owned()))
                    },
                    prost_types::Value {
                        kind: Some(Kind::StringValue("two".to_owned()))
                    },
                ]
            }))
        );

        // The field this RPC exists to carry: without it "validated" cannot be
        // told apart from "authenticated".
        let Some(Kind::StructValue(hire)) = &fields["hire"].kind else {
            panic!("hire must be a nested struct: {:?}", fields["hire"]);
        };
        assert_eq!(
            hire.fields["identity_assurance"].kind,
            Some(Kind::StringValue("iaa1".to_owned()))
        );
    }

    #[test]
    fn an_observation_younger_than_the_bound_is_served() {
        assert!(within_max_age(Some(Duration::from_secs(59)), Some(BOUND)));
    }

    #[test]
    fn an_observation_older_than_the_bound_is_refused() {
        assert!(!within_max_age(Some(Duration::from_secs(61)), Some(BOUND)));
    }

    #[test]
    fn an_observation_exactly_at_the_bound_is_refused() {
        // Strictly younger. This is the boundary that decides what
        // `hire_max_age=0` means, and it is why zero needs no special case.
        assert!(!within_max_age(Some(BOUND), Some(BOUND)));
        assert!(!within_max_age(Some(Duration::ZERO), Some(Duration::ZERO)));
    }

    #[test]
    fn an_unmeasurable_age_satisfies_no_bound() {
        // `Claim::age_at` returns None for an observation dated in the future.
        assert!(!within_max_age(None, Some(BOUND)));
    }

    #[test]
    fn no_bound_asks_no_question() {
        assert!(within_max_age(Some(Duration::from_secs(86_400)), None));
        assert!(within_max_age(None, None));
    }
}
