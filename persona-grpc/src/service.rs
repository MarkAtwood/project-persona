use std::pin::Pin;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use persona_attestors::{Attestor, Claim};
use persona_core::{AudienceExtensions, PresenceLevel, SvidSigner, TrustBundleStore};

use crate::consumer_attest::PeerIdentity;
use crate::workload::{
    spiffe_workload_api_server::SpiffeWorkloadApi, JwtBundlesRequest, JwtBundlesResponse,
    JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest, ValidateJwtsvidResponse,
    WitBundlesRequest, WitBundlesResponse, WitsvidRequest, WitsvidResponse, X509BundlesRequest,
    X509BundlesResponse, X509svidRequest, X509svidResponse,
};

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

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send + 'static>>;

/// A fresh 32-byte challenge, handed to `prove()` so that an attestor which signs it
/// produces something specific to this request rather than replayable.
///
/// Nothing verifies that binding yet. No attestor implements `prove()`, so no signature
/// exists to check, and `Claim::derive` is not given the challenge and so could not check
/// one if it did. Whoever implements the first real `prove()` has to close that: the
/// challenge must reach the verifier alongside the assertion, and the assertion must be
/// checked against it and against the candidate's key. Tracked as persona-5s4b.116.
fn new_challenge() -> Result<[u8; 32], Status> {
    use rand_core::{OsRng, RngCore as _};
    let mut buf = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| Status::internal("challenge generation failed"))?;
    Ok(buf)
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream = BoxStream<X509svidResponse>;
    type FetchX509BundlesStream = BoxStream<X509BundlesResponse>;
    type FetchJWTBundlesStream = BoxStream<JwtBundlesResponse>;
    type FetchWITSVIDStream = BoxStream<WitsvidResponse>;
    type FetchWITBundlesStream = BoxStream<WitBundlesResponse>;

    // persona-4qm: X.509-SVID issuance not yet implemented
    async fn fetch_x509svid(
        &self,
        _req: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        Err(Status::unimplemented(
            "X.509-SVID issuance not yet implemented",
        ))
    }

    // persona-rbu: Return X.509 bundles for all active trust domains
    async fn fetch_x509_bundles(
        &self,
        _req: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        let bundles = self
            .bundles
            .snapshot()
            .into_iter()
            .map(|b| {
                // Concatenate all DER-encoded CA certs for this trust domain.
                let der_blob: Vec<u8> = b.x509_authorities.into_iter().flatten().collect();
                (b.trust_domain.to_string(), der_blob)
            })
            .collect();
        let response = X509BundlesResponse {
            crl: vec![],
            bundles,
        };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // persona-rbu: Return JWKS bundles for all active trust domains
    async fn fetch_jwt_bundles(
        &self,
        _req: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        let bundles = self
            .bundles
            .snapshot()
            .into_iter()
            .map(|b| {
                let jwks_bytes = serde_json::to_vec(&b.jwt_authorities).unwrap_or_default();
                (b.trust_domain.to_string(), jwks_bytes)
            })
            .collect();
        let response = JwtBundlesResponse { bundles };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // persona-rrv: JWT-SVID issuance
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
                let Some(claim) = Claim::derive(&candidate, &evidence) else {
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

        // Presence gate. `require_presence` is the strictest level named by any
        // audience, so satisfying it satisfies every audience the token names.
        if require_presence > claim.presence() {
            let reason = format!(
                "required presence level not satisfied (need {require_presence:?}, have {:?})",
                claim.presence()
            );
            tracing::info!(event = "svid_denied", reason = %reason);
            return Err(Status::unauthenticated(reason));
        }

        // ponytail: timestamps as Unix seconds | upgrade to RFC 3339 strings when chrono added
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let present_until = now_secs + 300; // 5 min presence TTL

        let persona_ext = serde_json::json!({
            "root_trust_domain": claim.spiffe_id().trust_domain.to_string(),
            "sources": [claim.source()],
            "identity_assurance": claim.assurance().to_string(),
            "presence": {
                "present": claim.presence() != PresenceLevel::None,
                "attested_by": claim.source(),
                "attested_at": now_secs,
                "present_until": present_until,
            },
            "auth_methods": [claim.source()],
        });

        // The root identity is an input to derivation and never an output. There
        // is no branch here that can emit claim.spiffe_id().uri().
        let spiffe_id_str = self
            .signer
            .pseudonymous_id(claim.spiffe_id(), &consumer)
            .uri();
        let audiences: Vec<&str> = exts.iter().map(|e| e.audience.as_str()).collect();

        let token = self
            .signer
            .sign_jwt_svid(&spiffe_id_str, &audiences, persona_ext)
            .map_err(|e| {
                let reason = e.to_string();
                tracing::info!(event = "svid_denied", reason = %reason);
                Status::internal(reason)
            })?;

        // Deliberately no root identity here. Logging it beside the pseudonym would
        // write the join table this feature exists to withhold, and personad is a
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
            presence = ?claim.presence(),
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

    // persona-t67: JWT-SVID validation
    async fn validate_jwtsvid(
        &self,
        req: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let req = req.into_inner();
        if req.svid.is_empty() {
            return Err(Status::invalid_argument("svid must not be empty"));
        }

        // Get the local trust bundle's public key for verification.
        let pub_key_der = self.signer.public_key_der();
        let decoding_key = DecodingKey::from_ec_der(pub_key_der);

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[&req.audience]);

        // Decode and validate: checks signature, exp, aud.
        let token_data = decode::<serde_json::Value>(&req.svid, &decoding_key, &validation)
            .map_err(|e| Status::invalid_argument(format!("JWT validation failed: {e}")))?;

        let spiffe_id = token_data
            .claims
            .get("spiffe_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if spiffe_id.is_empty() {
            return Err(Status::invalid_argument("JWT missing spiffe_id claim"));
        }

        tracing::info!(
            event = "svid_validated",
            spiffe_id = %spiffe_id,
            audience = %req.audience,
        );

        // ponytail: empty claims in ValidateJWTSVID response | upgrade to prost_types::Struct conversion when needed
        Ok(Response::new(ValidateJwtsvidResponse {
            spiffe_id,
            claims: None,
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
