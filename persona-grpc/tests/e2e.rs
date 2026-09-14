use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use persona_attestors::{
    Attestor, AttestorError, Candidate, ChallengeSignature, Evidence, FreshnessResult,
    SelfAssertedDomain, SignedAssertion,
};
use persona_core::{SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use persona_grpc::{
    service::WorkloadApiService,
    workload::spiffe_workload_api_client::SpiffeWorkloadApiClient,
    workload::{JwtsvidRequest, ValidateJwtsvidRequest},
};

// ── Test attestor ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TestAttestor;

#[async_trait]
impl Attestor for TestAttestor {
    fn name(&self) -> &str {
        "test"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![Candidate::new(
            "test",
            SelfAssertedDomain::SshLocal,
            "user/testuser",
            "Test User",
        )])
    }

    // A test double standing in for an attestor that can prove possession.
    // Possession maps to the floor tier (Iaa1 / PresenceLevel::None), which is
    // exactly what the old `Claim::new(..., Iaa1, PresenceLevel::None, ...)`
    // fixture asserted, so the issued token is unchanged.
    async fn prove(
        &self,
        _candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        Ok(vec![Evidence::Possession(ChallengeSignature::new(
            SignedAssertion::new(challenge.to_vec(), "application/test"),
        ))])
    }

    async fn freshness(&self, _candidate: &Candidate) -> Result<FreshnessResult, AttestorError> {
        Ok(FreshnessResult::Fresh)
    }
}

// ── Helper: build a fresh socket path ─────────────────────────────────────────

fn tmp_socket_path() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("/tmp/persona-test-{nanos}.sock")
}

// ── Integration test ──────────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_and_validate_jwt_svid() {
    let socket_path = tmp_socket_path();

    // Build service components.
    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    let local_bundle = TrustBundle::new(
        TrustDomain::SshLocal,
        vec![signer.public_key_der().to_vec()],
        serde_json::json!({ "keys": [] }),
    );
    bundles.upsert(local_bundle);

    let service = WorkloadApiService::new(
        Arc::clone(&signer),
        Arc::clone(&bundles),
        vec![Arc::new(TestAttestor) as Arc<dyn Attestor>],
    );

    // Spawn the server.
    let sock_for_server = socket_path.clone();
    let server_handle = tokio::spawn(async move {
        persona_grpc::server::serve(std::path::Path::new(&sock_for_server), service)
            .await
            .expect("server error");
    });

    // Give the server a moment to bind.
    sleep(Duration::from_millis(100)).await;

    // Connect a client via Unix socket.
    let sock_for_client = socket_path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = sock_for_client.clone();
            async move {
                let stream = UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .expect("client connect failed");

    let mut client = SpiffeWorkloadApiClient::new(channel);

    const AUDIENCE: &str = "https://test.example.com";

    // ── 1. FetchJWTSVID ──────────────────────────────────────────────────────

    let resp = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: String::new(),
        })
        .await
        .expect("FetchJWTSVID RPC failed");

    let svids = resp.into_inner().svids;
    assert!(!svids.is_empty(), "expected at least one SVID");

    let svid = &svids[0];

    // Check 1: non-empty token.
    assert!(!svid.svid.is_empty(), "JWT token must not be empty");

    // Check 2: SPIFFE ID starts with spiffe://.
    assert!(
        svid.spiffe_id.starts_with("spiffe://"),
        "SPIFFE ID must start with spiffe://, got: {}",
        svid.spiffe_id
    );

    // Check 3: decode the middle (claims) segment and parse as JSON.
    let parts: Vec<&str> = svid.svid.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");

    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64url decode of JWT claims segment failed");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_bytes).expect("JWT claims are not valid JSON");

    // Check 4: claims contain "sub" (or spiffe_id) and "aud".
    assert!(
        claims.get("sub").is_some() || claims.get("spiffe_id").is_some(),
        "JWT claims must contain 'sub' or 'spiffe_id', got: {claims}"
    );
    assert!(
        claims.get("aud").is_some(),
        "JWT claims must contain 'aud', got: {claims}"
    );

    // Check 5: ValidateJWTSVID succeeds and returns the correct SPIFFE ID.
    let validate_resp = client
        .validate_jwtsvid(ValidateJwtsvidRequest {
            svid: svid.svid.clone(),
            audience: AUDIENCE.to_owned(),
        })
        .await
        .expect("ValidateJWTSVID RPC failed");

    let validated = validate_resp.into_inner();
    assert_eq!(
        validated.spiffe_id, svid.spiffe_id,
        "validated SPIFFE ID must match the issued SPIFFE ID"
    );

    // Teardown.
    server_handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}
