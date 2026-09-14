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
    workload::{JwtBundlesRequest, JwtsvidRequest, ValidateJwtsvidRequest},
};

const AUDIENCE: &str = "https://test.example.com";

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
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/persona-test-{nanos}-{seq}.sock")
}

/// Start a daemon whose only attestor proves possession, and return a
/// connected client plus a teardown handle.
async fn start_daemon(
    socket_path: &str,
) -> (
    SpiffeWorkloadApiClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));

    let service = WorkloadApiService::new(
        signer,
        bundles,
        vec![Arc::new(TestAttestor) as Arc<dyn Attestor>],
    );

    let sock_for_server = socket_path.to_owned();
    let handle = tokio::spawn(async move {
        persona_grpc::server::serve(std::path::Path::new(&sock_for_server), service)
            .await
            .expect("server error");
    });

    sleep(Duration::from_millis(100)).await;

    (connect(socket_path).await, handle)
}

/// Connect a client to an already-listening daemon socket.
async fn connect(socket_path: &str) -> SpiffeWorkloadApiClient<tonic::transport::Channel> {
    let sock_for_client = socket_path.to_owned();
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
    SpiffeWorkloadApiClient::new(channel)
}

// ── Integration test ──────────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_and_validate_jwt_svid() {
    let socket_path = tmp_socket_path();
    let (mut client, server_handle) = start_daemon(&socket_path).await;

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

    // Check 2b: the issued ID is a pseudonym, and the token carries no trace of
    // the root identity — through `sub`, `spiffe_id`, or any persona claim.
    assert!(
        svid.spiffe_id.starts_with("spiffe://ssh.local/pseudonym/"),
        "consumer must receive a pseudonym, got: {}",
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

    let body = claims.to_string();
    assert!(
        !body.contains("user/testuser") && !body.contains("Test User"),
        "root identity leaked into the token: {body}"
    );

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

// persona-5s4b.47: policy is per-audience, so the gate must see every audience.
// Before the fix this issues a token: element [0] parses to PresenceLevel::None,
// `None > None` is false, and both raw strings are signed into `aud`.
#[tokio::test]
async fn presence_requirement_is_taken_from_every_audience() {
    for order in [
        vec![
            "https://harmless.example".to_owned(),
            "https://bank.example?persona_require_presence=hardware".to_owned(),
        ],
        vec![
            "https://bank.example?persona_require_presence=hardware".to_owned(),
            "https://harmless.example".to_owned(),
        ],
    ] {
        let socket_path = tmp_socket_path();
        let (mut client, handle) = start_daemon(&socket_path).await;

        let status = client
            .fetch_jwtsvid(JwtsvidRequest {
                audience: order,
                spiffe_id: String::new(),
            })
            .await
            .expect_err("a hardware requirement on any audience must gate the request");

        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert!(
            status.message().contains("presence"),
            "must deny at the presence gate, got: {}",
            status.message()
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}

// persona-5s4b.71: a requirement the daemon does not understand is refused,
// never downgraded to no requirement at all.
#[tokio::test]
async fn unrecognised_presence_requirement_is_refused_not_ignored() {
    let socket_path = tmp_socket_path();
    let (mut client, handle) = start_daemon(&socket_path).await;

    for audience in [
        "https://bank.example?persona_require_presence=biometric",
        "https://bank.example?persona_require_presence=Hardware",
        "https://bank.example?persona_max_age=60",
    ] {
        let status = client
            .fetch_jwtsvid(JwtsvidRequest {
                audience: vec![audience.to_owned()],
                spiffe_id: String::new(),
            })
            .await
            .expect_err("an unhonourable persona_ extension must not yield an SVID");
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "audience {audience} must be refused"
        );
    }

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

// The token's `aud` names the relying party, not persona's policy language.
#[tokio::test]
async fn signed_audience_has_persona_params_stripped() {
    let socket_path = tmp_socket_path();
    let (mut client, handle) = start_daemon(&socket_path).await;

    let resp = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![
                "https://app.example?persona_require_presence=none&tenant=acme".to_owned(),
            ],
            spiffe_id: String::new(),
        })
        .await
        .expect("FetchJWTSVID RPC failed");

    let svids = resp.into_inner().svids;
    let parts: Vec<&str> = svids[0].svid.splitn(3, '.').collect();
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64url decode of JWT claims segment failed");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_bytes).expect("JWT claims are not valid JSON");

    let aud = claims["aud"].as_array().expect("aud must be an array");
    assert_eq!(aud.len(), 1);
    assert_eq!(aud[0], "https://app.example?tenant=acme");

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

// ── persona-5s4b.82: validation follows the bundle ────────────────────────────

/// Start a daemon whose published bundle is a *foreign* signer's, while the
/// service signs with its own. The discriminator for persona-5s4b.82: today's
/// code answers the opposite on both halves below.
async fn start_daemon_with_foreign_bundle(
    socket_path: &str,
) -> (
    SpiffeWorkloadApiClient<tonic::transport::Channel>,
    Arc<SvidSigner>,
    tokio::task::JoinHandle<()>,
) {
    let service_signer = Arc::new(SvidSigner::new().unwrap());
    let foreign = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &foreign));

    let service = WorkloadApiService::new(
        service_signer,
        bundles,
        vec![Arc::new(TestAttestor) as Arc<dyn Attestor>],
    );
    let sock = socket_path.to_owned();
    let handle = tokio::spawn(async move {
        persona_grpc::server::serve(std::path::Path::new(&sock), service)
            .await
            .expect("server error");
    });
    sleep(Duration::from_millis(100)).await;
    (connect(socket_path).await, foreign, handle)
}

#[tokio::test]
async fn validate_follows_the_bundle_not_the_in_memory_key() {
    let socket_path = tmp_socket_path();
    let (mut client, foreign, handle) = start_daemon_with_foreign_bundle(&socket_path).await;

    // Signed by the key that IS published, by a signer the service has never
    // seen. Must validate: only a validator that reads the bundle can do this.
    let id = "spiffe://ssh.local/pseudonym/deadbeef";
    let token = foreign
        .sign_jwt_svid(id, &[AUDIENCE], serde_json::json!({}))
        .unwrap();
    let ok = client
        .validate_jwtsvid(ValidateJwtsvidRequest {
            svid: token,
            audience: AUDIENCE.to_owned(),
        })
        .await
        .expect("a token signed by the published key must validate");
    assert_eq!(ok.into_inner().spiffe_id, id);

    // Issued by the service's own signer, whose key is NOT published. Must be
    // refused: the daemon's in-memory key confers no authority.
    let issued = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: String::new(),
        })
        .await
        .expect("FetchJWTSVID RPC failed")
        .into_inner()
        .svids
        .remove(0);
    assert!(
        client
            .validate_jwtsvid(ValidateJwtsvidRequest {
                svid: issued.svid,
                audience: AUDIENCE.to_owned(),
            })
            .await
            .is_err(),
        "a key that is not in the published bundle must not validate anything"
    );

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

#[tokio::test]
async fn validate_refuses_a_trust_domain_with_no_published_authority() {
    let socket_path = tmp_socket_path();
    let signer = Arc::new(SvidSigner::new().unwrap());
    // Deliberately empty: consumer_gate.rs already proves the daemon is
    // constructible with no bundle at all, and issuance stays bundle-independent.
    let bundles = Arc::new(TrustBundleStore::new());
    let service = WorkloadApiService::new(
        Arc::clone(&signer),
        bundles,
        vec![Arc::new(TestAttestor) as Arc<dyn Attestor>],
    );
    let sock = socket_path.clone();
    let handle = tokio::spawn(async move {
        persona_grpc::server::serve(std::path::Path::new(&sock), service)
            .await
            .expect("server error");
    });
    sleep(Duration::from_millis(100)).await;
    let mut client = connect(&socket_path).await;

    let token = signer
        .sign_jwt_svid(
            "spiffe://ssh.local/pseudonym/deadbeef",
            &[AUDIENCE],
            serde_json::json!({}),
        )
        .unwrap();
    assert!(
        client
            .validate_jwtsvid(ValidateJwtsvidRequest {
                svid: token,
                audience: AUDIENCE.to_owned(),
            })
            .await
            .is_err(),
        "a daemon that publishes no authority for a trust domain must not vouch for its tokens"
    );

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

// ── persona-5s4b.96: the oracle is outside this codebase ──────────────────────

#[tokio::test]
async fn a_third_party_verifies_a_token_with_only_the_published_bundle() {
    use tonic::codegen::tokio_stream::StreamExt as _;

    let socket_path = tmp_socket_path();
    let (mut client, handle) = start_daemon(&socket_path).await;

    let svid = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: String::new(),
        })
        .await
        .expect("FetchJWTSVID RPC failed")
        .into_inner()
        .svids
        .remove(0);

    let mut stream = client
        .fetch_jwt_bundles(JwtBundlesRequest {})
        .await
        .expect("FetchJWTBundles RPC failed")
        .into_inner();
    let bundles = stream
        .next()
        .await
        .expect("FetchJWTBundles sent no message")
        .expect("FetchJWTBundles stream error")
        .bundles;
    let jwks = bundles
        .get("spiffe://ssh.local")
        .expect("no bundle published for this daemon's trust domain");

    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("third-party-verify");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("jwks.json"), jwks).unwrap();
    std::fs::write(dir.join("token.jwt"), &svid.svid).unwrap();

    // Everything past this line is outside the daemon: the bytes above are all
    // the verifier gets, and every cryptographic operation is openssl's.
    assert!(
        verify(&dir, "token.jwt").success(),
        "a third party holding only the published bundle could not verify the token"
    );

    // Negative control. Without it, a verifier script that always exits 0 would
    // pass the assertion above.
    let (input, sig) = svid.svid.rsplit_once('.').expect("compact JWS");
    let tail = &sig[sig.len() - 2..];
    let tampered = format!(
        "{input}.{}{}",
        &sig[..sig.len() - 2],
        if tail == "AB" { "CD" } else { "AB" }
    );
    std::fs::write(dir.join("tampered.jwt"), tampered).unwrap();
    assert!(
        !verify(&dir, "tampered.jwt").success(),
        "the external verifier accepted a tampered signature: it is verifying nothing"
    );

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

/// Runs the external verifier. A missing `python3` or `openssl` fails the test;
/// it never skips. "The test suite requires python3 and openssl" is a
/// constraint, and skipping on a missing tool would be a weakened test by the
/// same logic that bans `#[ignore]`.
fn verify(dir: &std::path::Path, token: &str) -> std::process::ExitStatus {
    std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/verify_jwt_svid.py"
        ))
        .arg(dir.join("jwks.json"))
        .arg(dir.join(token))
        .arg(dir)
        .status()
        .expect("python3 is required by the persona test suite (see tests/verify_jwt_svid.py)")
}
