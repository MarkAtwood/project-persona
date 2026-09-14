// persona-5s4b.41 AC: two different applications get two different pseudonyms
// for the same user, and each gets the same one every time it runs.
//
// Linux-only, and this is a platform gate with a reason, not an #[ignore].
// Consumers are distinguished by the SHA-256 of their executable, so two real
// consumers means two real binaries. Appending a trailing byte to a copy of the
// test binary changes its hash while leaving it executable — true of ELF, false
// of Mach-O, where arm64 macOS SIGKILLs a binary whose ad-hoc signature no longer
// matches. macOS therefore has no end-to-end proof of this property; say so
// rather than papering over it.
#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use persona_attestors::{Attestor, AttestorError, Candidate, Evidence};

mod common;
use persona_core::{SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use persona_grpc::service::WorkloadApiService;
use persona_grpc::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use persona_grpc::workload::JwtsvidRequest;

const OUT_VAR: &str = "PERSONA_CHILD_OUT";
const SOCK_VAR: &str = "PERSONA_CHILD_SOCK";

#[derive(Debug)]
struct ProvingAttestor;

#[async_trait]
impl Attestor for ProvingAttestor {
    fn name(&self) -> &str {
        "test"
    }
    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![common::candidate("test")])
    }
    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        Ok(vec![common::possession(candidate, challenge)])
    }
}

/// Connect to `sock`, fetch one SVID, write its raw JWT to `out`.
///
/// The whole token, not just the SPIFFE ID: persona-5s4b.118 is about what the
/// claim block around the pseudonym reveals, so the parent needs to read it.
async fn run_as_consumer(sock: String, out: String) {
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = sock.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
        }))
        .await
        .expect("child could not connect");

    let resp = SpiffeWorkloadApiClient::new(channel)
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec!["https://example.test".into()],
            spiffe_id: String::new(),
        })
        .await
        .expect("child FetchJWTSVID failed");

    let token = resp.into_inner().svids[0].svid.clone();
    std::fs::write(out, token).expect("child could not write its result");
}

/// The decoded claims segment of a compact JWS.
fn claims_of(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64url decode of JWT claims segment failed");
    serde_json::from_slice(&bytes).expect("claims segment is not JSON")
}

/// A copy of this test binary at `dest`, with `tag` appended so its hash differs.
fn distinct_copy(dest: &std::path::Path, tag: &[u8]) {
    let me = std::env::current_exe().expect("current_exe");
    std::fs::copy(&me, dest).expect("copy test binary");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dest)
        .expect("open copy for append");
    f.write_all(tag).expect("append tag");
}

/// Run `exe` as a consumer against `sock` and return the raw JWT it received.
///
/// `tokio::process`, not `std::process`: the daemon under test is a task on this
/// same runtime, so blocking the thread on a child that is trying to connect to
/// it deadlocks — the accept loop never runs.
async fn consumer_run(exe: &std::path::Path, sock: &str, out: &std::path::Path) -> String {
    let _ = std::fs::remove_file(out);
    let status = tokio::process::Command::new(exe)
        .args(["--exact", "two_consumers_get_two_pseudonyms", "--nocapture"])
        .env(SOCK_VAR, sock)
        .env(OUT_VAR, out)
        .status()
        .await
        .expect("spawn consumer");
    assert!(
        status.success(),
        "consumer {} failed: {status}",
        exe.display()
    );
    std::fs::read_to_string(out).expect("consumer produced no result")
}

#[tokio::test]
async fn two_consumers_get_two_pseudonyms() {
    // Child mode: this process IS one of the two consumers.
    if let (Ok(sock), Ok(out)) = (std::env::var(SOCK_VAR), std::env::var(OUT_VAR)) {
        run_as_consumer(sock, out).await;
        return;
    }

    // SAFETY: getpid() takes no arguments, has no preconditions and cannot fail.
    let pid = unsafe { libc::getpid() };
    let dir = std::env::temp_dir().join(format!("persona-twoconsumers-{pid}"));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let sock = dir.join("api.sock");
    let sock_str = sock.to_str().expect("utf-8 socket path").to_owned();

    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));
    let service = WorkloadApiService::new(
        signer,
        bundles,
        vec![Arc::new(ProvingAttestor) as Arc<dyn Attestor>],
    );

    let sock_for_server = sock.clone();
    let handle = tokio::spawn(async move {
        persona_grpc::server::serve(&sock_for_server, service)
            .await
            .expect("server error");
    });
    sleep(Duration::from_millis(100)).await;

    let app_a = dir.join("app-a");
    let app_b = dir.join("app-b");
    distinct_copy(&app_a, b"\n# persona test consumer A\n");
    distinct_copy(&app_b, b"\n# persona test consumer B\n");

    let out = dir.join("result");
    let tok_a1 = consumer_run(&app_a, &sock_str, &out).await;
    let tok_b = consumer_run(&app_b, &sock_str, &out).await;
    let tok_a2 = consumer_run(&app_a, &sock_str, &out).await;

    let (ca1, cb, ca2) = (claims_of(&tok_a1), claims_of(&tok_b), claims_of(&tok_a2));
    let id_of = |c: &serde_json::Value| c["sub"].as_str().expect("sub").to_owned();
    let (a1, b, a2) = (id_of(&ca1), id_of(&cb), id_of(&ca2));

    let prefix = "spiffe://ssh.local/pseudonym/";
    assert!(a1.starts_with(prefix), "A got {a1}");
    assert!(b.starts_with(prefix), "B got {b}");
    let root = common::candidate("test").path;
    assert!(!a1.contains(&root) && !b.contains(&root));
    assert_ne!(a1, b, "two applications must not share a pseudonym");
    assert_eq!(
        a2, a1,
        "one application must keep its pseudonym across runs"
    );

    // persona-5s4b.118, accepted and bounded, pinned here so nobody later
    // "fixes" it silently and nobody later re-argues it. The pseudonyms differ,
    // but on a single-identity daemon these three fields are constants shared by
    // every consumer, so a colluding pair can already link on them alone.
    for field in ["root_trust_domain", "sources", "auth_methods"] {
        assert_eq!(
            ca1["persona"][field], cb["persona"][field],
            "{field} is identical across consumers and is the unconditional join key"
        );
    }

    // `attested_at` is published on purpose: withholding it leaves a consumer
    // unable to judge freshness for itself. It is a whole-second value derived
    // from the observation, and the window is derived from it in turn — so
    // neither is the request clock, and two consumers served from ONE
    // observation would receive byte-identical values. That case is not
    // reachable end to end today, because every request re-runs prove() and
    // makes its own observation; a second-granularity equality assertion here
    // would be a coin flip, so the equality is pinned at unit level in
    // persona-attestors/src/claim.rs instead.
    for c in [&ca1, &cb, &ca2] {
        let attested_at = c["persona"]["presence"]["attested_at"]
            .as_u64()
            .expect("attested_at must be whole Unix seconds");
        let present_until = c["persona"]["presence"]["present_until"]
            .as_u64()
            .expect("present_until must be whole Unix seconds");
        assert_eq!(present_until, attested_at + 300);
        assert!(attested_at <= c["iat"].as_u64().expect("iat"));
    }

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
