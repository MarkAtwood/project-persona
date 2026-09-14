// persona-okek AC2. `CandidateOnlyAttestor` deliberately implements no
// `prove()`. If `Attestor::prove` ever loses its default body this file stops
// compiling — that is the "deleting every prove() implementation still
// compiles" half of the criterion, checked by the compiler, with no assertion
// to rot.
//
// The runtime half: a candidate that nothing proved yields no claim, so the
// daemon declines with the same `svid_denied` / "no identity claims available"
// path already observed on macOS.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use persona_attestors::{Attestor, AttestorError, Candidate, SelfAssertedDomain};
use persona_core::{SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use persona_grpc::{
    service::WorkloadApiService, workload::spiffe_workload_api_client::SpiffeWorkloadApiClient,
    workload::JwtsvidRequest,
};

#[derive(Debug)]
struct CandidateOnlyAttestor;

#[async_trait]
impl Attestor for CandidateOnlyAttestor {
    fn name(&self) -> &str {
        "candidate-only"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![Candidate::new(
            "candidate-only",
            SelfAssertedDomain::SshLocal,
            "user/testuser",
            "Test User",
        )])
    }
}

fn tmp_socket_path() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/persona-noprove-{nanos}-{seq}.sock")
}

/// Start a daemon whose only attestor can enumerate but cannot prove, and
/// return a connected client plus a teardown guard.
async fn start_daemon(
    socket_path: &str,
) -> (
    SpiffeWorkloadApiClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::new(
        TrustDomain::SshLocal,
        vec![signer.public_key_der().to_vec()],
        serde_json::json!({ "keys": [] }),
    ));

    let service = WorkloadApiService::new(
        signer,
        bundles,
        vec![Arc::new(CandidateOnlyAttestor) as Arc<dyn Attestor>],
    );

    let sock_for_server = socket_path.to_owned();
    let handle = tokio::spawn(async move {
        persona_grpc::server::serve(std::path::Path::new(&sock_for_server), service)
            .await
            .expect("server error");
    });

    sleep(Duration::from_millis(100)).await;

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

    (SpiffeWorkloadApiClient::new(channel), handle)
}

#[tokio::test]
async fn attestor_without_prove_issues_nothing() {
    let socket_path = tmp_socket_path();
    let (mut client, handle) = start_daemon(&socket_path).await;

    let status = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec!["https://example.test".into()],
            spiffe_id: String::new(),
        })
        .await
        .expect_err("a candidate with no evidence must not yield an SVID");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "no identity claims available");

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}

#[tokio::test]
async fn attestor_without_prove_cannot_satisfy_hardware_presence() {
    let socket_path = tmp_socket_path();
    let (mut client, handle) = start_daemon(&socket_path).await;

    let status = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec!["https://example.test?persona_require_presence=hardware".into()],
            spiffe_id: String::new(),
        })
        .await
        .expect_err("hardware presence must not be satisfiable without evidence");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
}
