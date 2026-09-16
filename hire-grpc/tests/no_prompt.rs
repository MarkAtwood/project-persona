//! FetchJWTSVID never asks a human anything.
//!
//! The epic constraint (hire-jl4j): this RPC is reachable by any attested
//! consumer, so it may prove only what can be proved silently. A candidate
//! declaring [`ProofCost::Interactive`] must not reach `prove()` at all — not
//! be proved and discarded, not be proved and refused, not reached.
//!
//! `TouchCounter` records whether `prove()` ran. The same attestor is started
//! twice, once declaring each cost, and the two runs differ in nothing else —
//! so the silent run is what proves the interactive run was skipped for the
//! declared cost rather than for being broken.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use hire_attestors::{Attestor, AttestorError, Candidate, Evidence, ProofCost};
use hire_core::{SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use hire_grpc::{
    service::WorkloadApiService, workload::spiffe_workload_api_client::SpiffeWorkloadApiClient,
    workload::JwtsvidRequest,
};

mod common;

const AUDIENCE: &str = "https://test.example.com";

/// An attestor that can genuinely prove, and counts how often it was asked.
#[derive(Debug)]
struct TouchCounter {
    cost: ProofCost,
    proofs: Arc<AtomicUsize>,
}

#[async_trait]
impl Attestor for TouchCounter {
    fn name(&self) -> &str {
        "touch-counter"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![
            common::candidate("touch-counter").with_proof_cost(self.cost)
        ])
    }

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        // Stands in for the pinentry dialog or the blinking key. Counted before
        // the proof, because a prompt a user dismissed still interrupted them.
        self.proofs.fetch_add(1, Ordering::SeqCst);
        Ok(vec![common::possession(candidate, challenge)])
    }
}

fn tmp_socket_path() -> String {
    use std::sync::atomic::AtomicU32;
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/hire-noprompt-{nanos}-{seq}.sock")
}

/// Run one FetchJWTSVID against a daemon whose only attestor declares `cost`,
/// and report whether an SVID came back and how often `prove()` was asked.
async fn fetch_once(cost: ProofCost) -> (bool, usize) {
    let socket_path = tmp_socket_path();
    let proofs = Arc::new(AtomicUsize::new(0));
    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));
    let service = WorkloadApiService::new(
        signer,
        bundles,
        vec![Arc::new(TouchCounter {
            cost,
            proofs: Arc::clone(&proofs),
        }) as Arc<dyn Attestor>],
    );

    let sock = socket_path.clone();
    let handle = tokio::spawn(async move {
        hire_grpc::server::serve(std::path::Path::new(&sock), service)
            .await
            .expect("server error");
    });
    sleep(Duration::from_millis(100)).await;

    let path = socket_path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .expect("connect to daemon");

    let issued = SpiffeWorkloadApiClient::new(channel)
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: String::new(),
        })
        .await
        .is_ok();

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
    (issued, proofs.load(Ordering::SeqCst))
}

#[tokio::test]
async fn an_interactive_candidate_is_never_proved_by_fetch_jwtsvid() {
    let (issued, proofs) = fetch_once(ProofCost::Silent).await;
    assert!(issued, "the silent control must be issued an SVID");
    assert_eq!(proofs, 1, "the silent control must have been proved once");

    let (issued, proofs) = fetch_once(ProofCost::Interactive).await;
    assert_eq!(
        proofs, 0,
        "FetchJWTSVID asked a human: prove() ran for a candidate that declared it may prompt"
    );
    assert!(
        !issued,
        "an identity nobody may be prompted for must not be issued either"
    );
}
