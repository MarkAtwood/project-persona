// persona-5s4b.41 AC: a caller the daemon cannot attest gets no SVID.
//
// Driven off-socket on purpose. The branch under test is the refusal, which is
// reached exactly when the connection carries no PeerIdentity — so constructing
// a request without that extension exercises the real code path rather than
// mocking it. The transport half is covered by tests/two_consumers.rs.

use std::sync::Arc;

use async_trait::async_trait;
use persona_attestors::{Attestor, AttestorError, Candidate, Evidence};

mod common;
use persona_core::{SvidSigner, TrustBundleStore};
use persona_grpc::service::WorkloadApiService;
use persona_grpc::workload::spiffe_workload_api_server::SpiffeWorkloadApi;
use persona_grpc::workload::JwtsvidRequest;

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

fn service() -> WorkloadApiService {
    WorkloadApiService::new(
        Arc::new(SvidSigner::new().unwrap()),
        Arc::new(TrustBundleStore::new()),
        vec![Arc::new(ProvingAttestor) as Arc<dyn Attestor>],
    )
}

#[tokio::test]
async fn a_request_with_no_attested_consumer_is_refused() {
    // No PeerIdentity extension: the attestation the transport would have
    // supplied is absent.
    let status = service()
        .fetch_jwtsvid(tonic::Request::new(JwtsvidRequest {
            audience: vec!["https://example.test".into()],
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("an unattested consumer must not receive an SVID");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "consumer could not be attested");
}

#[tokio::test]
async fn the_consumer_gate_runs_before_the_audience_is_parsed() {
    // A trust boundary is checked first: an unidentified caller must not learn
    // whether its audience was well formed, nor whether this user has an identity.
    let status = service()
        .fetch_jwtsvid(tonic::Request::new(JwtsvidRequest {
            audience: vec![],
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("must be refused");

    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "consumer could not be attested");
}
