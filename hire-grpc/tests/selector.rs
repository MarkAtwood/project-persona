//! `JWTSVIDRequest.spiffe_id` selects what gets proved (hire-5s4b.87).
//!
//! Two rules are under test here and they are the same rule seen from both
//! sides. Naming an identity is the consent to prove it, so a selector reaches
//! a source that may prompt — and a selector that cannot be proved is
//! `NOT_FOUND` rather than a different identity with status OK.
//!
//! The substitution is what made this worth a test rather than a comment: the
//! response carries a per-consumer pseudonym, not the requested ID, so a caller
//! comparing the two cannot tell a substituted identity from ordinary
//! pseudonymisation by inspection.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
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

/// A test double whose proof cost and willingness to prove are both dialled in.
#[derive(Debug)]
struct Source {
    name: &'static str,
    cost: ProofCost,
    provable: bool,
}

#[async_trait]
impl Attestor for Source {
    fn name(&self) -> &str {
        self.name
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![common::candidate(self.name).with_proof_cost(self.cost)])
    }

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        if !self.provable {
            return Err(AttestorError::ChallengeFailed("declined".into()));
        }
        Ok(vec![common::possession(candidate, challenge)])
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
    format!("/tmp/hire-selector-{nanos}-{seq}.sock")
}

/// The SPIFFE ID the test doubles all name, before pseudonymisation.
fn offered_id() -> String {
    format!("spiffe://ssh.local/{}", common::candidate("any").path)
}

/// Run one FetchJWTSVID against a daemon holding `sources`, and return the
/// issued token or the gRPC status code.
async fn fetch(sources: Vec<Source>, spiffe_id: &str) -> Result<String, tonic::Code> {
    let socket_path = tmp_socket_path();
    let signer = Arc::new(SvidSigner::new().unwrap());
    let bundles = Arc::new(TrustBundleStore::new());
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));
    let service = WorkloadApiService::new(
        signer,
        bundles,
        sources
            .into_iter()
            .map(|s| Arc::new(s) as Arc<dyn Attestor>)
            .collect(),
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

    let result = SpiffeWorkloadApiClient::new(channel)
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: spiffe_id.to_owned(),
        })
        .await
        .map(|r| {
            r.into_inner()
                .svids
                .into_iter()
                .next()
                .expect("one svid")
                .svid
        })
        .map_err(|s| s.code());

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
    result
}

/// The `hire.sources` array from an issued token, which names the attestor
/// whose claim was used.
fn sources_of(token: &str) -> Vec<String> {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url claims");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["hire"]["sources"]
        .as_array()
        .expect("hire.sources")
        .iter()
        .map(|v| v.as_str().expect("a source name").to_owned())
        .collect()
}

fn interactive(name: &'static str) -> Source {
    Source {
        name,
        cost: ProofCost::Interactive,
        provable: true,
    }
}

fn silent(name: &'static str) -> Source {
    Source {
        name,
        cost: ProofCost::Silent,
        provable: true,
    }
}

#[tokio::test]
async fn naming_an_identity_is_the_consent_to_prove_it() {
    // The same source, the same request, differing only in whether the caller
    // named what it wanted. Unnamed it is skipped for possibly prompting;
    // named it is proved, because the prompt it may cost is the one the caller
    // asked for. This is the whole path by which gpg and ssh-agent are reachable
    // at all.
    assert_eq!(
        fetch(vec![interactive("gpg-like")], "").await.unwrap_err(),
        tonic::Code::Unauthenticated,
        "an unnamed request must not reach a source that may prompt"
    );

    let token = fetch(vec![interactive("gpg-like")], &offered_id())
        .await
        .expect("a named identity must be proved even though proving may prompt");
    assert_eq!(sources_of(&token), vec!["gpg-like"]);
}

#[tokio::test]
async fn a_selector_nobody_can_prove_is_not_found() {
    // Three ways to fail, one answer. A caller able to tell them apart could
    // enumerate which identities this human holds by reading the difference.
    let unknown = "spiffe://ssh.local/key/no-such-key";
    assert_eq!(
        fetch(vec![silent("present")], unknown).await.unwrap_err(),
        tonic::Code::NotFound,
        "an identity nothing offers"
    );

    let declines = Source {
        name: "declines",
        cost: ProofCost::Silent,
        provable: false,
    };
    assert_eq!(
        fetch(vec![declines], &offered_id()).await.unwrap_err(),
        tonic::Code::NotFound,
        "an identity offered but not proven"
    );

    // Above all: not a different identity with status OK.
    assert_eq!(
        fetch(vec![silent("other")], unknown).await.unwrap_err(),
        tonic::Code::NotFound,
        "a selector that cannot be met must never be answered with another identity"
    );
}

#[tokio::test]
async fn a_malformed_selector_is_refused_rather_than_ignored() {
    assert_eq!(
        fetch(vec![silent("present")], "not-a-spiffe-id")
            .await
            .unwrap_err(),
        tonic::Code::InvalidArgument,
    );
}

#[tokio::test]
async fn the_first_registered_attestor_wins_a_tie() {
    // Both prove possession, so both claims are iaa1 and the comparison is a
    // tie. registry.rs appends the Unix account source last precisely so that
    // anything which proved a key beats "the kernel says this uid", and until
    // now that rested on the order of two push calls and nothing else.
    let token = fetch(vec![silent("first"), silent("second")], "")
        .await
        .expect("an SVID");
    assert_eq!(sources_of(&token), vec!["first"]);

    let token = fetch(vec![silent("second"), silent("first")], "")
        .await
        .expect("an SVID");
    assert_eq!(
        sources_of(&token),
        vec!["second"],
        "the tie must follow registration order, not the source name"
    );
}
