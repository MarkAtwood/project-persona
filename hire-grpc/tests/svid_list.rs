//! FetchJWTSVID returns every silently-provable identity, tagged (hire-jl4j.2).
//!
//! `workload.proto` calls `svids` "the list of returned JWT-SVIDs" and defines
//! `hint` as guidance "when more than one SVID is returned", so the list is the
//! conformant shape and returning one was the deviation.
//!
//! Two rules, and the second is what makes the first safe: the order is
//! documented but ADVISORY, and the tag is NORMATIVE. A caller may read
//! `svids[0]` and stop; a caller that needs a particular kind of identity reads
//! the tag and chooses, and is never required to sort-order to be correct.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

use hire_attestors::{
    AttainableAssurance, Attestor, AttestorError, Candidate, Evidence, ProofCost,
};
use hire_core::{SvidHint, SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use hire_grpc::{
    service::WorkloadApiService, workload::spiffe_workload_api_client::SpiffeWorkloadApiClient,
    workload::Jwtsvid, workload::JwtsvidRequest,
};

mod common;

const AUDIENCE: &str = "https://test.example.com";

/// A source that proves one identity, keyed by its own seed.
///
/// `attains` is what the candidate declares it *could* reach; the claim's real
/// tier comes from the evidence and is `iaa1` for every double here, since
/// possession is all any of them has. That mismatch is deliberate — it is the
/// property `AttainableAssurance` exists to keep, and a sort that read the
/// declaration instead of the proof would order these wrongly.
#[derive(Debug)]
struct Source {
    name: &'static str,
    seed: u8,
    attains: AttainableAssurance,
    cost: ProofCost,
}

#[async_trait]
impl Attestor for Source {
    fn name(&self) -> &str {
        self.name
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        Ok(vec![common::key(self.seed)
            .candidate(self.name)
            .with_attainable(self.attains)
            .with_proof_cost(self.cost)])
    }

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        Ok(vec![common::key(self.seed).possession(candidate, challenge)])
    }
}

fn source(name: &'static str, seed: u8) -> Source {
    Source {
        name,
        seed,
        attains: AttainableAssurance::Iaa1,
        cost: ProofCost::Silent,
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
    format!("/tmp/hire-svidlist-{nanos}-{seq}.sock")
}

async fn fetch_all(sources: Vec<Source>) -> Vec<Jwtsvid> {
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

    let svids = SpiffeWorkloadApiClient::new(channel)
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![AUDIENCE.to_owned()],
            spiffe_id: String::new(),
        })
        .await
        .expect("FetchJWTSVID RPC failed")
        .into_inner()
        .svids;

    handle.abort();
    let _ = std::fs::remove_file(&socket_path);
    svids
}

/// The `hire` claim block of an issued token.
fn hire_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url claims");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["hire"].clone()
}

#[tokio::test]
async fn every_silently_provable_identity_is_returned_once() {
    let svids = fetch_all(vec![
        source("first", 1),
        source("second", 2),
        source("third", 3),
    ])
    .await;
    assert_eq!(svids.len(), 3, "one SVID per distinct identity");

    // Distinct identities get distinct pseudonyms, so a caller cannot be handed
    // the same subject twice under different tags.
    let mut ids: Vec<&str> = svids.iter().map(|s| s.spiffe_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3, "pseudonyms must be distinct per identity");
}

#[tokio::test]
async fn one_identity_proved_twice_is_returned_once() {
    // Two sources, one key: the same SPIFFE ID proven twice is one identity.
    // Handing a caller two tokens for one subject makes it choose between
    // indistinguishable options.
    let svids = fetch_all(vec![source("first", 9), source("second", 9)]).await;
    assert_eq!(svids.len(), 1);
    // The survivor is the one the sort put first, so the registration-order
    // tiebreak decides which source is named.
    assert_eq!(hire_claims(&svids[0].svid)["sources"][0], "first");
}

#[tokio::test]
async fn the_tag_says_what_the_token_says() {
    let svids = fetch_all(vec![source("only", 4)]).await;
    let hint: SvidHint = svids[0].hint.parse().expect("the hint must parse back");
    let claims = hire_claims(&svids[0].svid);

    // The whole reason the tag reuses the claim block's vocabulary: a caller
    // reading the tag and a caller decoding the token learn the same things.
    assert_eq!(hint.source, claims["sources"][0].as_str().unwrap());
    assert_eq!(
        hint.identity_assurance.to_string(),
        claims["identity_assurance"].as_str().unwrap()
    );
    assert_eq!(
        hint.presence.to_string() != "none",
        claims["presence"]["present"].as_bool().unwrap(),
        "the tag's presence level and the claim block's boolean must agree"
    );
    assert!(hint.age < 60, "a just-issued observation is seconds old");
}

#[tokio::test]
async fn an_interactive_source_stays_out_of_the_list() {
    // The consent boundary holds for the plural answer too: the list is what
    // can be proved without asking anybody, and nothing else.
    let mut prompts = source("prompts", 5);
    prompts.cost = ProofCost::Interactive;
    let svids = fetch_all(vec![source("silent", 6), prompts]).await;

    assert_eq!(svids.len(), 1);
    assert_eq!(hire_claims(&svids[0].svid)["sources"][0], "silent");
}

#[tokio::test]
async fn the_order_follows_the_proof_and_not_the_declaration() {
    // `second` declares it could reach iaa3 and proves iaa1 like everything
    // else here. A sort that read the declaration would put it first, which is
    // exactly the confusion the Candidate/Claim split exists to prevent.
    let mut boastful = source("second", 8);
    boastful.attains = AttainableAssurance::Iaa3;
    let svids = fetch_all(vec![source("first", 7), boastful]).await;

    assert_eq!(svids.len(), 2);
    assert_eq!(
        hire_claims(&svids[0].svid)["sources"][0],
        "first",
        "a tier nobody proved must not order the list"
    );
}
