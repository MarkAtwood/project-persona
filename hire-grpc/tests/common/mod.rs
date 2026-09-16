// Each integration test in this directory is its own binary and compiles its
// own copy of this module, so anything the binary at hand does not call reads
// as dead. Nothing here is unused -- every item has a caller in some sibling.
#![allow(dead_code)]

//! A real ed25519 key the test doubles in this directory prove possession of.
//!
//! One module rather than a copy per test binary. The SSH key blob and the
//! signature blob have to agree byte for byte with
//! `ChallengeSignature::verify_ssh_ed25519`, and three copies of that framing
//! are three copies free to drift apart — the same failure `spiffe_path()`
//! exists to prevent one layer up.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use hire_attestors::{Candidate, ChallengeSignature, Evidence, ProofCost, SelfAssertedDomain};

/// A fixed seed rather than `SigningKey::generate`: the doubles need
/// determinism, not randomness, and a seed sidesteps the `rand_core` version
/// question between this workspace and dalek 2.x entirely.
const SEED: u8 = 7;

/// One of several distinct identities the doubles can prove.
///
/// A second key exists because a second *identity* does: tests about returning
/// several SVIDs cannot be written with one, and a candidate whose path did not
/// come from a real key would not verify — the verifying constructor binds the
/// signature to the key the candidate names.
pub struct TestKey {
    seed: u8,
}

/// The identity backed by seed `seed`. Two different seeds are two different
/// keys and therefore two different SPIFFE paths.
pub fn key(seed: u8) -> TestKey {
    TestKey { seed }
}

impl TestKey {
    /// The candidate this key backs, named by its real fingerprint.
    pub fn candidate(&self, source: &str) -> Candidate {
        candidate_for(self.seed, source)
    }

    /// Sign `challenge` with this key and verify it, as the ssh attestor does.
    pub fn possession(&self, candidate: &Candidate, challenge: &[u8]) -> Evidence {
        possession_for(self.seed, candidate, challenge)
    }
}

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_blob(seed: u8) -> Vec<u8> {
    let mut blob = Vec::new();
    push_string(&mut blob, b"ssh-ed25519");
    push_string(&mut blob, signing_key(seed).verifying_key().as_bytes());
    blob
}

/// The candidate the doubles enumerate, named by its real key fingerprint.
///
/// The path is the fingerprint because the verifying constructor binds the
/// signature to the key the candidate names; a made-up path would not verify.
pub fn candidate(source: &str) -> Candidate {
    candidate_for(SEED, source)
}

fn candidate_for(seed: u8, source: &str) -> Candidate {
    let fingerprint =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key_blob(seed)));
    Candidate::new(
        source,
        SelfAssertedDomain::SshLocal,
        format!("key/{fingerprint}"),
        "Test User",
    )
    // Honest rather than convenient: the double signs with a fixed key held in
    // this process, so proving it cannot reach a human by any path. Without the
    // declaration FetchJWTSVID's consent gate skips it and every test in this
    // directory that expects an issued SVID stops seeing one.
    .with_proof_cost(ProofCost::Silent)
}

/// Sign `challenge` with the test key and verify it, exactly as the ssh
/// attestor does.
///
/// This is a genuine signature through the real verifying constructor, so these
/// doubles now exercise the same path a live agent does. Before hire-5s4b.116
/// they passed the challenge itself as the "signature", which bound nothing.
pub fn possession(candidate: &Candidate, challenge: &[u8]) -> Evidence {
    possession_for(SEED, candidate, challenge)
}

fn possession_for(seed: u8, candidate: &Candidate, challenge: &[u8]) -> Evidence {
    let mut sig_blob = Vec::new();
    push_string(&mut sig_blob, b"ssh-ed25519");
    push_string(&mut sig_blob, &signing_key(seed).sign(challenge).to_bytes());

    Evidence::Possession(
        ChallengeSignature::verify_ssh_ed25519(candidate, challenge, &key_blob(seed), &sig_blob)
            .expect("the test key's own signature over the challenge must verify"),
    )
}
