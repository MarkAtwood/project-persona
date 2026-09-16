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
const SEED: [u8; 32] = [7u8; 32];

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn key_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    push_string(&mut blob, b"ssh-ed25519");
    push_string(&mut blob, signing_key().verifying_key().as_bytes());
    blob
}

/// The candidate the doubles enumerate, named by its real key fingerprint.
///
/// The path is the fingerprint because the verifying constructor binds the
/// signature to the key the candidate names; a made-up path would not verify.
pub fn candidate(source: &str) -> Candidate {
    let fingerprint =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key_blob()));
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
    let mut sig_blob = Vec::new();
    push_string(&mut sig_blob, b"ssh-ed25519");
    push_string(&mut sig_blob, &signing_key().sign(challenge).to_bytes());

    Evidence::Possession(
        ChallengeSignature::verify_ssh_ed25519(candidate, challenge, &key_blob(), &sig_blob)
            .expect("the test key's own signature over the challenge must verify"),
    )
}
