#![cfg(unix)]
//! End-to-end against the real kernel and the real passwd database.
//!
//! Nothing here skips, and that is the property under test as much as any
//! assertion: the other eight sources need an agent, a daemon, a card or a
//! cached token, and this one needs only a running process. A skip path in this
//! file would mean the attestor had grown a prerequisite.
//!
//! The oracle is the `id` utility. It is a separate binary reached through a
//! separate code path from the `getpwuid_r` call under test, but both
//! ultimately consult the same NSS or Open Directory backend, so this is a
//! cross-path check and not an externally sourced vector — the same caveat, for
//! the same reason, as `persona-grpc/src/consumer_attest.rs:273-275`. There is
//! no external vector for what this machine's account is called: the fact is
//! local by definition, so the best available oracle is a second implementation
//! of the same lookup. `id` rather than `getent` because POSIX mandates `id`
//! and both CI legs carry it, while `getent` is absent on macOS and on musl.
//!
//! Nothing here mutates the process environment. The oracle below is a
//! fork/exec that reads the `environ` array, and a sibling thread calling
//! `setenv` can reallocate that array underneath it, so the one test that
//! needs a stripped environment lives in `unix_account_bare_env.rs` and gets
//! a process to itself.

use std::process::Command;
use std::time::SystemTime;

use persona_attestors::{Attestor, Candidate, Claim, Evidence, UnixAttestor};
use persona_core::{IdentityAssurance, PresenceLevel, TrustDomain};

/// The uid `id -u` reports for this process.
fn oracle_uid() -> u32 {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .expect("id is a POSIX utility and must be present");
    assert!(out.status.success(), "id -u exited {}", out.status);
    String::from_utf8(out.stdout)
        .expect("id -u prints a decimal number")
        .trim()
        .parse()
        .expect("id -u prints a decimal number")
}

/// The display name the attestor owes for `uid`, determined without asking it.
///
/// Two answers rather than one, and neither is a skip: when `id -un` resolves a
/// name, that name is what the passwd database holds and the attestor must
/// report it; when `id -un` fails, no entry maps the uid — a container with no
/// `/etc/passwd` — and the documented fallback is what the attestor must
/// report. The oracle decides which case this machine is in.
fn oracle_display_name(uid: u32) -> String {
    let out = Command::new("id")
        .arg("-un")
        .output()
        .expect("id is a POSIX utility and must be present");
    if out.status.success() {
        String::from_utf8(out.stdout)
            .expect("an account name is UTF-8 on any machine this runs on")
            .trim()
            .to_owned()
    } else {
        format!("uid {uid}")
    }
}

async fn sole_candidate(attestor: &UnixAttestor) -> Candidate {
    let mut candidates = attestor
        .enumerate()
        .await
        .expect("the kernel cannot refuse the question");
    assert_eq!(
        candidates.len(),
        1,
        "a process runs under exactly one account, so this source enumerates \
         exactly one candidate: {candidates:?}"
    );
    candidates.remove(0)
}

#[tokio::test]
async fn enumerate_names_the_one_account_the_oracle_names() {
    let uid = oracle_uid();
    let expected_name = oracle_display_name(uid);

    let attestor = UnixAttestor::new();
    let candidate = sole_candidate(&attestor).await;

    assert_eq!(
        candidate.source,
        attestor.name(),
        "the issued token echoes candidate.source, not Attestor::name, so the \
         two must not drift apart"
    );
    assert_eq!(candidate.source, "unix");
    assert_eq!(
        candidate.path,
        format!("unix/{uid}"),
        "the SPIFFE path names the uid the oracle reports"
    );
    assert_eq!(
        candidate.display_name, expected_name,
        "getpwuid_r and id -un disagree about who this account is"
    );
    assert_eq!(
        candidate.spiffe_id().trust_domain,
        TrustDomain::SshLocal,
        "personad seeds a trust bundle only for ssh.local, so a candidate under \
         any other domain would fail the daemon's own ValidateJWTSVID"
    );
}

#[tokio::test]
async fn prove_yields_one_platform_assertion_and_derives_a_claim() {
    let attestor = UnixAttestor::new();
    let candidate = sole_candidate(&attestor).await;
    let challenge = [0xa5u8; 32];

    // Brackets the clock rather than using it as an oracle.
    let before = SystemTime::now();
    let evidence = attestor
        .prove(&candidate, &challenge)
        .await
        .expect("the account this process runs under always proves");
    let after = SystemTime::now();

    assert_eq!(
        evidence.len(),
        1,
        "one question asked, one answer: {evidence:?}"
    );
    assert!(
        matches!(evidence[0], Evidence::PlatformAssertion(_)),
        "the OS attests nothing cryptographic, so any other variant would be an \
         overclaim: {:?}",
        evidence[0]
    );

    let claim = Claim::derive(&candidate, &challenge, &evidence)
        .expect("a platform assertion always survives the challenge filter");
    assert_eq!(claim.source(), "unix");
    assert_eq!(claim.spiffe_id().path, candidate.path);
    assert_eq!(claim.spiffe_id().trust_domain, TrustDomain::SshLocal);
    assert_eq!(claim.display_name(), candidate.display_name);
    assert!(
        claim.attested_at() >= before && claim.attested_at() <= after,
        "prove() stamps the instant it asked the kernel, so the claim is dated \
         from inside this call"
    );

    // The accepted cost, asserted rather than described: there is nothing for a
    // nonce to bind, so the same evidence answers a challenge it never saw.
    // This is the one attestor with no replay defence, and a reader who expects
    // ssh_agent_live.rs's `is_none()` here should find the difference pinned.
    assert!(
        Claim::derive(&candidate, b"a different challenge", &evidence).is_some(),
        "a platform assertion is deliberately unbound; if it became \
         challenge-bound, that is a real improvement and this test is the \
         record of what changed"
    );
}

/// Pins the tier. Read the assertion messages before changing either level.
#[tokio::test]
async fn a_unix_account_is_iaa1_with_no_presence_because_a_uid_is_not_a_seat() {
    let attestor = UnixAttestor::new();
    let candidate = sole_candidate(&attestor).await;
    let challenge = [0x17u8; 32];
    let evidence = attestor.prove(&candidate, &challenge).await.expect("prove");
    let claim = Claim::derive(&candidate, &challenge, &evidence).expect("derive");

    assert_eq!(
        claim.assurance(),
        IdentityAssurance::Iaa1,
        "SPEC-HIA.md:373 puts a local username at iaa1, in the same bucket as \
         an SSH key and a GPG key. Nothing checked who holds the account, so \
         iaa2 would claim an IdP verified a human and iaa3 would claim \
         hardware did. Raising this is a spec change, not a code change."
    );
    assert_eq!(
        claim.presence(),
        PresenceLevel::None,
        "getuid() says a process runs under an account. It does not say a human \
         is at a seat, so this must never become Session — that would let \
         persona_require_presence be satisfied by a cron job. Reading logind or \
         utmp is a different claim and a separate bead."
    );
}
