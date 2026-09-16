//! End-to-end against a real `gpg` and a real `gpg-agent` holding a real key.
//!
//! Exactly one `#[test]`, for the same reason as `ssh_agent_live.rs`: the
//! attestor is aimed at a keyring through the process-global `GNUPGHOME`, and a
//! Cargo integration test file is its own binary, so one test per file means
//! there is nothing to race. A second live test wants a second file, not a
//! constructor taking a home directory.
//!
//! Skips, with a printed reason, where gpg is absent. It generates its own
//! throwaway key in its own home directory and kills its own agent, so it never
//! reads or mutates the developer's keyring.
//!
//! THE HOME DIRECTORY PATH IS SHORT ON PURPOSE. gpg-agent's socket lives inside
//! `GNUPGHOME`, and `sun_path` is 108 bytes: under a deep scratch directory,
//! key generation hangs until it is killed rather than failing with anything a
//! reader could act on.

use std::path::PathBuf;
use std::process::Command;

use hire_attestors::{Attestor, Claim, Evidence, GpgAttestor};
use hire_core::{IdentityAssurance, PresenceLevel, TrustDomain};

const LIVE_UID: &str = "HIRE Live <live@example.invalid>";
const OTHER_UID: &str = "HIRE Other <other@example.invalid>";

/// Kills the agent this test started and removes its keyring, even if an
/// assertion panics, so a failing run leaves neither a process nor a secret key.
struct GnupgHome {
    dir: PathBuf,
}

impl Drop for GnupgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .args(["--kill", "all"])
            .env("GNUPGHOME", &self.dir)
            .output();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn a_real_gpg_key_signs_the_challenge_and_claims_no_presence() {
    if !have("gpg") || !have("gpgconf") {
        eprintln!("skipping: gnupg is not installed on this machine");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hire-gpg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch keyring");
    let home = GnupgHome { dir: dir.clone() };

    // Loopback pinentry with an empty passphrase, for generation only: an
    // unattended key is the point of the fixture. The attestor itself never
    // passes --pinentry-mode, so nothing here teaches it to bypass one.
    //
    // Two keys, because one cannot catch the check that matters most: a
    // verifier that accepted any good signature at all, rather than one by the
    // key the candidate names, passes every assertion a single-key keyring can
    // make. The second key is what a proof signed by the wrong key is made of.
    for uid in [LIVE_UID, OTHER_UID] {
        let generated = Command::new("gpg")
            .args([
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                uid,
                "ed25519",
                "sign",
                "never",
            ])
            .env("GNUPGHOME", &home.dir)
            .output()
            .expect("gpg --quick-generate-key");
        assert!(
            generated.status.success(),
            "key generation failed for {uid}: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
    }

    // Safe in edition 2021, and the whole reason this file holds one test.
    std::env::set_var("GNUPGHOME", &home.dir);

    assert!(GpgAttestor::is_available());
    let attestor = GpgAttestor::new();

    let candidates = attestor.enumerate().await.expect("enumerate");
    let named = |uid: &str| {
        candidates
            .iter()
            .find(|c| c.display_name == uid)
            .unwrap_or_else(|| panic!("the key this test generated must be enumerated: {uid}"))
    };
    let candidate = named(LIVE_UID);
    let other = named(OTHER_UID);
    assert!(candidate.path.starts_with("gpg/"));
    assert_ne!(candidate.path, other.path);

    // The real thing: a real agent signs a real challenge with a real key, and
    // the only constructor for possession evidence checks the result.
    let challenge = [0xa5u8; 32];
    let evidence = attestor
        .prove(candidate, &challenge)
        .await
        .expect("a held gpg key must prove possession");

    let claim = Claim::derive(candidate, &challenge, &evidence)
        .expect("verified possession must yield a claim");

    // A signature proves a key answered, not that anybody was there to ask it.
    // pinentry may or may not have appeared and the daemon cannot tell, so it
    // claims nothing about a human either way.
    assert_eq!(claim.assurance(), IdentityAssurance::Iaa1);
    assert_eq!(claim.presence(), PresenceLevel::None);
    assert_eq!(claim.spiffe_id().trust_domain, TrustDomain::SshLocal);
    assert_eq!(claim.spiffe_id().path, candidate.path);

    // A signature answering some other challenge is a replay, not evidence.
    assert!(
        Claim::derive(
            candidate,
            b"a challenge this signature never saw",
            &evidence
        )
        .is_none(),
        "evidence bound to one challenge must not satisfy another"
    );

    // And the binding is checked where it is established, not only in derive:
    // the verifying constructor compares the data gpg says the signature
    // actually covers against the challenge it was handed.
    let Evidence::Possession(signature) = &evidence[0] else {
        panic!("gpg must produce possession evidence");
    };
    let signed_message = signature.assertion().bytes.clone();
    assert!(
        hire_attestors::ChallengeSignature::verify_openpgp(
            candidate,
            b"a different challenge entirely",
            &signed_message,
        )
        .await
        .is_err(),
        "a signature over one challenge must not witness another"
    );

    // The check a one-key keyring cannot make: this signature is good, gpg says
    // so, and it is by the wrong key. A verifier reading only gpg's exit status
    // -- or reading VALIDSIG without comparing the fingerprint -- accepts it,
    // and every other assertion in this file still passes.
    assert!(
        hire_attestors::ChallengeSignature::verify_openpgp(other, &challenge, &signed_message)
            .await
            .is_err(),
        "a signature by another key in the same keyring must not witness this candidate"
    );

    // A fingerprint gpg does not hold proves nothing, and fails before any
    // agent is asked to sign for it.
    let stranger = hire_attestors::Candidate::new(
        "gpg",
        hire_attestors::SelfAssertedDomain::SshLocal,
        "gpg/0000000000000000000000000000000000000000",
        "Nobody",
    );
    assert!(
        attestor.prove(&stranger, &challenge).await.is_err(),
        "a key this keyring does not hold must not prove anything"
    );
}
