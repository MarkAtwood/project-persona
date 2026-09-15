#![cfg(unix)]
//! The OS as an identity source on a box with nothing else on it.
//!
//! Its own integration binary, and that is the point. This test calls
//! `setenv`/`unsetenv`, and `unix_account_live.rs` reaches its oracle through
//! `Command::new("id")`, a fork/exec that reads the process `environ` array.
//! `cargo test` runs the tests in one binary on parallel threads, so the two
//! together are a data race on `environ` itself: glibc may reallocate the array
//! in `setenv` while another thread is reading it to build the child's
//! environment, which is a read of freed memory.
//!
//! That is not the hazard the shared file's header described. It said the
//! mutation was safe because the subject reads no environment variable, so no
//! sibling could observe the change. True, and beside the point: the race is on
//! the array, not on any variable's value, and it does not care which variable
//! is written. Nondeterministic and low-probability, which is worse than a
//! reliable failure.
//!
//! One test per binary is the constraint that removes it -- nothing else runs
//! in this process, so there is no sibling to race.

use persona_attestors::{probe_sources, Claim};

#[tokio::test]
async fn the_os_is_an_identity_source_with_no_agent_no_token_and_no_cloud_account() {
    // Take away what the other eight need. HOME is redirected rather than
    // unset, so the oidc token scan and the gpg keyring scan look somewhere
    // real and find nothing, instead of falling back to /root.
    let empty_home = std::env::temp_dir().join(format!("persona-unix-bare-{}", std::process::id()));
    std::fs::create_dir_all(&empty_home).expect("scratch dir");
    std::env::set_var("HOME", &empty_home);
    for var in [
        "SSH_AUTH_SOCK",
        "PERSONA_DID_KEYS",
        "GNOME_DESKTOP_SESSION_ID",
        "XDG_CURRENT_DESKTOP",
    ] {
        std::env::remove_var(var);
    }

    let sources = probe_sources().await;
    let names: Vec<&str> = sources.iter().map(|a| a.name()).collect();

    assert!(
        names.contains(&"unix"),
        "the OS is an identity source whenever the kernel is, so this source is \
         never absent: {names:?}"
    );
    assert_eq!(
        names.last(),
        Some(&"unix"),
        "position is load-bearing and invisible in a per-file diff: \
         persona-grpc keeps the first claim seen at the winning tier, so an \
         always-available iaa1 source placed any earlier takes the slot from an \
         ssh key or a hardware touch at the same tier and re-homes every \
         pseudonym derived from it: {names:?}"
    );

    // Availability the registry cannot fake: the source actually answers.
    let unix = sources.last().expect("at least the unix source");
    let candidates = unix.enumerate().await.expect("enumerate on a bare box");
    assert_eq!(candidates.len(), 1);
    let challenge = [0x2cu8; 32];
    let evidence = unix
        .prove(&candidates[0], &challenge)
        .await
        .expect("prove on a bare box");
    assert!(Claim::derive(&candidates[0], &challenge, &evidence).is_some());

    std::fs::remove_dir_all(&empty_home).expect("scratch dir cleanup");
}
