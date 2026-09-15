//! End-to-end against a real `ssh-agent` holding a real key.
//!
//! Exactly one `#[test]`, and that is a constraint rather than an accident: the
//! attestor is aimed at an agent through the process-global `SSH_AUTH_SOCK`, and
//! CI sets that variable to the empty string. A Cargo integration test file is
//! its own binary, so one test per file means there is nothing to race. If a
//! second live-agent test is ever wanted, the answer is a second file, not a
//! constructor taking a socket path — that would put a test-only field on a
//! production unit struct to buy a seam the process boundary already provides.
//!
//! Skips, with a printed reason, where openssh-client is absent. It spawns its
//! own agent and its own throwaway key, so it never reads or mutates the
//! developer's agent.

use std::path::{Path, PathBuf};
use std::process::Command;

use hire_attestors::{Attestor, Claim, SshAgentAttestor};
use hire_core::{IdentityAssurance, PresenceLevel, TrustDomain};

/// Kills the spawned agent and removes its scratch directory even if an
/// assertion panics, so a failing run leaks neither a process nor a socket.
struct Agent {
    dir: PathBuf,
    sock: PathBuf,
    pid: String,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = Command::new("ssh-agent")
            .arg("-k")
            .env("SSH_AUTH_SOCK", &self.sock)
            .env("SSH_AGENT_PID", &self.pid)
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

fn run(program: &str, args: &[&str], sock: &Path) {
    let status = Command::new(program)
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
        .status()
        .unwrap_or_else(|e| panic!("{program} failed to run: {e}"));
    assert!(status.success(), "{program} exited {status}");
}

#[tokio::test]
async fn a_real_agent_key_proves_possession_and_claims_no_presence() {
    if !have("ssh-agent") || !have("ssh-keygen") || !have("ssh-add") {
        eprintln!("skipping: openssh-client is not installed on this machine");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hire-ssh-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let sock = dir.join("agent.sock");

    let spawned = Command::new("ssh-agent")
        .args(["-a", sock.to_str().expect("utf-8 path")])
        .output()
        .expect("ssh-agent");
    assert!(spawned.status.success(), "ssh-agent failed to start");
    // `ssh-agent -a` prints `SSH_AGENT_PID=<pid>; export SSH_AGENT_PID;`.
    let pid = String::from_utf8_lossy(&spawned.stdout)
        .split("SSH_AGENT_PID=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .map(|s| s.trim().to_owned())
        .expect("ssh-agent did not report its pid");
    let agent = Agent {
        dir: dir.clone(),
        sock: sock.clone(),
        pid,
    };

    let key = dir.join("id_ed25519");
    let key_path = key.to_str().expect("utf-8 path");
    run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "hire-live-test",
            "-f",
            key_path,
        ],
        &sock,
    );
    run("ssh-add", &[key_path], &sock);

    // Safe in edition 2021, and the whole reason this file holds one test.
    std::env::set_var("SSH_AUTH_SOCK", &sock);

    assert!(SshAgentAttestor::is_available());
    let attestor = SshAgentAttestor::new();

    let candidates = attestor.enumerate().await.expect("enumerate");
    let candidate = candidates
        .iter()
        .find(|c| c.display_name == "hire-live-test")
        .expect("the key this test added must be enumerated");
    assert!(candidate.path.starts_with("key/"));

    // The real thing: a real agent signs a real challenge with a real key, and
    // the only constructor for possession evidence checks the result.
    let challenge = [0x5au8; 32];
    let evidence = attestor
        .prove(candidate, &challenge)
        .await
        .expect("a resident ed25519 key must prove possession");

    let claim = Claim::derive(candidate, &challenge, &evidence)
        .expect("verified possession must yield a claim");

    // The owner decision, asserted rather than described. A key with no
    // passphrase and no confirm flag signs with no human in the loop, so
    // possession buys the floor and claims no presence at all.
    assert_eq!(claim.assurance(), IdentityAssurance::Iaa1);
    assert_eq!(claim.presence(), PresenceLevel::None);
    assert_eq!(claim.spiffe_id().trust_domain, TrustDomain::SshLocal);
    assert_eq!(claim.spiffe_id().path, candidate.path);

    // The same evidence against a different challenge is a replay.
    assert!(Claim::derive(candidate, b"a different challenge", &evidence).is_none());

    drop(agent);
}
