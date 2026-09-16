//! End-to-end: a `did:key` proved by the ssh-agent that holds its secret half.
//!
//! One `#[test]` per file, for the reason `ssh_agent_live.rs` gives: the
//! attestors are aimed through the process-global `SSH_AUTH_SOCK` and
//! `HIRE_DID_KEYS`.
//!
//! THE ORACLE IS OUTSIDE THIS CODEBASE. The identifier under test is built from
//! the agent key by a base58 implementation in Python, so a fault in the Rust
//! decoder cannot cancel itself out: a wrong decode yields a point that matches
//! no key in the agent, and the proof fails rather than passing against a DID
//! this crate encoded for itself. Skips where `ssh-agent`, `ssh-keygen` or
//! `python3` is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use hire_attestors::{Attestor, Claim, DidKeyAttestor};
use hire_core::{IdentityAssurance, PresenceLevel};

/// Kills the spawned agent and removes its scratch directory even if an
/// assertion panics.
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

/// `did:key:z<base58btc(0xed01 || key)>`, encoded by Python.
///
/// Deliberately not by this crate: hire only decodes, and a test that encoded
/// with the inverse of the code under test would agree with itself whatever
/// either one did.
fn did_key_of(public_key: &[u8; 32]) -> String {
    let script = r#"
import sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
raw = b"\xed\x01" + bytes.fromhex(sys.argv[1])
n = int.from_bytes(raw, "big")
out = ""
while n:
    n, r = divmod(n, 58)
    out = A[r] + out
print("did:key:z" + out)
"#;
    let hex: String = public_key.iter().map(|b| format!("{b:02x}")).collect();
    let out = Command::new("python3")
        .args(["-c", script, &hex])
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "python3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

/// The 32-byte ed25519 point inside an OpenSSH public key line.
///
/// An `ssh-ed25519` blob is `[11-byte algorithm][32-byte point]`, both
/// length-prefixed, so the point is the last 32 bytes. Done here with a slice
/// rather than through the crate's own parser, for the same reason as above.
fn point_of(pub_line: &str) -> [u8; 32] {
    use base64::Engine as _;
    let b64 = pub_line.split_whitespace().nth(1).expect("key blob field");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64 key blob");
    blob[blob.len() - 32..].try_into().expect("32 bytes")
}

#[tokio::test]
async fn a_did_key_is_proved_by_the_agent_holding_its_secret() {
    if !have("ssh-agent") || !have("ssh-keygen") || !have("ssh-add") || !have("python3") {
        eprintln!("skipping: openssh-client or python3 is not installed on this machine");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hire-did-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let sock = dir.join("agent.sock");

    let spawned = Command::new("ssh-agent")
        .args(["-a", sock.to_str().expect("utf-8 path")])
        .output()
        .expect("ssh-agent");
    assert!(spawned.status.success(), "ssh-agent failed to start");
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

    // TWO keys in the agent, and that is what makes the identifier binding
    // testable at all: a signature by a key the agent does not hold fails the
    // signature check on its own, so only a second key it *does* hold can tell
    // "this DID" apart from "a DID".
    let mut dids = Vec::new();
    for n in 0..2 {
        let key = agent.dir.join(format!("id_ed25519_{n}"));
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
                "hire-did-live",
                "-f",
                key_path,
            ],
            &sock,
        );
        run("ssh-add", &[key_path], &sock);
        let pub_line = std::fs::read_to_string(format!("{key_path}.pub")).expect("public key");
        dids.push(did_key_of(&point_of(&pub_line)));
    }
    let (did, other) = (dids[0].clone(), dids[1].clone());
    assert_ne!(did, other);

    // A second DID the agent cannot answer for, so the test tells "proved"
    // apart from "proved something".
    let stranger = did_key_of(&[0x11u8; 32]);
    assert_ne!(did, stranger);

    // Safe in edition 2021, and the whole reason this file holds one test.
    std::env::set_var("SSH_AUTH_SOCK", &sock);
    std::env::set_var("HIRE_DID_KEYS", format!("{did} {other} {stranger}"));

    assert!(DidKeyAttestor::is_available());
    let attestor = DidKeyAttestor::new();

    let candidates = attestor.enumerate().await.expect("enumerate");
    assert_eq!(candidates.len(), 3, "every configured DID is a candidate");
    let candidate = candidates
        .iter()
        .find(|c| c.display_name == did)
        .expect("the DID for the agent's key must be enumerated");

    let challenge = [0x3cu8; 32];
    let evidence = attestor
        .prove(candidate, &challenge)
        .await
        .expect("a DID whose key is in the agent must prove possession");

    let claim = Claim::derive(candidate, &challenge, &evidence)
        .expect("verified possession must yield a claim");
    assert_eq!(claim.assurance(), IdentityAssurance::Iaa1);
    assert_eq!(claim.presence(), PresenceLevel::None);
    assert_eq!(claim.spiffe_id().path, candidate.path);

    // Configured, enumerable, and unprovable: nothing local holds its secret.
    // This is the case a file-backed keystore would have papered over.
    let stranger_candidate = candidates
        .iter()
        .find(|c| c.display_name == stranger)
        .expect("the stranger DID is a candidate too");
    assert!(
        attestor
            .prove(stranger_candidate, &challenge)
            .await
            .is_err(),
        "a DID no local agent can answer for must not prove anything"
    );

    // The verifying constructor is the trust boundary, so it is exercised
    // directly rather than only through prove(): a real signature by the
    // agent's key, offered for a DID the candidate does not name, must not
    // witness anything. prove() re-derives the DID from the candidate and so
    // can never make this mistake -- which is exactly why the check needs a
    // test that can.
    let hire_attestors::Evidence::Possession(signature) = &evidence[0] else {
        panic!("did:key must produce possession evidence");
    };
    let mut framed = Vec::new();
    framed.extend_from_slice(&(11u32).to_be_bytes());
    framed.extend_from_slice(b"ssh-ed25519");
    framed.extend_from_slice(&(64u32).to_be_bytes());
    framed.extend_from_slice(&signature.assertion().bytes);
    assert!(
        hire_attestors::ChallengeSignature::verify_did_key_ed25519(
            candidate, &challenge, &stranger, &framed,
        )
        .is_err(),
        "a signature offered for a DID the candidate does not name must not verify"
    );

    // The same refusal where the signature check cannot help: the agent's OTHER
    // key really does sign this challenge, and the DID offered really does
    // encode the key that signed it, so every cryptographic check passes. Only
    // the identifier binding stands between that and a claim minted for an
    // identity nobody proved.
    let other_candidate = candidates
        .iter()
        .find(|c| c.display_name == other)
        .expect("the second agent key's DID is a candidate");
    let other_evidence = attestor
        .prove(other_candidate, &challenge)
        .await
        .expect("the agent's second key must prove too");
    let hire_attestors::Evidence::Possession(other_signature) = &other_evidence[0] else {
        panic!("did:key must produce possession evidence");
    };
    let mut other_framed = Vec::new();
    other_framed.extend_from_slice(&(11u32).to_be_bytes());
    other_framed.extend_from_slice(b"ssh-ed25519");
    other_framed.extend_from_slice(&(64u32).to_be_bytes());
    other_framed.extend_from_slice(&other_signature.assertion().bytes);
    assert!(
        hire_attestors::ChallengeSignature::verify_did_key_ed25519(
            candidate,
            &challenge,
            &other,
            &other_framed,
        )
        .is_err(),
        "a good signature by another held key must not witness this candidate"
    );
    assert!(
        hire_attestors::ChallengeSignature::verify_did_key_ed25519(
            candidate,
            b"a different challenge entirely",
            &did,
            &framed,
        )
        .is_err(),
        "a signature over one challenge must not witness another"
    );
    // Control: the same reassembled signature, offered honestly, does verify --
    // so the two refusals above are about what changed and not about the
    // reassembly.
    hire_attestors::ChallengeSignature::verify_did_key_ed25519(
        candidate, &challenge, &did, &framed,
    )
    .expect("the agent's own signature over this challenge must verify");

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
}
