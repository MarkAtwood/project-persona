//! What `prove()` does when the agent will not, or cannot, sign.
//!
//! Driven by a scripted fake agent rather than a real one, because neither
//! branch is reachable through OpenSSH without either removing a key mid-test or
//! holding a confirm-flagged key that needs a human to decline it.
//!
//! One `#[test]`, for the same reason as `ssh_agent_live.rs`: the attestor is
//! aimed through the process-global `SSH_AUTH_SOCK`. Both cases run inside it,
//! sequentially, against one socket — `prove()` opens a fresh connection per
//! call, so the fake agent scripts them by connection order with nothing shared.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use persona_attestors::{Attestor, Candidate, SelfAssertedDomain, SshAgentAttestor};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// An `ssh-ed25519` key blob over a fixed point, and the SPIFFE path it maps to.
///
/// The point is never used to verify anything here: both branches under test
/// refuse before any signature exists. It only has to be well-formed enough for
/// `prove()` to accept it as an ed25519 key and go on to ask for a signature.
fn key_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    push_string(&mut blob, b"ssh-ed25519");
    push_string(&mut blob, &[0x11u8; 32]);
    blob
}

async fn read_message(stream: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    let (ty, rest) = body.split_first()?;
    Some((*ty, rest.to_vec()))
}

async fn write_message(stream: &mut UnixStream, msg_type: u8, payload: &[u8]) {
    let len = (1 + payload.len()) as u32;
    let _ = stream.write_all(&len.to_be_bytes()).await;
    let _ = stream.write_all(&[msg_type]).await;
    let _ = stream.write_all(payload).await;
}

fn identities_answer(keys: &[Vec<u8>]) -> Vec<u8> {
    let mut out = (keys.len() as u32).to_be_bytes().to_vec();
    for blob in keys {
        push_string(&mut out, blob);
        push_string(&mut out, b"fake");
    }
    out
}

#[tokio::test]
async fn an_agent_that_will_not_sign_yields_no_evidence() {
    let dir = std::env::temp_dir().join(format!("persona-ssh-fake-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let sock = dir.join("agent.sock");
    let listener = UnixListener::bind(&sock).expect("bind fake agent");

    // Set by the fake agent if it is ever asked to sign while holding no keys.
    // A `prove()` that asked anyway would be raising a confirm dialog for a
    // proof it is about to discard.
    let signed_while_empty = Arc::new(AtomicBool::new(false));

    let flag = Arc::clone(&signed_while_empty);
    let agent = tokio::spawn(async move {
        // Connection 1: the agent holds nothing.
        if let Ok((mut stream, _)) = listener.accept().await {
            while let Some((ty, _)) = read_message(&mut stream).await {
                match ty {
                    SSH2_AGENTC_REQUEST_IDENTITIES => {
                        write_message(
                            &mut stream,
                            SSH2_AGENT_IDENTITIES_ANSWER,
                            &identities_answer(&[]),
                        )
                        .await
                    }
                    SSH2_AGENTC_SIGN_REQUEST => {
                        flag.store(true, Ordering::SeqCst);
                        write_message(&mut stream, SSH_AGENT_FAILURE, &[]).await
                    }
                    _ => break,
                }
            }
        }
        // Connection 2: the agent holds the key and declines to sign with it,
        // which is what a confirm-flagged key does when the human says no.
        if let Ok((mut stream, _)) = listener.accept().await {
            while let Some((ty, _)) = read_message(&mut stream).await {
                match ty {
                    SSH2_AGENTC_REQUEST_IDENTITIES => {
                        write_message(
                            &mut stream,
                            SSH2_AGENT_IDENTITIES_ANSWER,
                            &identities_answer(&[key_blob()]),
                        )
                        .await
                    }
                    SSH2_AGENTC_SIGN_REQUEST => {
                        write_message(&mut stream, SSH_AGENT_FAILURE, &[]).await
                    }
                    _ => break,
                }
            }
        }
    });

    // Safe in edition 2021, and the whole reason this file holds one test.
    std::env::set_var("SSH_AUTH_SOCK", &sock);
    let attestor = SshAgentAttestor::new();

    // The candidate names a key by fingerprint. It is the same candidate in both
    // phases; only what the agent says about it changes.
    let candidate = Candidate::new(
        "ssh-agent",
        SelfAssertedDomain::SshLocal,
        fingerprint_path(&key_blob()),
        "fake",
    );

    let gone = attestor
        .prove(&candidate, b"a challenge")
        .await
        .expect_err("a key the agent no longer holds must not prove");
    assert!(gone.to_string().contains("no longer holds"), "got: {gone}");
    assert!(
        !signed_while_empty.load(Ordering::SeqCst),
        "prove() must not ask for a signature it cannot bind to the candidate"
    );

    let declined = attestor
        .prove(&candidate, b"a challenge")
        .await
        .expect_err("SSH_AGENT_FAILURE must not be read as success");
    assert!(
        declined.to_string().contains("declined to sign"),
        "got: {declined}"
    );

    agent.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The SPIFFE path for a key blob, computed here with sha2 and base64 rather
/// than through the attestor, so the candidate's path is not the code's own
/// output fed back to it.
fn fingerprint_path(key_blob: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    let fingerprint =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key_blob));
    format!("key/{fingerprint}")
}
