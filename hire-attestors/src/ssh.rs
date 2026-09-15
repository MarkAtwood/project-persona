//! SSH agent attestor — enumerates agent keys and proves possession of them.
//!
//! Speaks the SSH agent wire protocol directly over `SSH_AUTH_SOCK`:
//! `REQUEST_IDENTITIES` to enumerate, `SIGN_REQUEST` to prove.
//!
//! Proof is possession and nothing else. An agent key with no passphrase and no
//! confirm flag signs with no prompt and no human in the loop, so this attestor
//! asserts `Iaa1` with `PresenceLevel::None` and never more.
//!
// ponytail: ssh-ed25519 only | ceiling: an agent holding only ecdsa or rsa keys
//   enumerates but never proves, so it contributes no claim | upgrade path: a
//   sibling verifying constructor per key family in claim.rs, never a second
//   verifier here. `ecdsa-sha2-nistp256` needs an mpint decoder (strip one
//   leading 0x00, reject a high bit with no pad, reject > 32 bytes, left-pad to
//   32, then `p256::ecdsa::Signature::from_scalars`); its test matrix must
//   include r or s of 31 bytes, which is ~1 signature in 256 and is the case
//   sampling misses. `ssh-rsa` additionally falsifies .cargo/audit.toml.

use async_trait::async_trait;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::claim::ChallengeSignature;
use crate::{
    AttainableAssurance, Attestor, AttestorError, Candidate, Evidence, ProofCost,
    SelfAssertedDomain,
};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

/// The one agent key type this attestor proves. See the module header.
pub(crate) const SSH_ED25519: &[u8] = b"ssh-ed25519";

/// Largest agent reply accepted: a key list or an 83-byte signature. Far above
/// anything OpenSSH sends, far below a memory-exhaustion primitive.
const MAX_AGENT_REPLY: usize = 256 * 1024;

/// Largest identity count pre-allocated. `nkeys` is read from the wire and is
/// not bounded by the reply length, so a 5-byte reply can claim four billion
/// keys. Growth past this is handled by `Vec` as the loop actually parses them.
const MAX_PREALLOC_KEYS: usize = 64;

/// Attestor that lists SSH keys from the running SSH agent and proves them.
#[derive(Debug)]
pub struct SshAgentAttestor;

impl SshAgentAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if SSH_AUTH_SOCK is set and the socket exists.
    pub fn is_available() -> bool {
        std::env::var("SSH_AUTH_SOCK")
            .ok()
            .map(|p| std::path::Path::new(&p).exists())
            .unwrap_or(false)
    }
}

impl Default for SshAgentAttestor {
    fn default() -> Self {
        Self::new()
    }
}

async fn connect() -> Result<UnixStream, AttestorError> {
    let sock_path = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| AttestorError::Unavailable("SSH_AUTH_SOCK not set".into()))?;
    UnixStream::connect(&sock_path)
        .await
        .map_err(|e| AttestorError::Unavailable(format!("cannot connect to SSH agent: {e}")))
}

/// Send a framed SSH agent message and return the response bytes (after the
/// 4-byte length prefix, returning type + payload).
async fn agent_roundtrip(
    stream: &mut UnixStream,
    msg_type: u8,
    payload: &[u8],
) -> Result<Vec<u8>, AttestorError> {
    // [len:4be][type:1][payload]
    let len = (1 + payload.len()) as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&[msg_type]).await?;
    stream.write_all(payload).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_AGENT_REPLY {
        return Err(AttestorError::Unavailable(
            "ssh-agent reply too large".into(),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

/// Read a length-prefixed blob from a byte slice, returning (blob, rest).
pub(crate) fn read_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(buf[..4].try_into().ok()?) as usize;
    let rest = buf.get(4..)?;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// Append a length-prefixed blob.
fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// The SPIFFE path an agent key maps to.
///
/// One function, because `enumerate` writes it and
/// [`ChallengeSignature::verify_ssh_ed25519`] checks it. Two spellings that
/// drift apart silently stop binding anything.
pub(crate) fn spiffe_path(key_blob: &[u8]) -> String {
    let fingerprint =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key_blob));
    format!("key/{fingerprint}")
}

async fn list_identities(stream: &mut UnixStream) -> Result<Vec<(Vec<u8>, String)>, AttestorError> {
    let resp = agent_roundtrip(stream, SSH2_AGENTC_REQUEST_IDENTITIES, &[]).await?;
    if resp.first() != Some(&SSH2_AGENT_IDENTITIES_ANSWER) {
        return Err(AttestorError::Unavailable(
            "unexpected response from SSH agent".into(),
        ));
    }

    // After the type byte: [nkeys:4be]([key_blob:string][comment:string])*
    let mut cur = &resp[1..];
    if cur.len() < 4 {
        return Ok(vec![]);
    }
    let nkeys = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
    cur = &cur[4..];

    let mut keys = Vec::with_capacity(nkeys.min(MAX_PREALLOC_KEYS));
    for _ in 0..nkeys {
        let Some((key_blob, rest)) = read_string(cur) else {
            break;
        };
        let Some((comment, rest)) = read_string(rest) else {
            break;
        };
        cur = rest;
        keys.push((
            key_blob.to_vec(),
            String::from_utf8_lossy(comment).into_owned(),
        ));
    }
    Ok(keys)
}

#[async_trait]
impl Attestor for SshAgentAttestor {
    fn name(&self) -> &str {
        "ssh-agent"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        let mut stream = connect().await?;
        Ok(list_identities(&mut stream)
            .await?
            .into_iter()
            .map(|(key_blob, display_name)| {
                Candidate::new(
                    "ssh-agent",
                    SelfAssertedDomain::SshLocal,
                    spiffe_path(&key_blob),
                    display_name,
                )
                .with_attainable(AttainableAssurance::Iaa1)
                // A key added with `ssh-add -c` prompts on every signature, and
                // the agent's identities answer does not carry that constraint,
                // so nothing here can tell a confirm-flagged key from a plain
                // one. `Silent` is a guarantee and this cannot give it.
                .with_proof_cost(ProofCost::Interactive)
            })
            .collect())
    }

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        let mut stream = connect().await?;

        // Re-list rather than carrying the blob forward from enumerate(). A
        // Candidate holds only the fingerprint, and widening it would push an
        // ssh-specific field onto every other attestor's candidates. Re-listing
        // costs one roundtrip on a socket being opened anyway, and it asks the
        // more truthful question: is this key resident *now*?
        let key_blob = list_identities(&mut stream)
            .await?
            .into_iter()
            .map(|(blob, _comment)| blob)
            .find(|blob| spiffe_path(blob) == candidate.path)
            .ok_or_else(|| {
                AttestorError::ChallengeFailed(format!(
                    "ssh-agent no longer holds {}",
                    candidate.path
                ))
            })?;

        let (algorithm, _) = read_string(&key_blob).ok_or_else(|| {
            AttestorError::ChallengeFailed("malformed key blob from ssh-agent".into())
        })?;
        if algorithm != SSH_ED25519 {
            // Refused before the agent is asked to sign: a signature we cannot
            // verify is one we must not collect, and a confirm-flagged key must
            // not raise a dialog for a proof we would discard. The verifying
            // constructor checks this again — that check is the trust boundary,
            // this one is the message an operator can act on.
            //
            // ponytail: one event per unsupported key per RPC | ceiling: an agent
            //   holding four rsa keys logs four lines per request | upgrade path:
            //   decide in enumerate() so an unprovable key is never offered as a
            //   candidate — a separate decision, it changes `hire enumerate`.
            let algorithm = String::from_utf8_lossy(algorithm).into_owned();
            tracing::info!(
                event = "ssh_key_unsupported",
                key = %candidate.path,
                algorithm = %algorithm,
                "hire proves ssh-ed25519 agent keys only"
            );
            return Err(AttestorError::ChallengeFailed(format!(
                "ssh-agent key {} is {algorithm}; hire proves ssh-ed25519 keys only",
                candidate.path
            )));
        }

        // [key_blob:string][data:string][flags:u32be]. flags = 0: the three
        // defined flags (OLD_SIGNATURE, RSA_SHA2_256, RSA_SHA2_512) are all
        // RSA-only, and RSA keys are refused above.
        let mut payload = Vec::with_capacity(key_blob.len() + challenge.len() + 12);
        push_string(&mut payload, &key_blob);
        push_string(&mut payload, challenge);
        payload.extend_from_slice(&0u32.to_be_bytes());

        let resp = agent_roundtrip(&mut stream, SSH2_AGENTC_SIGN_REQUEST, &payload).await?;
        let body = match resp.split_first() {
            Some((&SSH2_AGENT_SIGN_RESPONSE, body)) => body,
            Some((&SSH_AGENT_FAILURE, _)) => {
                return Err(AttestorError::ChallengeFailed(format!(
                    "ssh-agent declined to sign for {}",
                    candidate.path
                )))
            }
            _ => {
                return Err(AttestorError::ChallengeFailed(
                    "unexpected response to ssh-agent sign request".into(),
                ))
            }
        };

        let (signature, trailing) = read_string(body).ok_or_else(|| {
            AttestorError::ChallengeFailed("malformed SIGN_RESPONSE from ssh-agent".into())
        })?;
        if !trailing.is_empty() {
            return Err(AttestorError::ChallengeFailed(
                "trailing bytes after ssh-agent signature".into(),
            ));
        }

        Ok(vec![Evidence::Possession(
            ChallengeSignature::verify_ssh_ed25519(candidate, challenge, &key_blob, signature)?,
        )])
    }
}
