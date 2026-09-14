//! SSH agent attestor — enumerates keys via the SSH agent protocol.
//!
//! Communicates with the agent through SSH_AUTH_SOCK using the minimal
//! wire protocol needed for key enumeration.
//!
// ponytail: enumerate only via raw SSH agent protocol | upgrade to
//   ssh-agent-client-tokio for full sign support

use async_trait::async_trait;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::{Attestor, AttestorError, Candidate, SelfAssertedDomain};

const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;

/// Attestor that lists SSH keys from the running SSH agent.
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

/// Send a framed SSH agent message and return the response bytes (after the
/// 4-byte length prefix and 1-byte type, returning type + payload).
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
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

/// Read a length-prefixed blob from a byte slice, returning (blob, rest).
fn read_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
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

#[async_trait]
impl Attestor for SshAgentAttestor {
    fn name(&self) -> &str {
        "ssh-agent"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        let sock_path = std::env::var("SSH_AUTH_SOCK")
            .map_err(|_| AttestorError::Unavailable("SSH_AUTH_SOCK not set".into()))?;

        let mut stream = UnixStream::connect(&sock_path)
            .await
            .map_err(|e| AttestorError::Unavailable(format!("cannot connect to SSH agent: {e}")))?;

        let resp = agent_roundtrip(&mut stream, SSH2_AGENTC_REQUEST_IDENTITIES, &[]).await?;

        if resp.is_empty() || resp[0] != SSH2_AGENT_IDENTITIES_ANSWER {
            return Err(AttestorError::Unavailable(
                "unexpected response from SSH agent".into(),
            ));
        }

        // After type byte: [nkeys:4be]([key_blob:string][comment:string])*
        let mut cur = &resp[1..];
        if cur.len() < 4 {
            return Ok(vec![]);
        }
        let nkeys = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        cur = &cur[4..];

        let mut candidates = Vec::with_capacity(nkeys);
        for _ in 0..nkeys {
            let (key_blob, rest) = match read_string(cur) {
                Some(v) => v,
                None => break,
            };
            let (comment_bytes, rest) = match read_string(rest) {
                Some(v) => v,
                None => break,
            };
            cur = rest;

            let fingerprint = {
                let hash = Sha256::digest(key_blob);
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash)
            };
            let display_name = String::from_utf8_lossy(comment_bytes).into_owned();

            candidates.push(Candidate::new(
                "ssh-agent",
                SelfAssertedDomain::SshLocal,
                format!("key/{fingerprint}"),
                display_name,
            ));
        }

        Ok(candidates)
    }
}
