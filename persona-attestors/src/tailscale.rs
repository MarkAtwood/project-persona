//! Tailscale LocalAPI attestor.
//!
//! Calls `/localapi/v0/status` over the Tailscale Unix socket to obtain the
//! local node's login identity.
//!
// ponytail: raw HTTP/1.1 over UnixStream is 20 lines | upgrade to hyper with
//           UDS connector when full LocalAPI coverage needed

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

/// Attests identity via the Tailscale LocalAPI Unix socket.
#[derive(Debug)]
pub struct TailscaleAttestor {
    socket_path: std::path::PathBuf,
}

impl TailscaleAttestor {
    pub fn new() -> Self {
        Self {
            socket_path: std::path::PathBuf::from("/var/run/tailscale/tailscaled.sock"),
        }
    }

    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }
}

impl Default for TailscaleAttestor {
    fn default() -> Self {
        Self::new()
    }
}

async fn fetch_status(socket_path: &std::path::Path) -> Result<serde_json::Value, AttestorError> {
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| AttestorError::Unavailable(e.to_string()))?;

    let request =
        "GET /localapi/v0/status HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| AttestorError::Unavailable("no HTTP body".into()))?;

    serde_json::from_slice(&response[body_start..])
        .map_err(|e| AttestorError::Unavailable(e.to_string()))
}

#[async_trait::async_trait]
impl Attestor for TailscaleAttestor {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        if !self.is_available() {
            return Ok(vec![]);
        }

        let status = fetch_status(&self.socket_path).await?;

        let self_node = &status["Self"];
        let login_name = self_node["LoginName"]
            .as_str()
            .ok_or_else(|| AttestorError::Unavailable("missing Self.LoginName".into()))?;
        let node_name = self_node["DNSName"]
            .as_str()
            .or_else(|| self_node["HostName"].as_str())
            .unwrap_or("unknown");
        let display = self_node["DisplayName"]
            .as_str()
            .unwrap_or(login_name)
            .to_owned();

        let claim = Claim {
            source: "tailscale".into(),
            assurance: IdentityAssurance::Iaa2,
            presence: PresenceLevel::None,
            spiffe_id: SpiffeId::new(
                TrustDomain::Tailscale,
                format!("user/{login_name}/node/{node_name}"),
            ),
            display_name: display,
        };

        Ok(vec![claim])
    }

    // ponytail: stub prove() | upgrade to Tailscale node keypair signing when needed
    async fn prove(
        &self,
        _claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        Err(AttestorError::Unavailable(
            "Tailscale prove() not yet implemented".into(),
        ))
    }

    async fn freshness(&self, claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        if !self.is_available() {
            return Ok(FreshnessResult::Unavailable);
        }

        let status = match fetch_status(&self.socket_path).await {
            Ok(s) => s,
            Err(_) => return Ok(FreshnessResult::Unavailable),
        };

        let login_name = status["Self"]["LoginName"].as_str().unwrap_or("");
        if claim
            .spiffe_id
            .path
            .starts_with(&format!("user/{login_name}/"))
        {
            Ok(FreshnessResult::Fresh)
        } else {
            Ok(FreshnessResult::Unavailable)
        }
    }
}
