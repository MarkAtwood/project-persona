//! Tailscale LocalAPI attestor.
//!
//! Calls `/localapi/v0/status` over the Tailscale Unix socket to obtain the
//! local node's login identity.
//!
// ponytail: raw HTTP/1.1 over UnixStream is 20 lines | upgrade to hyper with
//           UDS connector when full LocalAPI coverage needed

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    AttainableAssurance, Attestor, AttestorError, Candidate, ProofCost, SelfAssertedDomain,
};

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

    let headers = &response[..body_start];
    let body = if header_says_chunked(headers) {
        dechunk(&response[body_start..])?
    } else {
        response[body_start..].to_vec()
    };

    serde_json::from_slice(&body).map_err(|e| AttestorError::Unavailable(e.to_string()))
}

/// True when the response announces `Transfer-Encoding: chunked`.
fn header_says_chunked(headers: &[u8]) -> bool {
    String::from_utf8_lossy(headers).lines().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    })
}

/// Reassembles a chunked body.
///
/// tailscaled answers `/localapi/v0/status` with `Transfer-Encoding: chunked`
/// even when the request asks for `Connection: close`, so the bytes after the
/// header block start with a hex length rather than with JSON.
///
// ponytail: enough of RFC 9112 section 7.1 for one GET against one server --
//   hex length, optional `;extension`, CRLF, data, CRLF, terminated by a
//   zero-length chunk; trailers are ignored | ceiling: no support for
//   compressed or nested transfer codings | upgrade path: hyper with a UDS
//   connector, which the module header already names, once more of the
//   LocalAPI is used than this one call
fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, AttestorError> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| AttestorError::Unavailable("chunked body: no chunk header".into()))?;
        let line = String::from_utf8_lossy(&body[..eol]);
        let hex = line.split(';').next().unwrap_or("").trim();
        let len = usize::from_str_radix(hex, 16)
            .map_err(|_| AttestorError::Unavailable(format!("chunked body: bad length {hex:?}")))?;
        body = &body[eol + 2..];
        if len == 0 {
            return Ok(out);
        }
        if body.len() < len {
            return Err(AttestorError::Unavailable(
                "chunked body: truncated chunk".into(),
            ));
        }
        out.extend_from_slice(&body[..len]);
        body = &body[len..];
        if body.starts_with(b"\r\n") {
            body = &body[2..];
        }
    }
}

#[async_trait::async_trait]
impl Attestor for TailscaleAttestor {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        if !self.is_available() {
            return Ok(vec![]);
        }

        let status = fetch_status(&self.socket_path).await?;

        let self_node = &status["Self"];

        // `Self` carries a numeric `UserID`, not a login. The human-readable
        // identity lives in the top-level `User` map keyed by that id, and a
        // tailnet with several logins has several entries there. Verified
        // against tailscaled 1.102.2, whose `Self` has no `LoginName` or
        // `DisplayName` field at all.
        let user_id = self_node["UserID"]
            .as_u64()
            .ok_or_else(|| AttestorError::Unavailable("missing Self.UserID".into()))?;
        let user = &status["User"][user_id.to_string()];
        let login_name = user["LoginName"]
            .as_str()
            .ok_or_else(|| AttestorError::Unavailable(format!("no User entry for {user_id}")))?;
        let node_name = self_node["DNSName"]
            .as_str()
            .map(|d| d.trim_end_matches('.'))
            .or_else(|| self_node["HostName"].as_str())
            .unwrap_or("unknown");
        let display = user["DisplayName"]
            .as_str()
            .unwrap_or(login_name)
            .to_owned();

        let candidate = Candidate::new(
            "tailscale",
            SelfAssertedDomain::Tailscale,
            format!("user/{login_name}/node/{node_name}"),
            display,
        )
        .with_attainable(AttainableAssurance::Iaa2)
        .with_proof_cost(ProofCost::Silent);

        Ok(vec![candidate])
    }
}

#[cfg(all(test, unix))]
mod chunked_tests {
    use super::{dechunk, header_says_chunked};

    #[test]
    fn detects_the_chunked_header_case_insensitively() {
        assert!(header_says_chunked(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        ));
        assert!(header_says_chunked(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n"
        ));
        assert!(!header_says_chunked(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        ));
    }

    #[test]
    fn reassembles_the_shape_tailscaled_actually_sends() {
        // tailscaled 1.102.2 answers /localapi/v0/status with a single large
        // chunk then a zero chunk, which is what broke the old parser: the
        // body begins with a hex length, not with JSON.
        let body = b"10\r\n{\"Self\":{\"x\":1}}\r\n0\r\n\r\n";
        assert_eq!(dechunk(body).unwrap(), br#"{"Self":{"x":1}}"#);
    }

    #[test]
    fn joins_several_chunks() {
        let body = b"5\r\n{\"a\":\r\n3\r\n1}\x20\r\n0\r\n\r\n";
        assert_eq!(dechunk(body).unwrap(), b"{\"a\":1} ");
    }

    #[test]
    fn ignores_a_chunk_extension() {
        let body = b"4;name=value\r\nabcd\r\n0\r\n\r\n";
        assert_eq!(dechunk(body).unwrap(), b"abcd");
    }

    #[test]
    fn refuses_a_truncated_chunk() {
        assert!(dechunk(b"ff\r\nshort\r\n").is_err());
    }

    #[test]
    fn refuses_a_non_hex_length() {
        // The old parser's failure mode: JSON where a length belongs.
        assert!(dechunk(b"{\"Self\":{}}\r\n").is_err());
    }
}
