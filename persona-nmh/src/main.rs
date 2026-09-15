//! persona-nmh — Chrome/Firefox Native Messaging host.
//!
//! Reads Native Messaging frames (4-byte LE length + JSON) from stdin,
//! forwards identity requests to personad, writes JSON responses to stdout.
//!
// ponytail: full bidirectional streaming | upgrade: tokio async stdin/stdout with framing

use std::io::{Read, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A request from the browser extension.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrowserRequest {
    /// Fetch a JWT-SVID for the given audience.
    FetchJwt { audience: Vec<String> },
    /// Check daemon status.
    Status,
}

/// A response to the browser extension.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrowserResponse {
    /// Successful JWT-SVID.
    Jwt { svid: String, spiffe_id: String },
    /// Status info.
    Status { running: bool, version: String },
    /// Error.
    Error { message: String },
}

fn read_message() -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match std::io::stdin().read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    std::io::stdin().read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_message(msg: &[u8]) -> Result<()> {
    let len = (msg.len() as u32).to_le_bytes();
    std::io::stdout().write_all(&len)?;
    std::io::stdout().write_all(msg)?;
    std::io::stdout().flush()?;
    Ok(())
}

fn send_response(resp: &BrowserResponse) -> Result<()> {
    let json = serde_json::to_vec(resp)?;
    write_message(&json)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Don't log to stderr — that would corrupt the Native Messaging framing.
    // Log to a file instead if needed.

    loop {
        let msg = match read_message()? {
            Some(m) => m,
            None => break, // stdin closed = extension unloaded
        };

        let request: BrowserRequest = match serde_json::from_slice(&msg) {
            Ok(r) => r,
            Err(e) => {
                send_response(&BrowserResponse::Error {
                    message: format!("invalid request: {e}"),
                })?;
                continue;
            }
        };

        let response = handle_request(request).await;
        send_response(&response)?;
    }

    Ok(())
}

async fn handle_request(req: BrowserRequest) -> BrowserResponse {
    match req {
        BrowserRequest::Status => BrowserResponse::Status {
            running: persona_grpc::socket::workload_socket_path().exists(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        BrowserRequest::FetchJwt { audience } => match fetch_jwt(audience).await {
            Ok((svid, spiffe_id)) => BrowserResponse::Jwt { svid, spiffe_id },
            Err(e) => BrowserResponse::Error {
                message: e.to_string(),
            },
        },
    }
}

async fn fetch_jwt(audience: Vec<String>) -> Result<(String, String)> {
    use hyper_util::rt::TokioIo;
    use persona_grpc::workload::{
        spiffe_workload_api_client::SpiffeWorkloadApiClient, JwtsvidRequest,
    };
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    // Connect from the PathBuf rather than a String: `XDG_RUNTIME_DIR` is
    // arbitrary bytes, so a UTF-8 conversion here could fail on a path the
    // kernel accepts.
    let path = persona_grpc::socket::workload_socket_path();
    let channel = Endpoint::try_from("http://[::]:50051")
        .context("invalid endpoint")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = path.clone();
            async move {
                let stream = UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .context("connect to personad")?;

    let mut client = SpiffeWorkloadApiClient::new(channel);
    let resp = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience,
            spiffe_id: String::new(),
        })
        .await
        .context("FetchJWTSVID failed")?;

    let svids = resp.into_inner().svids;
    let svid = svids.into_iter().next().context("no SVIDs returned")?;
    Ok((svid.svid, svid.spiffe_id))
}
