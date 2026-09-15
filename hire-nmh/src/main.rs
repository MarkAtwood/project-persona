//! hire-nmh — Chrome/Firefox Native Messaging host.
//!
//! Reads Native Messaging frames (4-byte LE length + JSON) from stdin,
//! forwards identity requests to hired, writes JSON responses to stdout.
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

/// Largest frame this host will accept from the browser.
///
/// Chrome lets an extension send a native messaging host up to 64 MiB, but
/// every request this host understands is a small JSON object -- the largest is
/// a `fetch_jwt` carrying a list of audiences. The length prefix arrives from
/// the extension and nothing corroborates it, so the bound is what this
/// protocol needs rather than what the browser permits: a frame that claims
/// four billion bytes must be refused, not allocated.
const MAX_REQUEST: usize = 64 * 1024;

/// Largest frame this host will send.
///
/// Chrome caps a message from a native messaging host at 1 MB and kills the
/// host when one exceeds it, with no diagnostic the extension can read.
/// Checking here turns that into an error naming the size.
const MAX_RESPONSE: usize = 1024 * 1024;

/// Reads one Native Messaging frame, or `None` once the browser closes stdin.
fn read_message(input: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match input.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_REQUEST {
        // Refuse before allocating, and do not try to resynchronise: the frame
        // length is the only thing that says where the next frame starts, so a
        // length this host will not honour leaves the stream impossible to parse.
        anyhow::bail!("request frame of {len} bytes exceeds the {MAX_REQUEST}-byte limit");
    }
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Writes one Native Messaging frame: a 4-byte little-endian length, then JSON.
fn write_message(output: &mut impl Write, msg: &[u8]) -> Result<()> {
    if msg.len() > MAX_RESPONSE {
        anyhow::bail!(
            "response frame of {} bytes exceeds the {MAX_RESPONSE}-byte limit the browser accepts",
            msg.len()
        );
    }
    let len = (msg.len() as u32).to_le_bytes();
    output.write_all(&len)?;
    output.write_all(msg)?;
    output.flush()?;
    Ok(())
}

fn send_response(output: &mut impl Write, resp: &BrowserResponse) -> Result<()> {
    let json = serde_json::to_vec(resp)?;
    write_message(output, &json)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Don't log to stderr — that would corrupt the Native Messaging framing.
    // Log to a file instead if needed.

    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    loop {
        let msg = match read_message(&mut input)? {
            Some(m) => m,
            None => break, // stdin closed = extension unloaded
        };

        let request: BrowserRequest = match serde_json::from_slice(&msg) {
            Ok(r) => r,
            Err(e) => {
                send_response(
                    &mut output,
                    &BrowserResponse::Error {
                        message: format!("invalid request: {e}"),
                    },
                )?;
                continue;
            }
        };

        let response = handle_request(request).await;
        send_response(&mut output, &response)?;
    }

    Ok(())
}

async fn handle_request(req: BrowserRequest) -> BrowserResponse {
    match req {
        BrowserRequest::Status => BrowserResponse::Status {
            running: hire_grpc::socket::workload_socket_path().exists(),
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
    use hire_grpc::workload::{
        spiffe_workload_api_client::SpiffeWorkloadApiClient, JwtsvidRequest,
    };
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    // Connect from the PathBuf rather than a String: `XDG_RUNTIME_DIR` is
    // arbitrary bytes, so a UTF-8 conversion here could fail on a path the
    // kernel accepts.
    let path = hire_grpc::socket::workload_socket_path();
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
        .context("connect to hired")?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames built by an independent implementation, so the expectations here
    /// do not come from the code under test:
    ///
    /// ```text
    /// python3 -c "import struct,json
    /// m=json.dumps({'type':'fetch_jwt','audience':['https://example.com']},
    ///              separators=(',',':')).encode()
    /// print((struct.pack('<I',len(m))+m).hex())"
    /// ```
    const REQUEST_FRAME_HEX: &str = "370000007b2274797065223a2266657463685f6a7774222c2261756469656e6365223a5b2268747470733a2f2f6578616d706c652e636f6d225d7d";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("test vector is hex"))
            .collect()
    }

    #[test]
    fn reads_a_frame_the_browser_would_send() {
        let frame = unhex(REQUEST_FRAME_HEX);
        let msg = read_message(&mut frame.as_slice())
            .expect("a well-formed frame must parse")
            .expect("a well-formed frame is not end-of-stream");
        assert_eq!(
            msg,
            br#"{"type":"fetch_jwt","audience":["https://example.com"]}"#
        );
        let req: BrowserRequest = serde_json::from_slice(&msg).expect("must deserialize");
        assert!(matches!(req, BrowserRequest::FetchJwt { .. }));
    }

    #[test]
    fn a_closed_stdin_is_end_of_stream_not_an_error() {
        assert!(read_message(&mut [].as_slice())
            .expect("a clean close is not an error")
            .is_none());
    }

    #[test]
    fn refuses_a_length_prefix_it_would_have_to_allocate_for() {
        // The whole frame is four bytes claiming 4 GiB of payload. Allocating
        // first is what this bound exists to prevent, so the refusal has to come
        // from the length alone, not from running out of input.
        let frame = 0xFFFF_FFFFu32.to_le_bytes();
        let err = read_message(&mut frame.as_slice()).expect_err("must refuse");
        assert!(
            err.to_string().contains("exceeds the"),
            "must refuse on the declared length, not on a short read; got: {err}"
        );
    }

    #[test]
    fn the_limit_itself_is_accepted_and_one_byte_over_is_not() {
        let mut at = (MAX_REQUEST as u32).to_le_bytes().to_vec();
        at.extend(std::iter::repeat_n(b'x', MAX_REQUEST));
        assert_eq!(
            read_message(&mut at.as_slice())
                .expect("the limit is inclusive")
                .expect("not end-of-stream")
                .len(),
            MAX_REQUEST
        );

        let over = (MAX_REQUEST as u32 + 1).to_le_bytes();
        assert!(
            read_message(&mut over.as_slice()).is_err(),
            "one over must be refused"
        );
    }

    #[test]
    fn writes_the_frame_the_browser_expects() {
        // python3 -c "import struct; print((struct.pack('<I',2)+b'hi').hex())"
        let mut out = Vec::new();
        write_message(&mut out, b"hi").expect("must write");
        assert_eq!(out, unhex("020000006869"));
    }

    #[test]
    fn refuses_a_response_the_browser_would_kill_the_host_over() {
        let mut out = Vec::new();
        let huge = vec![b'x'; MAX_RESPONSE + 1];
        let err = write_message(&mut out, &huge).expect_err("must refuse");
        assert!(err.to_string().contains("exceeds the"), "got: {err}");
        assert!(
            out.is_empty(),
            "nothing may be written once the frame is refused"
        );
    }
}
