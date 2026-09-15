//! persona — CLI for the personad identity daemon.

use anyhow::{Context, Result};
use persona_grpc::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use std::path::PathBuf;
use tonic::transport::Channel;

#[allow(dead_code)] // used only on macOS via #[cfg(target_os = "macos")]
/// The launchd agent template, shared with the copy a packager installs.
///
/// `install-service` substitutes `__HOME__` and writes the result to
/// ~/Library/LaunchAgents/personad.plist. Pulled from the shipped file rather
/// than copied into this binary: two copies of one config drift, and the
/// systemd pair already had.
const LAUNCHD_PLIST: &str = include_str!("../../launchd/personad.plist");

/// The systemd user unit, shared with the copy a packager installs.
const SYSTEMD_UNIT: &str = include_str!("../../systemd/personad.service");

/// Connects to the personad Unix socket and returns a ready gRPC client.
async fn connect_to_daemon() -> Result<SpiffeWorkloadApiClient<Channel>> {
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    let path = persona_grpc::socket::workload_socket_path();
    if !path.exists() {
        anyhow::bail!(
            "personad socket not found at {}\nIs personad running? Try: systemctl --user start personad",
            path.display()
        );
    }

    // Connect from the PathBuf rather than a String: `XDG_RUNTIME_DIR` is
    // arbitrary bytes, so a UTF-8 conversion here could fail on a path the
    // kernel accepts.
    let sock = path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .context("invalid endpoint")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = sock.clone();
            async move {
                let stream = UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("cannot connect to personad at {}", path.display()))?;

    Ok(SpiffeWorkloadApiClient::new(channel))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map(String::as_str).unwrap_or("--help");

    match subcmd {
        "whoami" => whoami().await,
        "enumerate" => enumerate().await,
        "fetch-jwt" => fetch_jwt(&args[2..]).await,
        "fetch-x509" => fetch_x509().await,
        "prove" => prove(&args[2..]).await,
        "enroll" => enroll(&args[2..]),
        "install-service" => install_service().await,
        "trust-bundle" => trust_bundle(&args[2..]).await,
        "watch" => watch().await,
        "log" => show_log().await,
        "--help" | "-h" => {
            println!("usage: persona <command>");
            println!();
            println!("commands:");
            println!("  whoami           print current SPIFFE identity");
            println!("  enumerate        list locally-detected identity sources");
            println!("  fetch-jwt        fetch a JWT-SVID from the daemon");
            println!("  fetch-x509       (not implemented) fetch an X.509-SVID from the daemon");
            println!("  prove            prove identity to a peer (JWT with challenge)");
            println!("  enroll           (not implemented) enroll an application or origin");
            println!("  install-service  write personad service file (systemd or launchd)");
            println!("  trust-bundle     list trust bundles (add and remove not implemented)");
            println!("  watch            poll for JWT-SVID changes every 30 seconds");
            println!("  log              show how to view personad logs");
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("run 'persona --help' for usage");
            std::process::exit(1);
        }
    }
}

/// Prints the SPIFFE identity personad reports for this caller.
///
/// A refusal is not an answer and an empty SVID list is not an identity, so
/// both exit 1. Callers gate on `persona whoami && ...`.
async fn whoami() -> Result<()> {
    use persona_grpc::workload::JwtsvidRequest;

    let mut client = connect_to_daemon().await?;

    let response = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec!["persona:whoami".to_string()],
            spiffe_id: String::new(),
        })
        .await;

    match response {
        Ok(resp) => {
            let svids = resp.into_inner().svids;
            if svids.is_empty() {
                eprintln!("error: no identity");
                std::process::exit(1);
            } else {
                for svid in &svids {
                    println!("spiffe_id: {}", svid.spiffe_id);
                    println!(
                        "token:     {} (truncated)",
                        &svid.svid[..svid.svid.len().min(40)]
                    );
                }
            }
        }
        Err(status) => {
            eprintln!("personad: {}", status.message());
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Formats the count line for `persona enumerate`.
///
/// Sources and candidates are counted separately. `probe_sources` registers the
/// Unix attestor unconditionally, so a run that yields no candidates still has
/// at least one active source, and saying "no identity sources" would be false.
///
/// `sources` is the number of attestors `probe_sources` returned as active, not
/// the number it checked: sources that failed their availability probe are not
/// in the vector, and two are added without a probe at all. "active" is the
/// quantity actually measured, so that is the word used.
fn enumerate_summary(sources: usize, candidates: usize) -> String {
    let s = if sources == 1 { "source" } else { "sources" };
    let c = if candidates == 1 {
        "candidate"
    } else {
        "candidates"
    };
    format!("{sources} identity {s} active, {candidates} {c} found")
}

/// Lists the identity candidates visible to this process.
///
/// This runs the attestors in the CLI, not in personad. Every probe reads
/// process-local state, so the two see different worlds.
async fn enumerate() -> Result<()> {
    use persona_attestors::probe_sources;

    let sources = probe_sources().await;
    let mut candidates = 0usize;

    for attestor in &sources {
        match attestor.enumerate().await {
            Ok(found) => {
                for cand in found {
                    candidates += 1;
                    println!(
                        "{} | {} | {}",
                        cand.source,
                        cand.spiffe_id().uri(),
                        cand.display_name,
                    );
                }
            }
            Err(e) => {
                eprintln!("warning: {} enumerate failed: {}", attestor.name(), e);
            }
        }
    }

    eprintln!("{}", enumerate_summary(sources.len(), candidates));
    eprintln!("This list is what this shell can see. personad probes its own environment,");
    eprintln!("which this command does not read and cannot report: the daemon can hold");
    eprintln!("identities missing from this list and miss ones this list shows. Ask personad");
    eprintln!("directly with 'persona whoami'.");

    Ok(())
}

async fn fetch_jwt(args: &[String]) -> Result<()> {
    use base64::Engine as _;
    use persona_grpc::workload::JwtsvidRequest;

    let mut audience: Option<String> = None;
    let mut decode = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--audience" => {
                i += 1;
                audience = args.get(i).cloned();
            }
            "--decode" => {
                decode = true;
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let audience = match audience {
        Some(a) => a,
        None => {
            eprintln!("error: --audience is required");
            eprintln!("usage: persona fetch-jwt --audience <url> [--decode]");
            std::process::exit(1);
        }
    };

    let mut client = connect_to_daemon().await?;

    let response = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![audience],
            spiffe_id: String::new(),
        })
        .await;

    match response {
        Ok(resp) => {
            let svids = resp.into_inner().svids;
            if svids.is_empty() {
                eprintln!("error: no SVIDs returned");
                std::process::exit(1);
            }
            let jwt = &svids[0].svid;
            if !decode {
                println!("{jwt}");
            } else {
                let parts: Vec<&str> = jwt.splitn(3, '.').collect();
                if parts.len() < 2 {
                    eprintln!("error: malformed JWT");
                    std::process::exit(1);
                }
                let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[0])
                    .context("base64 decode JWT header")?;
                let header: serde_json::Value =
                    serde_json::from_slice(&header_bytes).context("parse JWT header")?;
                let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(parts[1])
                    .context("base64 decode JWT claims")?;
                let claims: serde_json::Value =
                    serde_json::from_slice(&claims_bytes).context("parse JWT claims")?;
                println!("header: {}", serde_json::to_string_pretty(&header)?);
                println!("claims: {}", serde_json::to_string_pretty(&claims)?);
            }
        }
        Err(status) => {
            eprintln!("error: personad: {}", status.message());
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Fetches a JWT-SVID with the challenge embedded in the audience string, proving
/// identity to a peer. The challenge becomes part of the JWT claims and signature,
/// preventing replay attacks.
async fn prove(args: &[String]) -> Result<()> {
    use persona_grpc::workload::JwtsvidRequest;

    let mut audience: Option<String> = None;
    let mut challenge: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--audience" => {
                i += 1;
                audience = args.get(i).cloned();
            }
            "--challenge" => {
                i += 1;
                challenge = args.get(i).cloned();
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let audience = match audience {
        Some(a) => a,
        None => {
            eprintln!("error: --audience is required");
            eprintln!("usage: persona prove --audience <url> --challenge <nonce>");
            std::process::exit(1);
        }
    };
    let challenge = match challenge {
        Some(c) => c,
        None => {
            eprintln!("error: --challenge is required");
            eprintln!("usage: persona prove --audience <url> --challenge <nonce>");
            std::process::exit(1);
        }
    };

    let audience_with_challenge = format!("{audience}?challenge={challenge}");
    let mut client = connect_to_daemon().await?;

    let response = client
        .fetch_jwtsvid(JwtsvidRequest {
            audience: vec![audience_with_challenge],
            spiffe_id: String::new(),
        })
        .await;

    match response {
        Ok(resp) => {
            let svids = resp.into_inner().svids;
            if svids.is_empty() {
                eprintln!("error: no SVIDs returned");
                std::process::exit(1);
            }
            println!("{}", svids[0].svid);
        }
        Err(status) => {
            eprintln!("error: personad: {}", status.message());
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Rejects X.509-SVID issuance. The daemon does not implement it.
///
/// The notice goes to stderr so `persona fetch-x509 > client.pem` leaves the
/// file empty instead of filling it with prose.
async fn fetch_x509() -> Result<()> {
    eprintln!("error: X.509-SVID issuance not yet implemented (persona-4qm)");
    std::process::exit(1);
}

/// Rejects both enroll subcommands. Enrollment is not implemented.
///
/// Earlier versions printed success here and stored nothing. Callers gate
/// deployments on this exit code, so it must be non-zero.
fn enroll(args: &[String]) -> Result<()> {
    let subcmd = args.first().map(String::as_str).unwrap_or("--help");
    match subcmd {
        "app" | "origin" => {
            eprintln!("error: enroll {subcmd} is not implemented");
            eprintln!("There is no enrollment store. The CLI records nothing and personad keeps");
            eprintln!("no enrollment state, so this command grants no origin or application any");
            eprintln!("scope, and un-enrolled callers are not denied anything.");
            std::process::exit(1);
        }
        "--help" | "-h" => {
            println!("usage: persona enroll app | origin <url>");
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown enroll subcommand: {other}");
            eprintln!("usage: persona enroll app | origin <url>");
            std::process::exit(1);
        }
    }
}

async fn trust_bundle(args: &[String]) -> Result<()> {
    use persona_grpc::workload::JwtBundlesRequest;

    let subcmd = args.first().map(String::as_str).unwrap_or("--help");
    match subcmd {
        "list" => {
            let mut client = connect_to_daemon().await?;
            let mut stream = client
                .fetch_jwt_bundles(JwtBundlesRequest {})
                .await
                .context("fetch_jwt_bundles")?
                .into_inner();
            use tokio_stream::StreamExt as _;
            while let Some(response) = stream.next().await {
                let response = response.context("stream error")?;
                for (domain, jwks) in &response.bundles {
                    println!("  domain: {domain}  (jwks: {} bytes)", jwks.len());
                }
            }
        }
        "add" => {
            eprintln!("error: trust-bundle add is not implemented (requires personad support)");
            eprintln!("No trust anchor was added. personad was not contacted.");
            std::process::exit(1);
        }
        "remove" => {
            eprintln!("error: trust-bundle remove is not implemented");
            eprintln!("No trust anchor was removed. personad was not contacted, so any anchor");
            eprintln!("for that domain is still live and tokens from it still validate.");
            std::process::exit(1);
        }
        "--help" | "-h" => {
            println!("usage: persona trust-bundle <list|add <url>|remove <domain>>");
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown trust-bundle subcommand: {other}");
            eprintln!("usage: persona trust-bundle <list|add <url>|remove <domain>>");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Polls personad every 30 seconds and prints identities as they change.
///
/// The loop does not give up when the daemon is unreachable: a restart should
/// not kill a watch someone is reading, and surviving outages is what a monitor
/// is for. So there is no failure threshold to pick and nothing to configure.
/// Only Ctrl-C ends it, which is the user stopping rather than a failure, so it
/// exits 0. `persona whoami` is the health check that answers with an exit code.
///
/// Identities go to stdout and diagnostics to stderr, so redirecting the stream
/// yields identities alone.
async fn watch() -> Result<()> {
    use persona_grpc::workload::JwtsvidRequest;
    use tokio::time::{interval, Duration};

    let mut ticker = interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = unix_timestamp();
                let mut client = match connect_to_daemon().await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[{now}] error: {e}");
                        continue;
                    }
                };
                match client.fetch_jwtsvid(JwtsvidRequest {
                    audience: vec!["persona:watch".to_string()],
                    spiffe_id: String::new(),
                }).await {
                    Ok(resp) => {
                        let svids = resp.into_inner().svids;
                        for svid in &svids {
                            println!("[{now}] {}", svid.spiffe_id);
                        }
                        if svids.is_empty() {
                            println!("[{now}] no identity");
                        }
                    }
                    Err(e) => {
                        eprintln!("[{now}] error: {}", e.message());
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }
    Ok(())
}

/// Seconds since the Unix epoch, stamped on each `watch` line.
///
/// Raw epoch seconds rather than a wall-clock rendering. They carry the date,
/// so a watch left running overnight does not print the same stamp twice; they
/// need no zone marker, so correlating a line against journald is arithmetic
/// rather than guesswork; and they sort. Whatever reads the stream renders one
/// when a human wants it (`date -d @1789437608`), which keeps date formatting
/// out of this crate's dependencies.
///
/// This replaced a hand-rolled `secs % 86400` split into hh:mm:ss, which was
/// UTC but carried no marker saying so, and wrapped at midnight.
fn unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Prints how to read personad's log on this platform.
///
/// Directions, not data: the platform's own reader does the work. So this goes
/// to stdout and exits 0 the way `--help` does, rather than following the
/// not-implemented commands to stderr and exit 1. journalctl is wrong on macOS,
/// where launchd writes an agent's output to the file named in the plist and
/// the unified log never sees it.
async fn show_log() -> Result<()> {
    println!("personad writes structured audit events to its stderr.");
    #[cfg(target_os = "macos")]
    {
        println!("launchd routes that to a file; the unified log never sees it.");
        println!("To follow it: tail -f ~/Library/Logs/personad.log");
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        if systemd_is_running() {
            println!("systemd routes that to the journal.");
            println!("To follow it: journalctl --user -u personad -f");
        } else {
            println!("systemd is not running here, so there is no journal to read.");
            println!("Read the stderr of however personad was started.");
        }
        Ok(())
    }
}

/// Returns true if systemd is the running init system.
///
/// `/run/systemd/system` is the marker systemd documents for `sd_booted()`.
/// Its absence is the same answer on Alpine, on WSL with systemd disabled and
/// on FreeBSD, so one check covers every host a `cfg(target_os)` cannot see:
/// the init system is a property of the running machine, not of the target.
fn systemd_is_running() -> bool {
    std::path::Path::new("/run/systemd/system").is_dir()
}

async fn install_service() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = std::path::PathBuf::from(&home).join("Library/LaunchAgents");
        std::fs::create_dir_all(&dir)?;
        let dest = dir.join("personad.plist");
        // launchd expands nothing, so the absolute path is baked in here.
        let plist = LAUNCHD_PLIST.replace("__HOME__", &home);
        std::fs::write(&dest, plist)?;
        println!("installed personad.plist");
        std::fs::create_dir_all(std::path::PathBuf::from(&home).join("Library/Logs"))?;
        println!("logs: ~/Library/Logs/personad.log");
        println!("run: launchctl load ~/Library/LaunchAgents/personad.plist");
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = PathBuf::from(&home).join(".config/systemd/user");
        if !systemd_is_running() {
            // Writing the unit anyway would leave a file nothing ever reads,
            // under a success message. Hand over the file instead: someone who
            // installed from crates.io has no checkout to copy it out of.
            eprintln!("error: systemd is not running here, so nothing was installed.");
            eprintln!("The unit is on stdout. Install it by hand at");
            eprintln!("{}/personad.service", dir.display());
            print!("{SYSTEMD_UNIT}");
            std::process::exit(1);
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let dest = dir.join("personad.service");
        std::fs::write(&dest, SYSTEMD_UNIT).with_context(|| format!("write {}", dest.display()))?;
        println!("installed personad.service, run: systemctl --user enable --now personad");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{enumerate_summary, LAUNCHD_PLIST};

    #[test]
    fn enumerate_summary_counts_sources_and_candidates_separately() {
        // The registry pushes the Unix attestor unconditionally, so zero candidates
        // does not mean zero sources. The old wording collapsed the two and printed
        // "no identity sources active" on a machine with one active source.
        assert_eq!(
            enumerate_summary(1, 0),
            "1 identity source active, 0 candidates found"
        );
        assert_eq!(
            enumerate_summary(4, 7),
            "4 identity sources active, 7 candidates found"
        );
        assert_eq!(
            enumerate_summary(2, 1),
            "2 identity sources active, 1 candidate found"
        );
        assert_eq!(
            enumerate_summary(0, 0),
            "0 identity sources active, 0 candidates found"
        );
    }

    #[test]
    fn enumerate_summary_never_denies_sources_it_found() {
        for sources in 1..8usize {
            let line = enumerate_summary(sources, 0);
            assert!(
                line.starts_with(&format!("{sources} identity source")),
                "the count must lead: {line}"
            );
            assert!(
                !line.contains("0 identity"),
                "a run with {sources} active sources must not report none: {line}"
            );
        }
    }

    #[test]
    fn launchd_plist_is_a_template_that_substitutes_cleanly() {
        assert!(
            LAUNCHD_PLIST.contains("__HOME__"),
            "the plist must carry a placeholder: launchd expands neither ~ nor $HOME"
        );
        let filled = LAUNCHD_PLIST.replace("__HOME__", "/Users/example");
        assert!(
            !filled.contains("__HOME__"),
            "every placeholder must be substituted"
        );
        assert!(filled.contains("<string>/Users/example/.cargo/bin/personad</string>"));
        assert!(
            !filled.contains("/usr/local/bin"),
            "the daemon is a user-session service and must not need a root-owned path"
        );
    }

    #[test]
    fn launchd_plist_logs_under_the_home_library_and_never_to_tmp() {
        // The daemon logs SPIFFE IDs, attestor sources and assurance levels, so the
        // log must not sit in a world-writable directory under a predictable name.
        // ~/Library is mode 0700 on macOS, which is what protects the file; launchd
        // itself creates it 0644.
        //
        // Redirection is required, not optional: an agent with no StandardOutPath has
        // its output discarded rather than routed to the unified log. Measured on
        // macOS 26.6.2 -- a test agent ran to completion and logged nothing.
        let filled = LAUNCHD_PLIST.replace("__HOME__", "/Users/example");
        assert!(!filled.contains("/tmp/"), "no path under /tmp");
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(
                filled.contains(key),
                "{key} must be set or launchd discards the output"
            );
        }
        assert!(filled.contains("<string>/Users/example/Library/Logs/personad.log</string>"));
    }
}
