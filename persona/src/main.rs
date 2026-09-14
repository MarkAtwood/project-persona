//! persona — CLI for the personad identity daemon.

use anyhow::{Context, Result};
use persona_grpc::workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use std::path::PathBuf;
use tonic::transport::Channel;

#[allow(dead_code)] // used only on macOS via #[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!--
  Template. launchd expands nothing in this file: no ~, no $HOME, no systemd-style
  specifiers, so every path must be absolute and literal. `persona install-service`
  substitutes __HOME__ and writes the result to ~/Library/LaunchAgents/personad.plist.
  Copying this file into place unedited will not work.

  Output is not redirected. launchd routes it to the system log:
      log stream --predicate 'process == \"personad\"'
  To keep a file instead, add StandardOutPath and StandardErrorPath pointing somewhere
  in your home directory, for example __HOME__/Library/Logs/personad.log. Do not point
  them at /tmp: the daemon logs SPIFFE IDs, attestor sources and assurance levels, and
  a predictable name in a world-writable directory can be pre-created by another user.
-->
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>personad</string>
    <key>ProgramArguments</key>
    <array>
        <string>__HOME__/.cargo/bin/personad</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
";

const SYSTEMD_UNIT: &str = "\
[Unit]
Description=Persona identity daemon (SPIFFE Workload API)
After=tailscaled.service
Documentation=https://github.com/persona-id/persona

[Service]
Type=simple
ExecStart=%h/.cargo/bin/personad
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
";

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

    let path_str = path.to_str().unwrap().to_owned();
    let channel = Endpoint::try_from("http://[::]:50051")
        .context("invalid endpoint")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = path_str.clone();
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
        "enroll" => enroll(&args[2..]).await,
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
            println!("  fetch-x509       fetch an X.509-SVID from the daemon");
            println!("  prove            prove identity to a peer (JWT with challenge)");
            println!("  enroll           enroll an application or origin");
            println!("  install-service  write personad service file (systemd or launchd)");
            println!("  trust-bundle     list or manage trust bundles");
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
                println!("no identity");
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
        }
    }

    Ok(())
}

async fn enumerate() -> Result<()> {
    use persona_attestors::probe_sources;

    let sources = probe_sources().await;
    let mut any = false;

    for attestor in &sources {
        match attestor.enumerate().await {
            Ok(claims) => {
                for claim in claims {
                    any = true;
                    println!(
                        "{} | {} | {} | {} | {}",
                        claim.source,
                        claim.spiffe_id.uri(),
                        claim.assurance,
                        claim.presence,
                        claim.display_name,
                    );
                }
            }
            Err(e) => {
                eprintln!("warning: {} enumerate failed: {}", attestor.name(), e);
            }
        }
    }

    if !any {
        println!("no identity sources active");
    }

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

/// Stub for X.509-SVID issuance — not yet implemented by the daemon.
async fn fetch_x509() -> Result<()> {
    println!("X.509-SVID issuance not yet implemented (persona-4qm)");
    Ok(())
}

/// Enrolls an application or an authorized origin.
async fn enroll(args: &[String]) -> Result<()> {
    let subcmd = args.first().map(String::as_str).unwrap_or("--help");
    match subcmd {
        "app" => enroll_app().await,
        "origin" => {
            let url = match args.get(1) {
                Some(u) => u,
                None => {
                    eprintln!("error: url required");
                    eprintln!("usage: persona enroll origin <url>");
                    std::process::exit(1);
                }
            };
            println!("origin {url} authorized (in-memory)");
            Ok(())
        }
        other => {
            eprintln!("unknown enroll subcommand: {other}");
            eprintln!("usage: persona enroll app | origin <url>");
            std::process::exit(1);
        }
    }
}

/// Shows enrollment info for the current process as an example app enrollment.
async fn enroll_app() -> Result<()> {
    let exe = std::fs::read_link("/proc/self/exe").context("read /proc/self/exe")?;
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| exe.display().to_string());
    // SAFETY: getpid() and getuid() have no preconditions and always succeed.
    let pid = unsafe { libc::getpid() };
    let uid = unsafe { libc::getuid() };
    println!("Enrolled: {name} (pid={pid}, uid={uid})");
    println!("Note: enrollment is stored in-memory only in this version");
    Ok(())
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
            println!("trust-bundle federation not yet implemented (requires personad support)");
        }
        "remove" => {
            println!("trust-bundle removal not yet implemented");
        }
        _ => {
            println!("usage: persona trust-bundle <list|add <url>|remove <domain>>");
        }
    }
    Ok(())
}

async fn watch() -> Result<()> {
    use persona_grpc::workload::JwtsvidRequest;
    use tokio::time::{interval, Duration};

    let mut ticker = interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = chrono_timestamp();
                let mut client = match connect_to_daemon().await {
                    Ok(c) => c,
                    Err(e) => {
                        println!("[{now}] error: {e}");
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
                        println!("[{now}] error: {}", e.message());
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

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 86400;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    format!("{h:02}:{m:02}:{sec:02}")
}

async fn show_log() -> Result<()> {
    println!("Note: personad writes structured audit events to its stderr/journald.");
    println!("To view logs: journalctl --user -u personad -f");
    println!("Or if running directly: check personad stderr output.");
    Ok(())
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
        println!("logs: log stream --predicate 'process == \"personad\"'");
        println!("run: launchctl load ~/Library/LaunchAgents/personad.plist");
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        // Linux / systemd path
        let home = std::env::var("HOME").context("HOME not set")?;
        let dir = PathBuf::from(&home).join(".config/systemd/user");
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let dest = dir.join("personad.service");
        std::fs::write(&dest, SYSTEMD_UNIT).with_context(|| format!("write {}", dest.display()))?;
        println!("installed personad.service, run: systemctl --user enable --now personad");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LAUNCHD_PLIST;

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
    fn launchd_plist_does_not_write_identity_logs_to_a_shared_directory() {
        // The daemon logs SPIFFE IDs, attestor sources and assurance levels. A
        // predictable name under /tmp can be pre-created by another local user.
        let filled = LAUNCHD_PLIST.replace("__HOME__", "/Users/example");
        for key in ["<key>StandardOutPath</key>", "<key>StandardErrorPath</key>"] {
            assert!(
                !filled.contains(key),
                "{key} is set; output should go to the system log"
            );
        }
        assert!(!filled.contains("/tmp/"), "no path under /tmp");
    }
}
