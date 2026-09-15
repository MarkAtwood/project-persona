//! personad — human identity daemon, SPIFFE Workload API.

use std::sync::Arc;

use anyhow::Context;
use persona_attestors::registry::probe_sources;
use persona_core::{SvidSigner, TrustBundle, TrustBundleStore, TrustDomain};
use persona_grpc::{server, service::WorkloadApiService};
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

// ponytail: localhost HTTP gateway stub | upgrade path: axum with rustls, JWT endpoint,
//   SO_PEERCRED analog via Origin header, enrolled origins allowlist
async fn maybe_start_http_gateway() {
    // HTTP gateway not yet implemented in this version.
    // Browser consumers should use the native messaging host instead.
    tracing::debug!("http gateway: stub, not started");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("personad starting");

    // Ephemeral CA keypair — never persisted
    let signer = Arc::new(SvidSigner::new().context("failed to generate signing keypair")?);

    // Trust bundle store: seed with the JWT authority for our local trust domain.
    let bundles = Arc::new(TrustBundleStore::new());
    // ponytail: hardcoded local trust domain | upgrade to configurable trust domain per SPEC-HIA §Trust Domain Model
    bundles.upsert(TrustBundle::local(TrustDomain::SshLocal, &signer));

    // Probe identity sources
    let attestors = probe_sources().await;

    maybe_start_http_gateway().await;

    // Build gRPC service
    let service = WorkloadApiService::new(Arc::clone(&signer), Arc::clone(&bundles), attestors);

    let socket_path = persona_grpc::socket::workload_socket_path();

    info!(?socket_path, "binding SPIFFE Workload API socket");

    // Signal handling: SIGTERM and SIGINT trigger graceful shutdown
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("SIGINT handler")?;

    let socket_path_cleanup = socket_path.clone();
    tokio::select! {
        result = server::serve(&socket_path, service) => {
            // ServeError is Send + Sync, so `?` carries the source chain here.
            // The boxed error this used to return was neither, which left this
            // call site nothing to do but flatten it to its Display text.
            result.context("SPIFFE Workload API server")?;
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            info!("received SIGINT, shutting down");
        }
    }

    // Clean up socket file
    if socket_path_cleanup.exists() {
        let _ = std::fs::remove_file(&socket_path_cleanup);
        info!("socket removed");
    }

    info!("personad stopped");
    Ok(())
}
