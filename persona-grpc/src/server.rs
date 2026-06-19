use std::path::Path;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use crate::service::WorkloadApiService;
use crate::workload::spiffe_workload_api_server::SpiffeWorkloadApiServer;

/// Bind and serve the SPIFFE Workload API on the given Unix socket path.
///
/// Creates parent directories if needed. Sets socket permissions to 0600.
/// Removes a stale socket file if one is present before binding.
pub async fn serve(
    socket_path: &Path,
    service: WorkloadApiService,
) -> Result<(), Box<dyn std::error::Error>> {
    if socket_path.exists() {
        tracing::warn!(?socket_path, "removing stale socket");
        std::fs::remove_file(socket_path)?;
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!(?socket_path, "SPIFFE Workload API listening");

    let incoming = UnixListenerStream::new(listener);
    Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
