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
        prepare_socket_dir(parent)?;
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

/// Creates the socket's parent directory owned by this user and readable only by them.
///
/// The fallback path is `/tmp/persona-{uid}`, and `/tmp` is world-writable, so another
/// local user can create that directory first. `create_dir_all` succeeds on a directory
/// that already exists no matter who owns it, and the sticky bit on `/tmp` protects
/// entries in `/tmp` rather than entries inside a subdirectory someone else owns. Binding
/// there would let that user unlink the socket and offer their own in its place, which
/// for a daemon that issues identity credentials means impersonating it. So refuse a
/// directory this user does not own, and tighten one that is too permissive.
#[cfg(unix)]
fn prepare_socket_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match std::fs::metadata(dir) {
        Ok(md) => {
            if !md.is_dir() {
                return Err(format!("{} exists and is not a directory", dir.display()).into());
            }
            // SAFETY: getuid() takes no arguments, has no preconditions and cannot fail.
            let uid = unsafe { libc::getuid() };
            let sticky = md.mode() & 0o1000 != 0;
            if md.uid() == uid {
                if md.mode() & 0o077 != 0 {
                    tracing::warn!(
                        ?dir,
                        mode = format!("{:o}", md.mode() & 0o777),
                        "tightening socket directory to 0700"
                    );
                    std::fs::set_permissions(dir, Permissions::from_mode(0o700))?;
                }
            } else if !(md.uid() == 0 && sticky) {
                // A root-owned sticky directory such as /tmp is safe: the kernel lets
                // only the entry's owner remove it. Anything else owned by another user
                // is not, because the directory's owner can unlink whatever we bind.
                return Err(format!(
                    "refusing to use {}: owned by uid {}, expected {uid}",
                    dir.display(),
                    md.uid()
                )
                .into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_socket_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::prepare_socket_dir;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        // SAFETY: getpid() takes no arguments, has no preconditions and cannot fail.
        let pid = unsafe { libc::getpid() };
        std::env::temp_dir().join(format!("persona-srvtest-{pid}-{name}"))
    }

    #[test]
    fn creates_a_missing_directory_private_to_this_user() {
        let dir = scratch("missing");
        let _ = fs::remove_dir_all(&dir);
        prepare_socket_dir(&dir).expect("should create the directory");
        let md = fs::metadata(&dir).expect("directory should exist");
        assert!(md.is_dir());
        assert_eq!(
            md.mode() & 0o777,
            0o700,
            "must not be group- or world-accessible"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tightens_a_directory_we_own_that_is_too_permissive() {
        let dir = scratch("loose");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        prepare_socket_dir(&dir).expect("should accept and tighten a directory we own");
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accepts_a_root_owned_sticky_directory() {
        // /tmp is root-owned and sticky, so the kernel lets only an entry's owner
        // remove it. The e2e test binds a socket directly there.
        let tmp = PathBuf::from("/tmp");
        let md = fs::metadata(&tmp).unwrap();
        assert_eq!(md.uid(), 0, "precondition: /tmp is root-owned");
        assert_ne!(md.mode() & 0o1000, 0, "precondition: /tmp is sticky");
        prepare_socket_dir(&tmp).expect("a root-owned sticky directory is safe");
    }

    #[test]
    fn refuses_a_directory_owned_by_another_user_without_the_sticky_bit() {
        // /usr is root-owned and not sticky. Binding under a directory another user
        // owns would let them unlink our socket and offer their own.
        let usr = PathBuf::from("/usr");
        let md = fs::metadata(&usr).unwrap();
        assert_eq!(md.uid(), 0, "precondition: /usr is root-owned");
        assert_eq!(md.mode() & 0o1000, 0, "precondition: /usr is not sticky");
        let err = prepare_socket_dir(&usr).expect_err("must refuse");
        assert!(err.to_string().contains("refusing to use"), "got: {err}");
    }
}
