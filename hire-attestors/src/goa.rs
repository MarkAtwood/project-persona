//! GNOME Online Accounts (GOA) attestor via D-Bus.
//!
//! Requires the `goa` feature and Linux. Without it, returns empty/unavailable.
// ponytail: full D-Bus org.gnome.OnlineAccounts enumeration | upgrade path:
//   use zbus crate to call GetAccounts, extract OIDC tokens per provider

use async_trait::async_trait;

use crate::{Attestor, AttestorError, Candidate};

/// Attestor for GNOME Online Accounts.
///
/// Queries D-Bus `org.gnome.OnlineAccounts` for configured accounts and
/// extracts per-provider OIDC tokens. Assurance and presence would come from a
/// verified token via `prove()`, which is not implemented, so this attestor
/// contributes no level today.
///
/// Only compiled on Linux; requires the `goa` feature flag.
#[derive(Debug)]
pub struct GoaAttestor;

impl GoaAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if running on Linux with a GNOME session and the goa feature enabled.
    pub fn is_available() -> bool {
        #[cfg(all(target_os = "linux", feature = "goa"))]
        return std::env::var("GNOME_DESKTOP_SESSION_ID").is_ok()
            || std::env::var("XDG_CURRENT_DESKTOP")
                .map(|d| d.to_uppercase().contains("GNOME"))
                .unwrap_or(false);
        #[cfg(not(all(target_os = "linux", feature = "goa")))]
        return false;
    }
}

impl Default for GoaAttestor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attestor for GoaAttestor {
    fn name(&self) -> &str {
        "gnome-online-accounts"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        // ponytail: full D-Bus account enumeration not yet implemented | upgrade path:
        //   zbus::Connection::session().await, proxy to org.gnome.OnlineAccounts,
        //   call GetAccounts(), extract OAuthBasedProviders for Google/Microsoft/Nextcloud
        Ok(vec![])
    }
}
