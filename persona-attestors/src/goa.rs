//! GNOME Online Accounts (GOA) attestor via D-Bus.
//!
//! Requires the `goa` feature and Linux. Without it, returns empty/unavailable.
// ponytail: full D-Bus org.gnome.OnlineAccounts enumeration | upgrade path:
//   use zbus crate to call GetAccounts, extract OIDC tokens per provider

use async_trait::async_trait;

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

/// Attestor for GNOME Online Accounts.
///
/// Queries D-Bus `org.gnome.OnlineAccounts` for configured accounts and
/// extracts per-provider OIDC tokens. Assurance: Iaa2 (IdP-verified).
/// Presence: Session (token may be stale).
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

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        // ponytail: full D-Bus account enumeration not yet implemented | upgrade path:
        //   zbus::Connection::session().await, proxy to org.gnome.OnlineAccounts,
        //   call GetAccounts(), extract OAuthBasedProviders for Google/Microsoft/Nextcloud
        Ok(vec![])
    }

    async fn prove(
        &self,
        _claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        // ponytail: OIDC token presentation not yet implemented | upgrade:
        //   fetch access token via EnsureCredentials(), sign challenge with it
        Err(AttestorError::ChallengeFailed(
            "GOA signing not yet implemented".into(),
        ))
    }

    async fn freshness(&self, _claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        if Self::is_available() {
            Ok(FreshnessResult::Fresh)
        } else {
            Ok(FreshnessResult::Unavailable)
        }
    }
}
