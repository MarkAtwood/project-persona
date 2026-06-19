use crate::{
    Attestor, DidKeyAttestor, Fido2Attestor, GoaAttestor, GpgAttestor, OidcCachedAttestor,
    PivAttestor, SshAgentAttestor, TailscaleAttestor,
};
use std::sync::Arc;

/// Probes all known identity sources and returns those that are available.
///
/// Probe order (matches SPEC-HIA.md §Platform Detection):
/// 1. Tailscale socket
/// 2. SSH agent (SSH_AUTH_SOCK)
/// 3. OIDC cached tokens
/// 4. DID keys (PERSONA_DID_KEYS)
/// 5. GPG keyring
/// 6. FIDO2 hardware keys
///
/// Each source is probed with a lightweight availability check before inclusion.
/// A source that fails to probe is logged and skipped — never fatal.
pub async fn probe_sources() -> Vec<Arc<dyn Attestor>> {
    let mut active: Vec<Arc<dyn Attestor>> = Vec::new();

    // 1. Tailscale
    let ts = TailscaleAttestor::new();
    if ts.is_available() {
        tracing::info!("tailscale: available");
        active.push(Arc::new(ts));
    } else {
        tracing::debug!("tailscale: socket not found, skipping");
    }

    // 2. SSH agent
    if SshAgentAttestor::is_available() {
        tracing::info!("ssh-agent: available");
        active.push(Arc::new(SshAgentAttestor::new()));
    } else {
        tracing::debug!("ssh-agent: SSH_AUTH_SOCK not set or socket missing, skipping");
    }

    // 3. OIDC cached tokens
    let oidc = OidcCachedAttestor::new();
    // OidcCachedAttestor is always probed — it scans files lazily in enumerate()
    active.push(Arc::new(oidc));
    tracing::debug!("oidc-cached: added (files scanned on demand)");

    // 4. DID keys
    if DidKeyAttestor::is_available() {
        tracing::info!("did:key: available");
        active.push(Arc::new(DidKeyAttestor::new()));
    } else {
        tracing::debug!("did:key: PERSONA_DID_KEYS not set, skipping");
    }

    // 5. GPG
    if GpgAttestor::is_available() {
        tracing::info!("gpg: available");
        active.push(Arc::new(GpgAttestor::new()));
    } else {
        tracing::debug!("gpg: not configured, skipping");
    }

    // 6. FIDO2
    if Fido2Attestor::is_available() {
        tracing::info!("fido2: available");
        active.push(Arc::new(Fido2Attestor::new()));
    } else {
        tracing::debug!("fido2: no devices found or feature not enabled, skipping");
    }

    // 7. GNOME Online Accounts
    if GoaAttestor::is_available() {
        tracing::info!("gnome-online-accounts: available");
        active.push(Arc::new(GoaAttestor::new()));
    } else {
        tracing::debug!(
            "gnome-online-accounts: not a GNOME session or goa feature not enabled, skipping"
        );
    }

    // 8. PIV/smartcard
    if PivAttestor::is_available() {
        tracing::info!("piv: available");
        active.push(Arc::new(PivAttestor::new()));
    } else {
        tracing::debug!("piv: no smartcard found or pkcs11 feature not enabled, skipping");
    }

    if active.is_empty() {
        tracing::warn!("no identity sources available; personad will issue no SVIDs");
    } else {
        tracing::info!(count = active.len(), "identity sources active");
    }

    active
}
