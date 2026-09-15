//! OIDC cached-token attestor — enumerates identity candidates from local token
//! caches (gcloud ADC, Azure MSAL) without network I/O.
//!
// ponytail: manual JWT payload parsing without signature validation |
//   upgrade to jsonwebtoken crate when validation is needed

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use hire_core::PresenceLevel;

use crate::{
    AttainableAssurance, Attestor, AttestorError, Candidate, FreshnessResult, ProofCost,
    SelfAssertedDomain,
};

/// Attestor that reads cached OIDC tokens from well-known local paths.
#[derive(Debug)]
pub struct OidcCachedAttestor;

impl OidcCachedAttestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OidcCachedAttestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode the JWT payload section without validating the signature.
fn parse_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true if the token's `exp` claim is in the future.
///
/// Reads the raw token every time. This is an unauthenticated field and is
/// treated as a hint about staleness only — never as an assurance signal.
fn token_is_unexpired(raw_token: &str) -> bool {
    parse_jwt_payload(raw_token)
        .and_then(|p| p.get("exp").and_then(|v| v.as_u64()))
        .is_some_and(|exp| exp > now_unix())
}

/// Build a Candidate from a raw JWT string, or return None if parsing fails.
fn candidate_from_jwt(raw_token: &str) -> Option<Candidate> {
    let payload = parse_jwt_payload(raw_token)?;

    let sub = payload.get("sub")?.as_str()?.to_owned();

    let display_name = payload
        .get("email")
        .or_else(|| payload.get("preferred_username"))
        .and_then(|v| v.as_str())
        .unwrap_or(&sub)
        .to_owned();

    // ponytail: the token's `iss` is unverified, so it names no trust domain |
    //   ceiling: OIDC identities sit under ssh.local and cap at the floor tier |
    //   upgrade path: a signature-verifying prove() returns
    //   Evidence::IdpVerified, which re-anchors the domain to the verified issuer
    Some(
        Candidate::new(
            "oidc-cached",
            SelfAssertedDomain::SshLocal,
            format!("user/{sub}/via/oidc-cached"),
            display_name,
        )
        .with_attainable(AttainableAssurance::Iaa2)
        .with_proof_cost(ProofCost::Silent),
    )
}

/// Runs [`scan_token_caches`] on a blocking thread.
///
/// The scan reads and parses up to three JSON files under `$HOME`. An Azure
/// MSAL cache is routinely a few hundred KiB, and `$HOME` may sit on NFS or
/// autofs where a single `read_to_string` blocks for seconds. Called directly
/// from an async method it stalls the reactor thread, and with it every other
/// task scheduled there -- not just this one. `freshness` re-scans on every
/// call, so this is a hot path, not startup.
///
/// A `JoinError` here means the scan panicked; the source is reported
/// unavailable rather than propagating the panic into the caller's task.
async fn scan_token_caches_off_reactor() -> Result<Vec<(Candidate, String)>, AttestorError> {
    tokio::task::spawn_blocking(scan_token_caches)
        .await
        .map_err(|e| AttestorError::Unavailable(format!("token cache scan failed: {e}")))
}

/// Scan well-known token cache files and return all parseable candidates.
fn scan_token_caches() -> Vec<(Candidate, String)> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return vec![],
    };

    let mut pairs: Vec<(Candidate, String)> = Vec::new();

    // --- gcloud application default credentials ---
    let gcloud_adc = format!("{home}/.config/gcloud/application_default_credentials.json");
    if let Ok(text) = std::fs::read_to_string(&gcloud_adc) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(token) = json.get("id_token").and_then(|v| v.as_str()) {
                if let Some(candidate) = candidate_from_jwt(token) {
                    pairs.push((candidate, token.to_owned()));
                }
            }
        }
    }

    // --- Azure MSAL token cache ---
    for fname in &["msal_token_cache.json", "accessTokens.json"] {
        let path = format!("{home}/.azure/{fname}");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                collect_azure_tokens(&json, &mut pairs);
            }
        }
    }

    pairs
}

/// Walk Azure MSAL cache JSON looking for id_token or idToken fields.
fn collect_azure_tokens(json: &serde_json::Value, out: &mut Vec<(Candidate, String)>) {
    // msal_token_cache.json: top-level "IdToken" object with entries that
    // have a "secret" field containing the raw JWT.
    if let Some(id_tokens) = json.get("IdToken").and_then(|v| v.as_object()) {
        for entry in id_tokens.values() {
            if let Some(token) = entry.get("secret").and_then(|v| v.as_str()) {
                if let Some(candidate) = candidate_from_jwt(token) {
                    out.push((candidate, token.to_owned()));
                }
            }
        }
        return;
    }

    // accessTokens.json: array of objects with an "idToken" field.
    if let Some(arr) = json.as_array() {
        for entry in arr {
            if let Some(token) = entry.get("idToken").and_then(|v| v.as_str()) {
                if let Some(candidate) = candidate_from_jwt(token) {
                    out.push((candidate, token.to_owned()));
                }
            }
        }
    }
}

#[async_trait]
impl Attestor for OidcCachedAttestor {
    fn name(&self) -> &str {
        "oidc-cached"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        let pairs = scan_token_caches_off_reactor().await?;
        Ok(pairs.into_iter().map(|(candidate, _)| candidate).collect())
    }

    async fn freshness(&self, candidate: &Candidate) -> Result<FreshnessResult, AttestorError> {
        // Re-read `exp` on the raw token, not an assurance level this attestor
        // derived from that same `exp` two functions earlier.
        let pairs = scan_token_caches_off_reactor().await?;
        match pairs.into_iter().find(|(c, _)| c.path == candidate.path) {
            None => Ok(FreshnessResult::Unavailable),
            Some((_, raw)) => {
                if token_is_unexpired(&raw) {
                    Ok(FreshnessResult::Fresh)
                } else {
                    Ok(FreshnessResult::Stale(PresenceLevel::None))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_scan_round_trips_through_the_blocking_pool() {
        // Covers the spawn_blocking plumbing only: that the scan runs to
        // completion on a blocking thread and its result comes back, whatever
        // this machine's $HOME happens to hold. A JoinError or a panic inside
        // the scan fails this.
        //
        // It does NOT cover the reason for the change -- that the scan no
        // longer occupies a reactor thread. Demonstrating that needs a scan
        // slow enough for a sibling task to observe progress during it, which
        // is a timing race, and a flaky test is worse than an absent one. The
        // property is spawn_blocking's documented contract.
        let scanned = scan_token_caches_off_reactor()
            .await
            .expect("the scan must not fail on any machine");
        // Every returned pair must be a candidate parsed from its own token,
        // which holds vacuously on a machine with no caches.
        for (candidate, token) in &scanned {
            assert!(!token.is_empty(), "a pair must carry its raw token");
            assert!(
                candidate.path.contains("/via/oidc-cached"),
                "candidate path should record its source: {}",
                candidate.path
            );
        }
    }
}
