//! OIDC cached-token attestor — enumerates identity claims from local token
//! caches (gcloud ADC, Azure MSAL) without network I/O.
//!
// ponytail: manual JWT payload parsing without signature validation |
//   upgrade to jsonwebtoken crate when validation is needed

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use persona_core::{IdentityAssurance, PresenceLevel, SpiffeId, TrustDomain};

use crate::{Attestor, AttestorError, Claim, FreshnessResult, SignedAssertion};

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

/// Extract a usable domain string from an OIDC issuer URI.
/// e.g. "https://accounts.google.com" → "accounts.google.com"
fn extract_domain(iss: &str) -> String {
    iss.strip_prefix("https://")
        .or_else(|| iss.strip_prefix("http://"))
        .unwrap_or(iss)
        .trim_end_matches('/')
        .to_owned()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a Claim from a raw JWT string, or return None if parsing fails.
fn claim_from_jwt(raw_token: &str) -> Option<Claim> {
    let payload = parse_jwt_payload(raw_token)?;

    let sub = payload.get("sub")?.as_str()?.to_owned();
    let iss = payload.get("iss")?.as_str()?.to_owned();
    let exp = payload.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);

    let display_name = payload
        .get("email")
        .or_else(|| payload.get("preferred_username"))
        .and_then(|v| v.as_str())
        .unwrap_or(&sub)
        .to_owned();

    let assurance = if exp > now_unix() {
        IdentityAssurance::Iaa2
    } else {
        IdentityAssurance::Iaa1
    };

    let domain = extract_domain(&iss);

    Some(Claim {
        source: "oidc-cached".into(),
        assurance,
        presence: PresenceLevel::None,
        spiffe_id: SpiffeId::new(
            TrustDomain::OrgOidc(domain),
            format!("user/{sub}/via/oidc-cached"),
        ),
        display_name,
    })
}

/// Scan well-known token cache files and return all parseable claims.
fn scan_token_caches() -> Vec<(Claim, String)> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return vec![],
    };

    let mut pairs: Vec<(Claim, String)> = Vec::new();

    // --- gcloud application default credentials ---
    let gcloud_adc = format!("{home}/.config/gcloud/application_default_credentials.json");
    if let Ok(text) = std::fs::read_to_string(&gcloud_adc) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(token) = json.get("id_token").and_then(|v| v.as_str()) {
                if let Some(claim) = claim_from_jwt(token) {
                    pairs.push((claim, token.to_owned()));
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
fn collect_azure_tokens(json: &serde_json::Value, out: &mut Vec<(Claim, String)>) {
    // msal_token_cache.json: top-level "IdToken" object with entries that
    // have a "secret" field containing the raw JWT.
    if let Some(id_tokens) = json.get("IdToken").and_then(|v| v.as_object()) {
        for entry in id_tokens.values() {
            if let Some(token) = entry.get("secret").and_then(|v| v.as_str()) {
                if let Some(claim) = claim_from_jwt(token) {
                    out.push((claim, token.to_owned()));
                }
            }
        }
        return;
    }

    // accessTokens.json: array of objects with an "idToken" field.
    if let Some(arr) = json.as_array() {
        for entry in arr {
            if let Some(token) = entry.get("idToken").and_then(|v| v.as_str()) {
                if let Some(claim) = claim_from_jwt(token) {
                    out.push((claim, token.to_owned()));
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

    async fn enumerate(&self) -> Result<Vec<Claim>, AttestorError> {
        let pairs = scan_token_caches();
        Ok(pairs.into_iter().map(|(claim, _)| claim).collect())
    }

    async fn prove(
        &self,
        claim: &Claim,
        _challenge: &[u8],
    ) -> Result<SignedAssertion, AttestorError> {
        // The cached JWT is itself the signed assertion. Re-scan to find it.
        let pairs = scan_token_caches();
        let raw_token = pairs
            .into_iter()
            .find(|(c, _)| c.spiffe_id == claim.spiffe_id)
            .map(|(_, tok)| tok)
            .ok_or_else(|| {
                AttestorError::Unavailable(format!("no cached token found for {}", claim.spiffe_id))
            })?;

        Ok(SignedAssertion {
            bytes: raw_token.into_bytes(),
            format: "application/jwt".into(),
        })
    }

    async fn freshness(&self, claim: &Claim) -> Result<FreshnessResult, AttestorError> {
        // Re-scan and re-check exp.
        let pairs = scan_token_caches();
        match pairs
            .into_iter()
            .find(|(c, _)| c.spiffe_id == claim.spiffe_id)
        {
            None => Ok(FreshnessResult::Unavailable),
            Some((c, _)) => {
                if c.assurance >= IdentityAssurance::Iaa2 {
                    Ok(FreshnessResult::Fresh)
                } else {
                    Ok(FreshnessResult::Stale(PresenceLevel::None))
                }
            }
        }
    }
}
