use crate::TrustDomain;
use std::collections::HashMap;
use std::sync::RwLock;

/// A single trust bundle for one trust domain.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    /// DER-encoded X.509 CA certificates for this trust domain.
    pub x509_authorities: Vec<Vec<u8>>,
    /// JWKS JSON for this trust domain (JWT verification).
    pub jwt_authorities: serde_json::Value,
}

/// Thread-safe store of trust bundles keyed by trust domain.
///
/// Populated at daemon startup from the local CA key and any federated sources.
/// Read by FetchJWTBundles and FetchX509Bundles RPCs.
#[derive(Debug, Default)]
pub struct TrustBundleStore {
    bundles: RwLock<HashMap<String, TrustBundle>>,
}

impl TrustBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the bundle for a trust domain.
    pub fn upsert(&self, bundle: TrustBundle) {
        let key = bundle.trust_domain.to_string();
        self.bundles
            .write()
            .expect("trust bundle lock poisoned")
            .insert(key, bundle);
    }

    /// Get a snapshot of all current bundles.
    pub fn snapshot(&self) -> Vec<TrustBundle> {
        self.bundles
            .read()
            .expect("trust bundle lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Get a single bundle by trust domain string key.
    pub fn get(&self, trust_domain: &str) -> Option<TrustBundle> {
        self.bundles
            .read()
            .expect("trust bundle lock poisoned")
            .get(trust_domain)
            .cloned()
    }
}
