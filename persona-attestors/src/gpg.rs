//! GPG attestor — enumerates keys via `gpg --list-keys --with-colons`.
//!
// ponytail: enumerate only; signing not implemented | upgrade path is
//   gpg --detach-sign --local-user <fingerprint> via stdin/stdout

use async_trait::async_trait;

use crate::{Attestor, AttestorError, Candidate, SelfAssertedDomain};

/// Attestor that lists GPG keys from the user's keyring.
#[derive(Debug)]
pub struct GpgAttestor;

impl GpgAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if a gpg binary exists and `~/.gnupg/` is present.
    pub fn is_available() -> bool {
        which_gpg().is_some() && default_gnupg_dir().exists()
    }
}

impl Default for GpgAttestor {
    fn default() -> Self {
        Self::new()
    }
}

fn which_gpg() -> Option<std::path::PathBuf> {
    for p in &["/usr/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg2"] {
        let p = std::path::Path::new(p);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn default_gnupg_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    std::path::PathBuf::from(home).join(".gnupg")
}

fn parse_gpg_colons(output: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut current_fp: Option<String> = None;
    let mut current_uid: Option<String> = None;

    for line in output.lines() {
        let fields: Vec<&str> = line.splitn(12, ':').collect();
        match fields.first() {
            Some(&"pub") => {
                // Flush previous key before starting a new one.
                if let (Some(fp), Some(uid)) = (current_fp.take(), current_uid.take()) {
                    candidates.push(make_candidate(fp, uid));
                }
            }
            Some(&"fpr") => {
                current_fp = fields.get(9).map(|s| s.to_string());
            }
            Some(&"uid") if current_uid.is_none() => {
                current_uid = fields.get(9).map(|s| s.to_string());
            }
            _ => {}
        }
    }
    // Flush the last key.
    if let (Some(fp), Some(uid)) = (current_fp, current_uid) {
        candidates.push(make_candidate(fp, uid));
    }
    candidates
}

// ponytail: gpg candidates sit under ssh.local, not pgp.local | ceiling: the
//   PgpLocal trust domain is never used | upgrade path: switch the domain in a
//   change that also migrates any enrolled SPIFFE IDs
fn make_candidate(fingerprint: String, display_name: String) -> Candidate {
    let short_fp = if fingerprint.len() >= 8 {
        fingerprint[fingerprint.len() - 8..].to_lowercase()
    } else {
        fingerprint.clone()
    };
    Candidate::new(
        "gpg",
        SelfAssertedDomain::SshLocal,
        format!("gpg/{short_fp}"),
        display_name,
    )
}

#[async_trait]
impl Attestor for GpgAttestor {
    fn name(&self) -> &str {
        "gpg"
    }

    async fn enumerate(&self) -> Result<Vec<Candidate>, AttestorError> {
        let gpg =
            which_gpg().ok_or_else(|| AttestorError::Unavailable("gpg binary not found".into()))?;

        let output = tokio::process::Command::new(gpg)
            .args([
                "--batch",
                "--no-tty",
                "--list-keys",
                "--with-colons",
                "--fingerprint",
            ])
            .output()
            .await
            .map_err(|e| AttestorError::Unavailable(format!("gpg exec failed: {e}")))?;

        if !output.status.success() {
            // No keys or gpg not configured — not an error.
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_gpg_colons(&stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gpg_colons_extracts_candidate() {
        let sample = "\
pub:u:4096:1:DEADBEEF12345678:1700000000:::-:::scESC:::::::23::0:\n\
fpr:::::::::AABBCCDDEEFF00112233445566778899DEADBEEF:\n\
uid:u::::1700000000::AABBCC::Alice <alice@example.com>:::::::::0:\n";
        let candidates = parse_gpg_colons(sample);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, "gpg");
        assert!(candidates[0].spiffe_id().uri().contains("deadbeef"));
        assert_eq!(candidates[0].display_name, "Alice <alice@example.com>");
    }
}
