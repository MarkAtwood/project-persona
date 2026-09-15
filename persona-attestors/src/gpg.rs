//! GPG attestor — enumerates keys whose secret half the operator holds, via
//! `gpg --list-secret-keys --with-colons`.
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

/// Pushes a candidate for a primary key whose secret half the operator holds.
fn flush_key(
    candidates: &mut Vec<Candidate>,
    fingerprint: Option<String>,
    uid: Option<String>,
    secret_held: bool,
) {
    if let (true, Some(fp), Some(uid)) = (secret_held, fingerprint, uid) {
        candidates.push(make_candidate(fp, uid));
    }
}

fn parse_gpg_colons(output: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut current_fp: Option<String> = None;
    let mut current_uid: Option<String> = None;
    let mut secret_held = false;
    // gpg prints an `fpr` after the primary and another after every subkey.
    // Only the first one names the identity; this flag consumes it.
    let mut want_primary_fpr = false;

    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first() {
            Some(&"sec") => {
                flush_key(
                    &mut candidates,
                    current_fp.take(),
                    current_uid.take(),
                    secret_held,
                );
                // Field 15 says where the secret key lives: `+` local, `#` not
                // available (offline-primary stub), anything else a token
                // serial number. A stub proves no more than a stranger's
                // public key does.
                secret_held = fields.get(14).is_some_and(|f| *f != "#");
                want_primary_fpr = true;
            }
            Some(&"fpr") if want_primary_fpr => {
                current_fp = fields.get(9).map(|s| s.to_string());
                want_primary_fpr = false;
            }
            Some(&"uid") if current_uid.is_none() => {
                current_uid = fields.get(9).map(|s| s.to_string());
            }
            _ => {}
        }
    }
    flush_key(&mut candidates, current_fp, current_uid, secret_held);
    candidates
}

// ponytail: gpg candidates sit under ssh.local, not pgp.local | ceiling: the
//   PgpLocal trust domain is never used | upgrade path: switch the domain in a
//   change that also migrates any enrolled SPIFFE IDs
fn make_candidate(fingerprint: String, display_name: String) -> Candidate {
    // The full fingerprint, never the 32-bit short key ID: the SPIFFE ID is the
    // authorization subject, and short IDs collide on demand (Evil32, 2016).
    Candidate::new(
        "gpg",
        SelfAssertedDomain::SshLocal,
        format!("gpg/{}", fingerprint.to_lowercase()),
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
                "--list-secret-keys",
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

    /// `gpg --batch --no-tty --list-secret-keys --with-colons --fingerprint`
    /// for a held 2048-bit key with a signing primary and an encryption subkey.
    const HELD_KEY: &str = "\
sec:u:2048:1:F89B03DD7C1C7CF3:1789436346:::u:::scESC:::+:::23::0:\n\
fpr:::::::::DCA433D5E52C0E3BC2FFAACAF89B03DD7C1C7CF3:\n\
grp:::::::::C9E63BA28950B26CF2F13D1A1289897C30999B96:\n\
uid:u::::1789436346::65805A6326CC48AD8A80F5C110E268E179B67F2D::Persona Fixture <fixture@example.invalid>::::::::::0:\n\
ssb:u:2048:1:95F75069F2C940FA:1789436346::::::e:::+:::23:\n\
fpr:::::::::6FF79DE07E215542036AC32495F75069F2C940FA:\n\
grp:::::::::DD661844847F70FA2E22834031A6C409CF9FB1DC:\n";

    /// The same listing for an offline-primary stub: the secret subkeys were
    /// exported, the secret key deleted, and the result reimported. Field 15 of
    /// `sec` is `#`.
    const STUB_KEY: &str = "\
sec:u:2048:1:4912B1B94BCC7CE7:1789436364:::u:::scESC:::#:::23::0:\n\
fpr:::::::::0A4CDBE63C2E43AD2F713ED74912B1B94BCC7CE7:\n\
grp:::::::::3F2BC44A4B128F52542DB5CB2D7F7C1673702F09:\n\
uid:u::::1789436364::F30D1032B443A9B75F65D20D35BCF78F968AD20B::Persona Stub <stub@example.invalid>::::::::::0:\n\
ssb:u:2048:1:FA6F485F7C9D2A23:1789436364::::::e:::+:::23:\n\
fpr:::::::::5C279EBDFC1ED9498785B16FFA6F485F7C9D2A23:\n\
grp:::::::::205EF534C20346592E8EA09DDE80AAC06C0D06D8:\n";

    const HELD_FP: &str = "dca433d5e52c0e3bc2ffaacaf89b03dd7c1c7cf3";
    const HELD_SUBKEY_FP: &str = "6ff79de07e215542036ac32495f75069f2c940fa";
    const STUB_FP: &str = "0a4cdbe63c2e43ad2f713ed74912b1b94bcc7ce7";

    #[test]
    fn parse_gpg_colons_extracts_candidate() {
        let candidates = parse_gpg_colons(HELD_KEY);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, "gpg");
        assert_eq!(
            candidates[0].display_name,
            "Persona Fixture <fixture@example.invalid>"
        );

        let uri = candidates[0].spiffe_id().uri();
        assert!(
            uri.contains(HELD_FP),
            "want full primary fingerprint: {uri}"
        );
        // The subkey's `fpr` follows the primary's; pairing it with the
        // primary's uid names a key the uid does not describe.
        assert!(!uri.contains(HELD_SUBKEY_FP), "subkey fingerprint: {uri}");
        // The 32-bit short key ID of the subkey — collidable, so never an
        // authorization subject.
        assert!(!uri.contains("f2c940fa"), "short key ID: {uri}");
    }

    #[test]
    fn parse_gpg_colons_rejects_offline_primary_stub() {
        assert!(parse_gpg_colons(STUB_KEY).is_empty());
    }

    #[test]
    fn parse_gpg_colons_accepts_smartcard_serial() {
        // Field 15 holds the token's serial number when the secret key lives on
        // a smartcard. That is the strongest possession case in the set, so an
        // acceptance rule narrowed to a literal `+` would be a regression.
        let listing = HELD_KEY.replace(
            "scESC:::+:::",
            "scESC:::D2760001240103040006123456789012:::",
        );

        let candidates = parse_gpg_colons(&listing);
        assert_eq!(candidates.len(), 1, "smartcard key dropped");
        assert!(candidates[0].spiffe_id().uri().contains(HELD_FP));
    }

    #[test]
    fn parse_gpg_colons_separates_keys_in_one_listing() {
        // The stub sits between two held keys, so a missed flush shows up as a
        // wrong pairing rather than a missing candidate. The third key is the
        // stub as gpg would print it if the secret key were present.
        let held_stub = STUB_KEY.replace("scESC:::#:::", "scESC:::+:::");
        let listing = format!("{HELD_KEY}{STUB_KEY}{held_stub}");

        let candidates = parse_gpg_colons(&listing);
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].spiffe_id().uri().contains(HELD_FP));
        assert_eq!(
            candidates[0].display_name,
            "Persona Fixture <fixture@example.invalid>"
        );
        assert!(candidates[1].spiffe_id().uri().contains(STUB_FP));
        assert_eq!(
            candidates[1].display_name,
            "Persona Stub <stub@example.invalid>"
        );
    }
}
