//! GPG attestor — enumerates keys whose secret half the operator holds, via
//! `gpg --list-secret-keys --with-colons`, and proves one by having gpg-agent
//! sign the daemon's challenge.
//!
//! The secret key never leaves the agent, and on a smartcard it never leaves
//! the card. That is the kernel.org signing workflow, and it is why this is the
//! shortest path to a real hardware proof on a box that has no FIDO2 support
//! compiled in: a Yubikey or Nitrokey holding a PGP key is reached through the
//! gpg already installed, with no new dependency and no new feature flag.
//!
//! Proof is possession and nothing else — `Iaa1`, no presence. pinentry may
//! well have appeared, and that is deliberately not read as a human being
//! present: gpg-agent signs silently for a key already cached, so the same key
//! proves with or without anybody there. What a prompt proves is not knowable
//! from this side of it, and guessing would put a presence claim on a JWT that
//! nothing observed.
//!
// ponytail: the verifier is the locally installed gpg | ceiling: hire believes
//   what `/usr/bin/gpg` reports about a signature | upgrade path: none worth
//   taking — see ChallengeSignature::verify_openpgp, where in-process packet
//   parsing is shown to shrink the trust set by nothing, because the public key
//   it would verify against comes from the same binary's keyring.

use async_trait::async_trait;
use std::path::Path;
use tokio::io::AsyncWriteExt as _;

use crate::claim::ChallengeSignature;
use crate::{
    AttainableAssurance, Attestor, AttestorError, Candidate, Evidence, ProofCost,
    SelfAssertedDomain,
};

/// Attestor that lists GPG keys from the user's keyring.
#[derive(Debug)]
pub struct GpgAttestor;

impl GpgAttestor {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if a gpg binary exists and its home directory is present.
    pub fn is_available() -> bool {
        which_gpg().is_some() && gnupg_home().exists()
    }
}

impl Default for GpgAttestor {
    fn default() -> Self {
        Self::new()
    }
}

/// The gpg to run, from a fixed list rather than from `PATH`.
///
/// `PATH` is inherited from whatever started the daemon, so resolving through
/// it would let anything earlier on it answer for the operator's keyring — and
/// this binary is the verifier as well as the signer.
pub(crate) fn which_gpg() -> Option<std::path::PathBuf> {
    for p in &["/usr/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg2"] {
        let p = std::path::Path::new(p);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Where gpg will look for the keyring, by gpg's own rule.
///
/// `GNUPGHOME` first, because that is what the gpg this module runs will
/// honour. Checking `~/.gnupg` while gpg reads somewhere else would report a
/// source unavailable that works, and available that does not.
fn gnupg_home() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("GNUPGHOME") {
        return std::path::PathBuf::from(home);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    std::path::PathBuf::from(home).join(".gnupg")
}

/// Run gpg with the batch flags every call needs, feeding `stdin` and
/// collecting both output streams.
///
/// `--batch` and `--no-tty` keep gpg from ever trying to read a passphrase off
/// the daemon's terminal, which it does not have. They do not stop gpg-agent
/// raising its own pinentry, and nothing here should: that dialog belongs to
/// the operator, and how long they take to answer it is their business, so
/// there is no timeout on this call. It is reached only from an explicitly
/// requested proof — `FetchJWTSVID` never gets here, because gpg candidates
/// declare [`ProofCost::Interactive`].
///
/// The write runs in its own task rather than ahead of the read. gpg's output
/// is a few hundred bytes today and a pipe buffer holds far more, so the
/// ordering cannot deadlock in practice; doing it this way means it cannot
/// deadlock in principle either, for the cost of one spawn.
pub(crate) async fn run(
    gpg: &Path,
    args: &[&str],
    stdin: &[u8],
) -> Result<std::process::Output, AttestorError> {
    let mut child = tokio::process::Command::new(gpg)
        .args(["--batch", "--no-tty"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AttestorError::Unavailable(format!("gpg exec failed: {e}")))?;

    let mut pipe = child
        .stdin
        .take()
        .ok_or_else(|| AttestorError::Unavailable("gpg stdin was not piped".into()))?;
    let payload = stdin.to_vec();
    let writer = tokio::spawn(async move {
        pipe.write_all(&payload).await?;
        pipe.shutdown().await
    });

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| AttestorError::Unavailable(format!("gpg did not run: {e}")))?;
    // A gpg that exited before reading its input breaks the pipe, and that is
    // gpg's answer rather than an error of ours -- the exit status and the
    // status lines say what went wrong, and they are what the caller reads.
    let _ = writer.await;
    Ok(output)
}

/// Returns true if the record's validity field marks it revoked.
///
/// Field 2 of a `sec` or `uid` record. A revocation certificate is the owner's
/// explicit statement that the key must not be used, so it must not become an
/// authorization subject even when its secret half is right here. Expiry is
/// deliberately not treated the same way: the operator still holds the secret
/// half of an expired key, and an expired identity beats no identity at all.
fn is_revoked(field: Option<&&str>) -> bool {
    matches!(field, Some(&"r"))
}

/// Pushes a candidate for a primary key the operator holds and has not revoked.
fn flush_key(
    candidates: &mut Vec<Candidate>,
    fingerprint: Option<String>,
    uid: Option<String>,
    enrollable: bool,
) {
    if let (true, Some(fp), Some(uid)) = (enrollable, fingerprint, uid) {
        candidates.push(make_candidate(fp, uid));
    }
}

fn parse_gpg_colons(output: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut current_fp: Option<String> = None;
    let mut current_uid: Option<String> = None;
    let mut enrollable = false;
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
                    enrollable,
                );
                // Field 15 says where the secret key lives: `+` local, `#` not
                // available (offline-primary stub), anything else a token
                // serial number. A stub proves no more than a stranger's
                // public key does. Possession is necessary but not
                // sufficient: a revoked key is one the owner has withdrawn.
                let secret_held = fields.get(14).is_some_and(|f| *f != "#");
                enrollable = secret_held && !is_revoked(fields.get(1));
                want_primary_fpr = true;
            }
            Some(&"fpr") if want_primary_fpr => {
                current_fp = fields.get(9).map(|s| s.to_string());
                want_primary_fpr = false;
            }
            // gpg lists revoked uids after live ones, so first-uid-wins picks
            // a live address on its own; this guard holds when that ordering
            // does not. The operator reads this string to choose an identity.
            Some(&"uid") if current_uid.is_none() && !is_revoked(fields.get(1)) => {
                current_uid = fields.get(9).map(|s| s.to_string());
            }
            _ => {}
        }
    }
    flush_key(&mut candidates, current_fp, current_uid, enrollable);
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
    .with_attainable(AttainableAssurance::Iaa1)
    // pinentry prompts for an uncached key and stays silent for a cached one,
    // and nothing here can tell which this is, so it declares the costlier one.
    .with_proof_cost(ProofCost::Interactive)
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

    async fn prove(
        &self,
        candidate: &Candidate,
        challenge: &[u8],
    ) -> Result<Vec<Evidence>, AttestorError> {
        let gpg =
            which_gpg().ok_or_else(|| AttestorError::Unavailable("gpg binary not found".into()))?;

        // Re-enumerate rather than trust the path, exactly as ssh.rs re-lists.
        // It costs one `gpg --list-secret-keys` and asks the truthful question:
        // is this key held and enrollable *now*? Reading the fingerprint back
        // out of the enumerated candidate also means the enrolment rule -- no
        // stub, no revoked key -- gates signing too, with one spelling of it.
        let fingerprint = self
            .enumerate()
            .await?
            .iter()
            .find(|c| c.path == candidate.path)
            .and_then(|c| c.path.strip_prefix("gpg/"))
            .map(str::to_owned)
            .ok_or_else(|| {
                AttestorError::ChallengeFailed(format!(
                    "gpg does not hold an enrollable key for {}",
                    candidate.path
                ))
            })?;

        // Inline rather than detached, so the verifier can compare the data the
        // signature actually covers against the challenge instead of being told
        // what was signed. `--local-user <fingerprint>` without a trailing `!`:
        // the `!` would force the primary key itself, and the hardware case
        // this exists for is a certify-only primary that delegates signing to a
        // subkey on the card. The primary is named in gpg's VALIDSIG output and
        // that is where the candidate is matched.
        let signed = run(
            &gpg,
            &["--local-user", &fingerprint, "--sign", "--output", "-"],
            challenge,
        )
        .await?;

        if !signed.status.success() {
            // The operator's own reason -- key expired, pinentry cancelled, card
            // not inserted -- is worth having in the log and is not worth
            // putting in the error a consumer sees.
            tracing::debug!(
                event = "gpg_sign_failed",
                key = %candidate.path,
                stderr = %String::from_utf8_lossy(&signed.stderr).trim(),
                "gpg-agent did not sign the challenge"
            );
            return Err(AttestorError::ChallengeFailed(format!(
                "gpg-agent did not sign for {}",
                candidate.path
            )));
        }

        Ok(vec![Evidence::Possession(
            ChallengeSignature::verify_openpgp(candidate, challenge, &signed.stdout).await?,
        )])
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
uid:u::::1789436346::65805A6326CC48AD8A80F5C110E268E179B67F2D::HIRE Fixture <fixture@example.invalid>::::::::::0:\n\
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
uid:u::::1789436364::F30D1032B443A9B75F65D20D35BCF78F968AD20B::HIRE Stub <stub@example.invalid>::::::::::0:\n\
ssb:u:2048:1:FA6F485F7C9D2A23:1789436364::::::e:::+:::23:\n\
fpr:::::::::5C279EBDFC1ED9498785B16FFA6F485F7C9D2A23:\n\
grp:::::::::205EF534C20346592E8EA09DDE80AAC06C0D06D8:\n";

    /// A key the owner revoked, by importing the revocation certificate gpg
    /// wrote at generation. Revoking the key marks every uid `r` as well.
    const REVOKED_KEY: &str = "\
sec:r:2048:1:ACDA14AE1B81B6E6:1789437608:::-:::sc:::+:::23::0:\n\
fpr:::::::::C48C869670DD7FDADADE70C5ACDA14AE1B81B6E6:\n\
uid:r::::1789437609::7708B404760C34E3AEFB2FC069C86D79AA921DD5::HIRE Current <current@example.invalid>::::::::::0:\n\
uid:r::::::776A75185DC89FE288065594A412DF1ACA1D95D5::HIRE Retired <retired@example.invalid>::::::::::0:\n";

    /// The same key before the revocation, with one of its two uids revoked via
    /// `gpg --quick-revoke-uid`. Real gpg prints the live uid first here; the
    /// two uid lines are swapped below so the assertion tests the guard rather
    /// than gpg's ordering.
    const REVOKED_UID_KEY: &str = "\
sec:u:2048:1:ACDA14AE1B81B6E6:1789437608:::u:::scSC:::+:::23::0:\n\
fpr:::::::::C48C869670DD7FDADADE70C5ACDA14AE1B81B6E6:\n\
uid:r::::::776A75185DC89FE288065594A412DF1ACA1D95D5::HIRE Retired <retired@example.invalid>::::::::::0:\n\
uid:u::::1789437609::7708B404760C34E3AEFB2FC069C86D79AA921DD5::HIRE Current <current@example.invalid>::::::::::0:\n";

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
            "HIRE Fixture <fixture@example.invalid>"
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
    fn parse_gpg_colons_rejects_revoked_primary() {
        assert!(parse_gpg_colons(REVOKED_KEY).is_empty());

        // The same listing with one uid left live. gpg does not print this --
        // revoking a primary marks every uid `r`, so the real fixture above is
        // refused for having no live uid and never reaches the `sec` check.
        // Field 2 of `sec` is what refuses this one, which is the intent
        // stated directly rather than inherited from how gpg marks uids.
        let live_uid = REVOKED_KEY.replace("uid:r::::1789437609:", "uid:u::::1789437609:");
        assert_ne!(live_uid, REVOKED_KEY, "fixture edit did not apply");
        assert!(
            parse_gpg_colons(&live_uid).is_empty(),
            "revoked key enrolled"
        );
    }

    #[test]
    fn parse_gpg_colons_accepts_expired_primary() {
        // An expired key is one the operator still holds; only the validity
        // window lapsed. Dropping it would delete a capability rather than
        // label it, so field 2 of `e` stays enrollable.
        let listing = HELD_KEY.replace("sec:u:", "sec:e:");

        let candidates = parse_gpg_colons(&listing);
        assert_eq!(candidates.len(), 1, "expired key dropped");
        assert!(candidates[0].spiffe_id().uri().contains(HELD_FP));
    }

    #[test]
    fn parse_gpg_colons_skips_revoked_uid_for_display_name() {
        let candidates = parse_gpg_colons(REVOKED_UID_KEY);
        assert_eq!(candidates.len(), 1);
        // A revoked address names someone the owner stopped answering as.
        assert_eq!(
            candidates[0].display_name,
            "HIRE Current <current@example.invalid>"
        );
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
            "HIRE Fixture <fixture@example.invalid>"
        );
        assert!(candidates[1].spiffe_id().uri().contains(STUB_FP));
        assert_eq!(
            candidates[1].display_name,
            "HIRE Stub <stub@example.invalid>"
        );
    }
}
