//! Consumer identity types for processes calling the hire socket.

/// Attested identity of a consumer process calling the hire socket.
///
/// Each variant represents a platform-specific attestation mechanism, ordered
/// roughly from strongest to weakest attestation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConsumerIdentity {
    /// SHA-256 hash of the calling binary (Linux fallback).
    BinarySha256([u8; 32]),
    /// macOS bundle ID and Team ID from code signing.
    MacosBundleId {
        /// Reverse-DNS bundle identifier, e.g. `"com.example.app"`.
        bundle_id: String,
        /// Apple Developer Team ID, e.g. `"ABCDE12345"`.
        team_id: String,
    },
    /// Flatpak application ID, e.g. `"org.gnome.Gedit"`.
    FlatpakApp(String),
    /// Snap package name, e.g. `"firefox"`.
    SnapName(String),
    /// Chrome or Firefox extension ID.
    ChromeExtension(String),
    // There is deliberately no Windows variant. One existed --
    // MsixPublisher(String), keyed "msix:publisher:{cn}" -- and was removed
    // before any Windows code was written, because it was a guess frozen into
    // a wire format. The publisher CN is shared by every application from one
    // publisher, so every app from that publisher would derive the SAME
    // pseudonym: a stable global correlator wearing a pseudonym's clothes,
    // which is the exact reason `attest_peer` refuses to key on uid. Compare
    // `MacosBundleId`, which carries the application AND its publisher. Most
    // Windows software is not MSIX-packaged besides.
    //
    // Whoever writes Windows consumer attestation picks the identity then,
    // knowing what the platform actually offers, and adds a variant with a
    // format they can defend. Removing this one cost nothing: it was never
    // constructed, so no pseudonym was ever derived from it and no scheme bump
    // is needed.
}

impl ConsumerIdentity {
    /// Returns a stable string key used as the HKDF `info` input.
    ///
    /// These format strings are a wire commitment, not an implementation detail
    /// of a helper. They are the `info` that `pseudonym::derive_pseudonym` mixes
    /// in, so reformatting one -- respacing it, renaming a field, reordering
    /// `bundle_id` and `team_id` -- changes every pseudonym derived for that
    /// variant, and every relying application then sees all of its users as new
    /// users. Such a change is a scheme change: bump the version in
    /// `pseudonym::SCHEME` with it.
    ///
    /// Format per variant:
    /// - `BinarySha256`  → `"binary_sha256:<hex>"`
    /// - `MacosBundleId` → `"macos:bundle_id:<id>:team_id:<team>"`
    /// - `FlatpakApp`    → `"flatpak:app:<id>"`
    /// - `SnapName`      → `"snap:name:<name>"`
    /// - `ChromeExtension` → `"chrome_extension:id:<id>"`
    pub fn selector_key(&self) -> String {
        match self {
            ConsumerIdentity::BinarySha256(hash) => {
                let hex = hash.iter().fold(String::with_capacity(64), |mut s, b| {
                    use std::fmt::Write as _;
                    write!(s, "{b:02x}").unwrap();
                    s
                });
                format!("binary_sha256:{hex}")
            }
            ConsumerIdentity::MacosBundleId { bundle_id, team_id } => {
                format!("macos:bundle_id:{bundle_id}:team_id:{team_id}")
            }
            ConsumerIdentity::FlatpakApp(id) => format!("flatpak:app:{id}"),
            ConsumerIdentity::SnapName(name) => format!("snap:name:{name}"),
            ConsumerIdentity::ChromeExtension(id) => format!("chrome_extension:id:{id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_sha256_selector_key() {
        let hash = [0xabu8; 32];
        let key = ConsumerIdentity::BinarySha256(hash).selector_key();
        // 32 bytes of 0xab → 64 lowercase hex chars
        assert_eq!(
            key,
            "binary_sha256:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn macos_bundle_id_selector_key() {
        let key = ConsumerIdentity::MacosBundleId {
            bundle_id: "com.example.app".into(),
            team_id: "ABCDE12345".into(),
        }
        .selector_key();
        assert_eq!(key, "macos:bundle_id:com.example.app:team_id:ABCDE12345");
    }

    #[test]
    fn flatpak_selector_key() {
        let key = ConsumerIdentity::FlatpakApp("org.gnome.Gedit".into()).selector_key();
        assert_eq!(key, "flatpak:app:org.gnome.Gedit");
    }

    #[test]
    fn snap_selector_key() {
        let key = ConsumerIdentity::SnapName("firefox".into()).selector_key();
        assert_eq!(key, "snap:name:firefox");
    }

    #[test]
    fn chrome_extension_selector_key() {
        let key = ConsumerIdentity::ChromeExtension("aabbccddeeffgghh".into()).selector_key();
        assert_eq!(key, "chrome_extension:id:aabbccddeeffgghh");
    }
}
