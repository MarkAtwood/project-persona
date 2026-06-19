//! Consumer identity types for processes calling the persona socket.

/// Attested identity of a consumer process calling the persona socket.
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
    /// MSIX Package Family Name publisher CN (Windows).
    MsixPublisher(String),
    /// Chrome or Firefox extension ID.
    ChromeExtension(String),
    /// Unattested: only UID and PID are known (fallback on unconfined Linux).
    Unattested {
        /// Unix user ID of the calling process.
        uid: u32,
        /// Process ID of the calling process.
        pid: u32,
    },
}

impl ConsumerIdentity {
    /// Returns a stable string key suitable for use as HKDF `info`.
    ///
    /// Format per variant:
    /// - `BinarySha256`  → `"binary_sha256:<hex>"`
    /// - `MacosBundleId` → `"macos:bundle_id:<id>:team_id:<team>"`
    /// - `FlatpakApp`    → `"flatpak:app:<id>"`
    /// - `SnapName`      → `"snap:name:<name>"`
    /// - `MsixPublisher` → `"msix:publisher:<cn>"`
    /// - `ChromeExtension` → `"chrome_extension:id:<id>"`
    /// - `Unattested`    → `"unattested:uid:<uid>:pid:<pid>"`
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
            ConsumerIdentity::MsixPublisher(cn) => format!("msix:publisher:{cn}"),
            ConsumerIdentity::ChromeExtension(id) => format!("chrome_extension:id:{id}"),
            ConsumerIdentity::Unattested { uid, pid } => {
                format!("unattested:uid:{uid}:pid:{pid}")
            }
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
    fn msix_selector_key() {
        let key = ConsumerIdentity::MsixPublisher("CN=Example".into()).selector_key();
        assert_eq!(key, "msix:publisher:CN=Example");
    }

    #[test]
    fn chrome_extension_selector_key() {
        let key =
            ConsumerIdentity::ChromeExtension("aabbccddeeffgghh".into()).selector_key();
        assert_eq!(key, "chrome_extension:id:aabbccddeeffgghh");
    }

    #[test]
    fn unattested_selector_key() {
        let key = ConsumerIdentity::Unattested { uid: 1000, pid: 42 }.selector_key();
        assert_eq!(key, "unattested:uid:1000:pid:42");
    }
}
