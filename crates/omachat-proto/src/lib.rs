//! Pure protocol codecs and compatibility metadata.

pub mod agent_loop;
pub mod geohash;
pub mod ipc;

/// Frozen upstream compatibility profile identifier.
pub const COMPATIBILITY_PROFILE: &str = "bitchat-swift-v1.7.1";

/// Canonical Swift revision for this compatibility profile.
pub const SWIFT_REVISION: &str = "9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa";

/// Android compatibility-peer revision for this profile.
pub const ANDROID_REVISION: &str = "93e9594bad3e537b4ec6fd096c0fde7533f22e74";

/// Omarchy integration-target revision for this profile.
pub const OMARCHY_REVISION: &str = "13f18b2cb7286fb54f87daf571a031aa6af3d8f0";

/// Render the exact one-line version payload required by the compatibility
/// profile.
#[must_use]
pub fn version_line(binary: &str) -> String {
    format!(
        "{binary} {} (profile={COMPATIBILITY_PROFILE}; swift={SWIFT_REVISION}; android={ANDROID_REVISION}; omarchy={OMARCHY_REVISION})",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::version_line;

    #[test]
    fn renders_frozen_version_contract() {
        assert_eq!(
            version_line("omachat"),
            "omachat 0.0.1 (profile=bitchat-swift-v1.7.1; swift=9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa; android=93e9594bad3e537b4ec6fd096c0fde7533f22e74; omarchy=13f18b2cb7286fb54f87daf571a031aa6af3d8f0)"
        );
    }
}
