use serde::{Deserialize, Serialize};

/// DNS Cookies anti-spoofing configuration (RFC 7873).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsCookiesConfig {
    /// Master switch — enabled by default for anti-spoofing protection.
    pub enabled: bool,

    /// Hex-encoded 32-byte HMAC secret (64 hex chars).
    /// When empty, the server generates an ephemeral secret on startup that
    /// will not survive a restart — suitable for testing only.
    pub server_secret: String,

    /// How often the server rotates to a new secret (seconds).
    /// The previous secret remains accepted during one full rotation window
    /// to allow in-flight clients to re-negotiate without errors.
    pub secret_rotation_secs: u64,

    /// When `true`, queries that carry an invalid or absent server cookie are
    /// rejected with REFUSED + EDE 25 (Bad or Missing EDNS Cookie).
    /// When `false` (default), the server responds normally but always
    /// echoes a fresh server cookie so clients can learn and cache it.
    pub require_valid_cookie: bool,
}

impl Default for DnsCookiesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_secret: String::new(),
            secret_rotation_secs: 3600,
            require_valid_cookie: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: DnsCookiesConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert!(config.server_secret.is_empty());
        assert_eq!(config.secret_rotation_secs, 3600);
        assert!(!config.require_valid_cookie);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            secret_rotation_secs = 7200
        "#;
        let config: DnsCookiesConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert!(config.server_secret.is_empty());
        assert_eq!(config.secret_rotation_secs, 7200);
        assert!(!config.require_valid_cookie);
    }
}
