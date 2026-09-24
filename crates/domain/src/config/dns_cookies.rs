use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// DNS Cookies anti-spoofing configuration (RFC 7873).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsCookiesConfig {
    /// Master switch — enabled by default for anti-spoofing protection.
    pub enabled: bool,

    /// 32-byte HMAC secret, written as 64 hex digits in the config file.
    /// `None` (an empty string) makes the server generate an ephemeral secret
    /// on startup that will not survive a restart — suitable for testing only.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub server_secret: Option<[u8; 32]>,

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
            server_secret: None,
            secret_rotation_secs: 3600,
            require_valid_cookie: false,
        }
    }
}

/// Parses a configured secret: empty (after trimming) is `None`, otherwise it
/// must be exactly 64 hex digits.
fn parse_server_secret(text: &str) -> Result<Option<[u8; 32]>, String> {
    let hex = text.trim().as_bytes();
    if hex.is_empty() {
        return Ok(None);
    }
    if hex.len() != 64 {
        return Err(format!(
            "dns_cookies.server_secret must be exactly 64 hex characters (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut secret = [0u8; 32];
    for (byte, pair) in secret.iter_mut().zip(hex.chunks_exact(2)) {
        let (Some(high), Some(low)) = (hex_digit(pair[0]), hex_digit(pair[1])) else {
            return Err("dns_cookies.server_secret contains invalid hex characters".to_string());
        };
        *byte = high << 4 | low;
    }
    Ok(Some(secret))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn serialize_secret<S: Serializer>(
    secret: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in secret.iter().flatten() {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    serializer.serialize_str(&hex)
}

fn deserialize_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_server_secret(&text).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: DnsCookiesConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert!(config.server_secret.is_none());
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
        assert!(config.server_secret.is_none());
        assert_eq!(config.secret_rotation_secs, 7200);
        assert!(!config.require_valid_cookie);
    }

    #[test]
    fn an_empty_secret_means_ephemeral() {
        let config: DnsCookiesConfig = toml::from_str("server_secret = \"\"").unwrap();
        assert!(config.server_secret.is_none());
    }

    #[test]
    fn a_configured_secret_is_decoded_and_serialized_back_as_hex() {
        let hex = "0fA1".repeat(16);
        let config: DnsCookiesConfig =
            toml::from_str(&format!("server_secret = \"  {hex}  \"")).unwrap();
        let secret = config.server_secret.unwrap();
        assert_eq!(secret[..2], [0x0f, 0xa1]);
        assert_eq!(secret[30..], [0x0f, 0xa1]);

        let serialized = toml::Value::try_from(&config).unwrap();
        assert_eq!(
            serialized["server_secret"].as_str(),
            Some(hex.to_ascii_lowercase().as_str())
        );
    }

    #[test]
    fn an_ephemeral_secret_serializes_as_an_empty_string() {
        let serialized = toml::Value::try_from(DnsCookiesConfig::default()).unwrap();
        assert_eq!(serialized["server_secret"].as_str(), Some(""));
    }

    #[test]
    fn malformed_secrets_are_parse_errors() {
        for bad in [
            "abc".to_string(),
            "zz".repeat(32),
            "+f".repeat(32),
            format!("{}é", "a".repeat(62)),
            "0".repeat(66),
        ] {
            assert!(
                toml::from_str::<DnsCookiesConfig>(&format!("server_secret = \"{bad}\"")).is_err(),
                "{bad:?} was accepted"
            );
        }
    }
}
