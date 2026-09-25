use serde::{Deserialize, Serialize};

/// Configuration for TLS on the web dashboard and REST API.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WebTlsConfig {
    /// Whether HTTPS is enabled for the web server.
    pub enabled: bool,

    /// Path to the PEM-encoded TLS certificate file.
    pub tls_cert_path: String,

    /// Path to the PEM-encoded TLS private key file.
    pub tls_key_path: String,
}

impl Default for WebTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tls_cert_path: "/data/cert.pem".to_string(),
            tls_key_path: "/data/key.pem".to_string(),
        }
    }
}
