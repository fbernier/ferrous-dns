use serde::{Deserialize, Serialize};

/// Authentication configuration, defined in `[auth]` section of `ferrous-dns.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Enable or disable authentication globally.
    /// When disabled, all endpoints are accessible without credentials.
    pub enabled: bool,

    /// Session cookie lifetime in hours when "Remember Me" is NOT checked.
    /// Default: 24 (1 day). Short-lived session for shared/public devices.
    pub session_ttl_hours: u32,

    /// Session cookie lifetime in days when "Remember Me" IS checked.
    /// Default: 30 days. Long-lived session for trusted home devices.
    pub remember_me_days: u32,

    /// Max failed login attempts before IP lockout.
    pub login_rate_limit_attempts: u32,

    /// Rate limit window in seconds. Default: 900 (15 minutes).
    pub login_rate_limit_window_secs: u64,

    /// Issuer label shown by authenticator apps next to the TOTP account
    /// (the "provider" name in the otpauth URI). Default: "Ferrous DNS".
    pub totp_issuer: String,

    /// Lifetime in seconds of a pending second-factor challenge — the window
    /// between the password step and TOTP/passkey verification, and the passkey
    /// registration ceremony. Default: 300 (5 minutes).
    pub mfa_challenge_ttl_secs: i64,

    /// Admin account configured in TOML — always recoverable via file edit.
    pub admin: AdminConfig,

    /// WebAuthn / passkey settings. Passkeys stay inert until `rp_id` and
    /// `rp_origin` are set (TOTP works regardless).
    pub webauthn: WebauthnConfig,
}

/// WebAuthn relying-party configuration, `[auth.webauthn]`.
///
/// WebAuthn requires a secure context: `rp_origin` must be HTTPS (or
/// `http://localhost`) and `rp_id` must be a registrable domain that the
/// origin belongs to. When either is empty, passkey endpoints report
/// "not configured" — a server reached by bare IP over plain HTTP cannot use
/// passkeys, so users there rely on TOTP.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct WebauthnConfig {
    /// Relying-party ID — the effective domain, e.g. `dns.example.com`.
    pub rp_id: String,

    /// Relying-party origin URL, e.g. `https://dns.example.com`.
    pub rp_origin: String,
}

impl WebauthnConfig {
    /// Whether passkeys are usable (both fields populated).
    pub fn is_configured(&self) -> bool {
        !self.rp_id.is_empty() && !self.rp_origin.is_empty()
    }
}

/// Admin account defined in the TOML config file.
///
/// This is the "escape hatch" — if a user loses access to database users,
/// they can always edit the TOML file and restart to regain admin access.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AdminConfig {
    /// Admin username. Default: "admin".
    pub username: String,

    /// Argon2id password hash. Set via the setup endpoint (first-run wizard).
    /// When empty/None, first-run setup is triggered; clear it to reset a lost password.
    pub password_hash: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_ttl_hours: 24,
            remember_me_days: 30,
            login_rate_limit_attempts: 5,
            login_rate_limit_window_secs: 900,
            totp_issuer: "Ferrous DNS".to_string(),
            mfa_challenge_ttl_secs: 300,
            admin: AdminConfig::default(),
            webauthn: WebauthnConfig::default(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            username: "admin".to_string(),
            password_hash: None,
        }
    }
}
