use std::fmt::Write;
use std::sync::Arc;

use ring::rand::SecureRandom;

use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, UserRole};

/// UTC storage format of every auth timestamp; lexicographic order matches time order.
pub(crate) const TIMESTAMP_FMT: &str = "%Y-%m-%d %H:%M:%S";

/// 256-bit CSPRNG value, hex-encoded; used for session ids, ceremony tokens and API keys.
pub(crate) fn random_hex_256() -> Result<String, DomainError> {
    let mut buf = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;
    Ok(hex_encode(&buf))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Timestamp `ttl` from now, in [`TIMESTAMP_FMT`].
pub(crate) fn expires_in(ttl: chrono::Duration) -> String {
    (chrono::Utc::now() + ttl).format(TIMESTAMP_FMT).to_string()
}

/// Whether a [`TIMESTAMP_FMT`] timestamp has passed; unparseable values count as expired.
pub(crate) fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, TIMESTAMP_FMT)
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}

/// Builds a fresh `AuthSession` for an authenticated user.
///
/// Shared by the password-only login path and the second-factor verify path so
/// session shape (id, TTL, timestamps) stays identical.
pub(crate) fn build_session(
    username: Arc<str>,
    role: UserRole,
    remember_me: bool,
    ip_address: &str,
    user_agent: &str,
    config: &AuthConfig,
) -> Result<AuthSession, DomainError> {
    let session_id = random_hex_256()?;
    let created_at = chrono::Utc::now().format(TIMESTAMP_FMT).to_string();
    let expires_at = expires_in(session_ttl(remember_me, config));

    Ok(AuthSession {
        id: Arc::from(session_id.as_str()),
        username,
        role,
        ip_address: Arc::from(ip_address),
        user_agent: Arc::from(user_agent),
        remember_me,
        last_seen_at: created_at.clone(),
        created_at,
        expires_at,
    })
}

/// Cookie `max_age` in seconds for the session.
pub(crate) fn session_max_age(remember_me: bool, config: &AuthConfig) -> i64 {
    if remember_me {
        i64::from(config.remember_me_days) * 86400
    } else {
        i64::from(config.session_ttl_hours) * 3600
    }
}

fn session_ttl(remember_me: bool, config: &AuthConfig) -> chrono::Duration {
    if remember_me {
        chrono::Duration::days(i64::from(config.remember_me_days))
    } else {
        chrono::Duration::hours(i64::from(config.session_ttl_hours))
    }
}
