use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Pi-hole v6 POST /api/auth request body.
///
/// `password` is the account password or an API token (Pi-hole's "app
/// password"); `totp` is the second factor, required only when one is enrolled.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub password: String,
    #[serde(default)]
    pub totp: Option<TotpCode>,
}

/// Pi-hole clients send the TOTP code as a JSON number; a string is accepted too.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum TotpCode {
    Number(u32),
    Text(String),
}

impl TotpCode {
    /// The code as typed: a number loses its leading zeros in JSON, so it is
    /// padded back to six digits.
    pub fn to_code(&self) -> String {
        match self {
            Self::Number(code) => format!("{code:06}"),
            Self::Text(code) => code.clone(),
        }
    }
}

/// Pi-hole v6 session object returned by GET/POST /api/auth.
///
/// `sid` is `null` when there is no session; `validity` is the seconds left
/// on it, or `-1` when there is none. `csrf` is always `null`: it only guards
/// Pi-hole's cookie auth, which this API does not accept.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionInfo {
    pub valid: bool,
    pub totp: bool,
    pub sid: Option<String>,
    pub csrf: Option<String>,
    pub validity: i64,
    pub message: String,
}

/// Pi-hole v6 auth response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub session: SessionInfo,
}
