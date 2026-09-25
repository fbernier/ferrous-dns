use std::time::{SystemTime, UNIX_EPOCH};

use qrcode::{render::svg, QrCode};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

use ferrous_dns_application::ports::TotpService;
use ferrous_dns_domain::DomainError;

/// RFC 6238 SHA1/6-digit/30s (the profile every authenticator app supports); QR codes render as SVG.
pub struct TotpRsService {
    issuer: String,
}

/// ±1 step (≈30s) of clock drift.
const SKEW: u8 = 1;
const STEP_SECS: u64 = 30;

impl TotpRsService {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
        }
    }

    fn build(&self, secret_base32: &str, account: &str) -> Result<TOTP, DomainError> {
        let bytes = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .map_err(|e| DomainError::ConfigError(format!("invalid TOTP secret: {e:?}")))?;
        TOTP::new(
            Algorithm::SHA1,
            6,
            SKEW,
            STEP_SECS,
            bytes,
            Some(self.issuer.clone()),
            account.to_string(),
        )
        .map_err(|e| DomainError::ConfigError(format!("TOTP init failed: {e}")))
    }
}

impl TotpService for TotpRsService {
    fn generate_secret(&self) -> String {
        match Secret::generate_secret().to_encoded() {
            Secret::Encoded(s) => s,
            Secret::Raw(bytes) => data_encoding::BASE32_NOPAD.encode(&bytes),
        }
    }

    fn provisioning_uri(&self, secret: &str, account: &str) -> Result<String, DomainError> {
        Ok(self.build(secret, account)?.get_url())
    }

    fn qr_svg(&self, otpauth_uri: &str) -> Result<String, DomainError> {
        let code = QrCode::new(otpauth_uri.as_bytes())
            .map_err(|e| DomainError::ConfigError(format!("QR encode failed: {e}")))?;
        Ok(code
            .render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .build())
    }

    fn verify(&self, secret: &str, code: &str) -> Result<Option<u64>, DomainError> {
        let totp = self.build(secret, "account")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DomainError::ConfigError(format!("TOTP check failed: {e}")))?
            .as_secs();
        Ok(matching_step(&totp, code.trim(), now))
    }
}

/// Newest step first, so a code valid for two steps in the window is charged to the later one.
fn matching_step(totp: &TOTP, code: &str, now: u64) -> Option<u64> {
    let current = now / STEP_SECS;
    let skew = u64::from(SKEW);
    (current.saturating_sub(skew)..=current + skew)
        .rev()
        .find(|step| {
            bool::from(
                totp.generate(step * STEP_SECS)
                    .as_bytes()
                    .ct_eq(code.as_bytes()),
            )
        })
}
