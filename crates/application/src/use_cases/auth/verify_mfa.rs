use std::net::IpAddr;
use std::sync::Arc;

use tracing::{info, instrument, warn};

use super::login_rate_limiter::LoginRateLimiter;
use super::session_factory::build_session;
use crate::ports::{MfaRepository, PasswordHasher, SessionRepository, TotpService, UserProvider};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError};

/// Completes a second-factor login: consumes a pending challenge plus a TOTP
/// code (or a recovery code) and mints the real session.
pub struct VerifyMfaUseCase {
    mfa_repo: Arc<dyn MfaRepository>,
    totp: Arc<dyn TotpService>,
    password_hasher: Arc<dyn PasswordHasher>,
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    auth_config: Arc<AuthConfig>,
    rate_limiter: Arc<LoginRateLimiter>,
}

impl VerifyMfaUseCase {
    pub fn new(
        mfa_repo: Arc<dyn MfaRepository>,
        totp: Arc<dyn TotpService>,
        password_hasher: Arc<dyn PasswordHasher>,
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        let rate_limiter = Arc::new(LoginRateLimiter::from_config(&auth_config));
        Self {
            mfa_repo,
            totp,
            password_hasher,
            user_provider,
            session_repo,
            auth_config,
            rate_limiter,
        }
    }

    /// Shares one lockout with the other credential checks, so failures on
    /// any of them count toward the same limit.
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<LoginRateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// Returns the created `AuthSession`. The challenge is consumed only on a
    /// correct code; a wrong code leaves it valid for retry until it expires.
    /// Wrong codes count toward the `peer_ip` lockout, which bounds those retries.
    #[instrument(skip(self, code))]
    pub async fn execute(
        &self,
        challenge_token: &str,
        code: &str,
        peer_ip: IpAddr,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AuthSession, DomainError> {
        self.rate_limiter.check(peer_ip)?;

        let challenge = self
            .mfa_repo
            .get_challenge(challenge_token)
            .await?
            .ok_or(DomainError::MfaChallengeExpired)?;

        if is_expired(&challenge.expires_at) {
            self.mfa_repo.delete_challenge(challenge_token).await?;
            return Err(DomainError::MfaChallengeExpired);
        }

        let username = challenge.username.as_ref();
        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        let mfa = self
            .mfa_repo
            .get(username)
            .await?
            .ok_or(DomainError::MfaNotConfigured)?;

        // Try TOTP first, then fall back to a recovery code.
        let mut verified = mfa.totp_enabled && self.totp.verify(&mfa.totp_secret, code)?;

        if !verified {
            verified = self.consume_recovery_code(username, code).await?;
        }

        if !verified {
            warn!(username = username, "Failed second-factor attempt");
            self.rate_limiter.record_failure(peer_ip);
            return Err(DomainError::InvalidMfaCode);
        }

        self.mfa_repo.delete_challenge(challenge_token).await?;

        let session = build_session(
            user.username.clone(),
            user.role.clone(),
            challenge.remember_me,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;
        self.session_repo.create(&session).await?;
        self.rate_limiter.reset(peer_ip);

        info!(
            username = username,
            "Second factor verified, user logged in"
        );
        Ok(session)
    }

    /// Matches `code` against the user's unused recovery codes; marks it used
    /// on a hit.
    async fn consume_recovery_code(&self, username: &str, code: &str) -> Result<bool, DomainError> {
        let normalized = code.trim().to_lowercase();
        let codes = self.mfa_repo.list_unused_recovery_codes(username).await?;
        let (ids, hashes): (Vec<_>, Vec<_>) =
            codes.into_iter().map(|rc| (rc.id, rc.code_hash)).unzip();
        if let Some(index) = self.password_hasher.verify_any(&normalized, hashes).await? {
            self.mfa_repo.mark_recovery_code_used(ids[index]).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

/// Checks if a timestamp has passed; fail-closed on parse error.
fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}
