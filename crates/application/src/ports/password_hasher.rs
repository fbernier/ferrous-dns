use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

/// Port for hashing and verifying passwords with Argon2id.
///
/// Implementations must bound and offload CPU-intensive work, including each
/// recovery-code batch, without releasing admission when the caller is cancelled.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password. Returns the full Argon2id PHC string.
    async fn hash(&self, password: &str) -> Result<String, DomainError>;

    /// Verify a plaintext password against a stored hash.
    async fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;

    /// Hash a batch in one blocking submission, preserving input order.
    async fn hash_many(&self, passwords: &[String]) -> Result<Vec<String>, DomainError>;

    /// Return the first matching hash's index, or `None`, in one blocking submission.
    /// Invalid hashes encountered before a match return an error, as with `verify`.
    async fn verify_any(
        &self,
        password: &str,
        hashes: Vec<Arc<str>>,
    ) -> Result<Option<usize>, DomainError>;
}
