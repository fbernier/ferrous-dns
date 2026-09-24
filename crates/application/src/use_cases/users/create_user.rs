use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{CreateUserInput, PasswordHasher, UserProvider, UserRepository};
use ferrous_dns_domain::{DomainError, User};

/// Creates a new user account in the database.
pub struct CreateUserUseCase {
    user_repo: Arc<dyn UserRepository>,
    user_provider: Arc<dyn UserProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
    admin_username: String,
}

impl CreateUserUseCase {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        user_provider: Arc<dyn UserProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
        admin_username: String,
    ) -> Self {
        Self {
            user_repo,
            user_provider,
            password_hasher,
            admin_username,
        }
    }

    #[instrument(skip(self, input))]
    pub async fn execute(&self, input: CreateUserInput) -> Result<User, DomainError> {
        User::validate_username(&input.username).map_err(DomainError::InvalidUsername)?;
        User::validate_password(&input.password).map_err(DomainError::InvalidPassword)?;
        User::validate_display_name(&input.display_name).map_err(DomainError::InvalidInput)?;

        // The provider hides the TOML admin until it has a password, but its name is still taken.
        if *input.username == *self.admin_username
            || self
                .user_provider
                .get_by_username(&input.username)
                .await?
                .is_some()
        {
            return Err(DomainError::DuplicateUsername(input.username.to_string()));
        }

        let password_hash = self.password_hasher.hash(&input.password).await?;

        let user = self
            .user_repo
            .create(
                &input.username,
                input.display_name.as_deref(),
                &password_hash,
                input.role,
            )
            .await?;

        info!(username = %input.username, role = input.role.as_str(), "User created");
        Ok(user)
    }
}
