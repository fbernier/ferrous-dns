use crate::DomainError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

/// Source of a user account: TOML config file or SQLite database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserSource {
    /// Admin defined in `ferrous-dns.toml` — always recoverable via file edit.
    Toml,
    /// User stored in SQLite `users` table — managed via API.
    Database,
}

impl UserSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Database => "database",
        }
    }
}

/// Role recorded on a user and its sessions; informational only, nothing enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }
}

impl FromStr for UserRole {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "viewer" => Ok(Self::Viewer),
            other => Err(DomainError::InvalidInput(format!("Invalid role: {other}"))),
        }
    }
}

/// A user account that can authenticate with Ferrous DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub username: Arc<str>,
    pub display_name: Option<Arc<str>>,
    pub password_hash: Arc<str>,
    pub role: UserRole,
    pub source: UserSource,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl User {
    /// TOML admin cannot be deleted or disabled via API.
    pub fn is_protected(&self) -> bool {
        self.source == UserSource::Toml
    }

    pub fn validate_username(username: &str) -> Result<(), String> {
        if username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }
        if username.len() > 64 {
            return Err("Username cannot exceed 64 characters".to_string());
        }
        let valid = username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid {
            return Err(
                "Username can only contain alphanumeric characters, hyphens, underscores, and dots"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_display_name(display_name: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(name) = display_name {
            if name.len() > 100 {
                return Err("Display name cannot exceed 100 characters".to_string());
            }
        }
        Ok(())
    }

    pub fn validate_password(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters".to_string());
        }
        if password.len() > 256 {
            return Err("Password cannot exceed 256 characters".to_string());
        }
        Ok(())
    }
}
