use crate::errors::domain_error::DomainError;
use serde::{Deserialize, Serialize};

/// Search engine covered by Safe Search enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafeSearchEngine {
    Google,
    Bing,
    YouTube,
    DuckDuckGo,
    Yandex,
    Brave,
    Ecosia,
}

impl SafeSearchEngine {
    /// Returns the canonical lowercase string representation used in the database and API.
    pub fn to_str(self) -> &'static str {
        match self {
            SafeSearchEngine::Google => "google",
            SafeSearchEngine::Bing => "bing",
            SafeSearchEngine::YouTube => "youtube",
            SafeSearchEngine::DuckDuckGo => "duckduckgo",
            SafeSearchEngine::Yandex => "yandex",
            SafeSearchEngine::Brave => "brave",
            SafeSearchEngine::Ecosia => "ecosia",
        }
    }

    pub fn all() -> &'static [SafeSearchEngine] {
        &[
            SafeSearchEngine::Google,
            SafeSearchEngine::Bing,
            SafeSearchEngine::YouTube,
            SafeSearchEngine::DuckDuckGo,
            SafeSearchEngine::Yandex,
            SafeSearchEngine::Brave,
            SafeSearchEngine::Ecosia,
        ]
    }
}

impl std::str::FromStr for SafeSearchEngine {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "google" => Ok(SafeSearchEngine::Google),
            "bing" => Ok(SafeSearchEngine::Bing),
            "youtube" => Ok(SafeSearchEngine::YouTube),
            "duckduckgo" => Ok(SafeSearchEngine::DuckDuckGo),
            "yandex" => Ok(SafeSearchEngine::Yandex),
            "brave" => Ok(SafeSearchEngine::Brave),
            "ecosia" => Ok(SafeSearchEngine::Ecosia),
            other => Err(DomainError::InvalidSafeSearchEngine(other.to_owned())),
        }
    }
}

/// Restriction level applied to YouTube queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YouTubeMode {
    /// Blocks most restricted content. Recommended for younger children.
    #[default]
    Strict,
    /// Allows some age-restricted content. Suitable for teenagers.
    Moderate,
}

impl YouTubeMode {
    /// Returns the canonical lowercase string representation used in the database and API.
    pub fn to_str(self) -> &'static str {
        match self {
            YouTubeMode::Strict => "strict",
            YouTubeMode::Moderate => "moderate",
        }
    }
}

impl std::str::FromStr for YouTubeMode {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(YouTubeMode::Strict),
            "moderate" => Ok(YouTubeMode::Moderate),
            other => Err(DomainError::InvalidInput(format!(
                "unknown YouTube mode: '{other}'"
            ))),
        }
    }
}

/// Per-group Safe Search configuration for a single search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeSearchConfig {
    /// Database row identifier. `None` before first persist.
    pub id: Option<i64>,
    pub group_id: i64,
    pub engine: SafeSearchEngine,
    pub enabled: bool,
    /// YouTube restriction level. Only relevant when `engine == YouTube`.
    pub youtube_mode: YouTubeMode,
    /// ISO-8601 creation timestamp. `None` before first persist.
    pub created_at: Option<String>,
    /// ISO-8601 last-update timestamp. `None` before first persist.
    pub updated_at: Option<String>,
}
