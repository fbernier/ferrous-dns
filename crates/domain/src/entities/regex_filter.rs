use super::managed_domain::DomainAction;
use crate::value_objects::validators::exceeds_chars;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexFilter {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub pattern: Arc<str>,
    pub action: DomainAction,
    pub group_id: i64,
    pub comment: Option<Arc<str>>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl RegexFilter {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Regex filter name cannot be empty".to_string());
        }
        if exceeds_chars(name, 200) {
            return Err("Regex filter name cannot exceed 200 characters".to_string());
        }
        Ok(())
    }

    pub fn validate_pattern(pattern: &str) -> Result<(), String> {
        if pattern.is_empty() {
            return Err("Pattern cannot be empty".to_string());
        }
        if exceeds_chars(pattern, 1000) {
            return Err("Pattern cannot exceed 1000 characters".to_string());
        }
        Ok(())
    }
}
