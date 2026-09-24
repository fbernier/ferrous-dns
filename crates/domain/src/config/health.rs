use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    pub interval: u64,
    pub timeout: u64,
    pub failure_threshold: u8,
    pub success_threshold: u8,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: 30,
            timeout: 2000,
            failure_threshold: 3,
            success_threshold: 2,
        }
    }
}
