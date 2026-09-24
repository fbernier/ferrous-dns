use ferrous_dns_domain::{Config, DomainError};

/// Port for reading and persisting the TOML config file.
pub trait ConfigFilePersistence: Send + Sync {
    /// Reads and parses the file; the caller validates the result.
    fn load_config_from_file(&self, path: &str) -> Result<Config, DomainError>;

    fn save_config_to_file(&self, config: &Config, path: &str) -> Result<(), DomainError>;
}
