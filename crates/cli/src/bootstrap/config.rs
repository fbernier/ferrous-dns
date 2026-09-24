use ferrous_dns_application::ports::ConfigFilePersistence;
use ferrous_dns_application::use_cases::ConfigOverrides;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence;
use std::path::Path;
use tracing::info;

use crate::args::Cli;

const CANDIDATE_PATHS: [&str; 2] = ["ferrous-dns.toml", "/etc/ferrous-dns/config.toml"];

/// The config file the server reads and rewrites: `--config`, else the first
/// candidate path that exists.
pub fn resolve_config_path(explicit: Option<&str>) -> Option<String> {
    explicit
        .or_else(|| {
            CANDIDATE_PATHS
                .into_iter()
                .find(|path| Path::new(path).exists())
        })
        .map(str::to_string)
}

/// The command-line settings that win over the config file, at startup and
/// on every reload.
pub fn config_overrides(cli: &Cli) -> ConfigOverrides {
    ConfigOverrides {
        dns_port: cli.dns_port,
        web_port: cli.web_port,
        bind_address: cli.bind,
        database_path: cli.database.clone(),
        log_level: cli.log_level.clone(),
    }
}

/// Loads `config_path` (the built-in defaults when there is none), applies
/// the command-line overrides and validates the result.
pub fn load_config(
    config_path: Option<&str>,
    overrides: &ConfigOverrides,
) -> anyhow::Result<Config> {
    let mut config = match config_path {
        Some(path) => TomlConfigFilePersistence.load_config_from_file(path)?,
        None => Config::builtin(),
    };
    overrides.apply(&mut config);

    config.validate()?;

    info!(
        config_file = config_path.unwrap_or("default"),
        dns_port = config.server.dns_port,
        web_port = config.server.web_port,
        bind = %config.server.bind_address,
        "Configuration loaded"
    );

    Ok(config)
}
