use ferrous_dns_api::{
    AppState, AuthUseCases, BackupUseCases, BlockingUseCases, ClientUseCases, DnsUseCases,
    GroupUseCases, QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
use ferrous_dns_application::ports::{
    BlocklistSourceCreator, ConfigFilePersistence, GroupCreator, LocalRecordCreator,
};
use ferrous_dns_application::use_cases::{
    CreateLocalRecordUseCase, DeleteLocalRecordUseCase, ExportConfigUseCase, ImportConfigUseCase,
    UpdateLocalRecordUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{UpstreamHealthAdapter, UpstreamReloadAdapter};
use ferrous_dns_infrastructure::repositories::{TomlConfigFilePersistence, TomlConfigRepository};
use ferrous_dns_infrastructure::tls::TlsCertificateService;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{DnsServices, Repositories, UseCases};

/// The config file the server reads and rewrites: the path it was started with,
/// else the one `Config` discovers, else `ferrous-dns.toml` in the working dir.
pub(super) fn resolve_config_file(config_path: Option<&str>) -> String {
    config_path
        .map(String::from)
        .or_else(Config::get_config_path)
        .unwrap_or_else(|| "ferrous-dns.toml".to_string())
}

/// Builds the shared API state.
///
/// `https_active` must reflect whether the web server really serves HTTPS, not
/// the `[server.web_tls] enabled` flag: it drives the session cookie's `Secure`
/// attribute, and a browser stores such a cookie only over a secure origin.
pub async fn build_app_state(
    use_cases: UseCases,
    auth: AuthUseCases,
    repos: &Repositories,
    dns_services: &DnsServices,
    config: Arc<RwLock<Config>>,
    config_path: Option<Arc<str>>,
    https_active: bool,
) -> AppState {
    let config_repo: Arc<dyn ferrous_dns_application::ports::ConfigRepository> = Arc::new(
        TomlConfigRepository::new(resolve_config_file(config_path.as_deref())),
    );

    let webauthn_configured = config.read().await.auth.webauthn.is_configured();

    let config_persistence: Arc<dyn ConfigFilePersistence> = Arc::new(TomlConfigFilePersistence);

    let backup = {
        let group_creator: Arc<dyn GroupCreator> = use_cases.create_group.clone();
        let blocklist_source_creator: Arc<dyn BlocklistSourceCreator> =
            use_cases.create_blocklist_source.clone();
        let local_record_creator_for_import = Arc::new(
            CreateLocalRecordUseCase::new(config.clone(), config_repo.clone())
                .with_ptr_registry(dns_services.ptr_registry.clone())
                .with_wildcard_registry(Some(dns_services.wildcard_registry.clone()))
                .with_dns_cache(Some(dns_services.cache.clone()
                    as Arc<dyn ferrous_dns_application::ports::DnsCachePort>)),
        );
        let local_record_creator: Arc<dyn LocalRecordCreator> = local_record_creator_for_import;
        let resolved_path = config_path
            .as_deref()
            .map(String::from)
            .or_else(Config::get_config_path);
        BackupUseCases {
            export: Arc::new(ExportConfigUseCase::new(
                config.clone(),
                repos.group.clone(),
                repos.blocklist_source.clone(),
            )),
            import: Arc::new(
                ImportConfigUseCase::new(
                    config.clone(),
                    config_persistence.clone(),
                    resolved_path,
                    group_creator,
                    blocklist_source_creator,
                    local_record_creator,
                )
                .with_block_filter(repos.block_filter_engine.clone()),
            ),
        }
    };

    AppState {
        query: QueryUseCases {
            get_stats: use_cases.get_stats,
            get_queries: use_cases.get_queries,
            get_timeline: use_cases.get_timeline,
            get_query_rate: use_cases.get_query_rate,
            get_cache_stats: use_cases.get_cache_stats,
            get_top_blocked_domains: use_cases.get_top_blocked_domains,
            get_top_clients: use_cases.get_top_clients,
        },
        dns: DnsUseCases {
            cache: dns_services.cache.clone()
                as Arc<dyn ferrous_dns_application::ports::DnsCachePort>,
            create_local_record: Arc::new(
                CreateLocalRecordUseCase::new(config.clone(), config_repo.clone())
                    .with_ptr_registry(dns_services.ptr_registry.clone())
                    .with_wildcard_registry(Some(dns_services.wildcard_registry.clone()))
                    .with_dns_cache(Some(dns_services.cache.clone()
                        as Arc<dyn ferrous_dns_application::ports::DnsCachePort>)),
            ),
            update_local_record: Arc::new(
                UpdateLocalRecordUseCase::new(config.clone(), config_repo.clone())
                    .with_ptr_registry(dns_services.ptr_registry.clone())
                    .with_wildcard_registry(Some(dns_services.wildcard_registry.clone()))
                    .with_dns_cache(Some(dns_services.cache.clone()
                        as Arc<dyn ferrous_dns_application::ports::DnsCachePort>)),
            ),
            delete_local_record: Arc::new(
                DeleteLocalRecordUseCase::new(config.clone(), config_repo)
                    .with_ptr_registry(dns_services.ptr_registry.clone())
                    .with_wildcard_registry(Some(dns_services.wildcard_registry.clone()))
                    .with_dns_cache(Some(dns_services.cache.clone()
                        as Arc<dyn ferrous_dns_application::ports::DnsCachePort>)),
            ),
            upstream_health: Arc::new(UpstreamHealthAdapter::new(
                dns_services.pool_manager.clone(),
                dns_services.health_checker.clone(),
            )),
            dnssec_stats: dns_services.dnssec_stats.clone(),
            reload_upstream: Arc::new(UpstreamReloadAdapter::new({
                let mut managers = vec![
                    dns_services.pool_manager.clone(),
                    dns_services.dnssec_pool_manager.clone(),
                ];
                if let Some(maintenance) = dns_services.maintenance_pool_manager.clone() {
                    managers.push(maintenance);
                }
                managers
            })),
        },
        groups: GroupUseCases {
            get_groups: use_cases.get_groups,
            create_group: use_cases.create_group,
            update_group: use_cases.update_group,
            delete_group: use_cases.delete_group,
            assign_client_group: use_cases.assign_client_group,
        },
        clients: ClientUseCases {
            get_clients: use_cases.get_clients,
            create_manual_client: use_cases.create_manual_client,
            update_client: use_cases.update_client,
            delete_client: use_cases.delete_client,
            get_client_subnets: use_cases.get_client_subnets,
            create_client_subnet: use_cases.create_client_subnet,
            delete_client_subnet: use_cases.delete_client_subnet,
            subnet_matcher: use_cases.subnet_matcher.clone(),
        },
        blocking: BlockingUseCases {
            get_blocklist: use_cases.get_blocklist,
            get_blocklist_sources: use_cases.get_blocklist_sources,
            create_blocklist_source: use_cases.create_blocklist_source,
            update_blocklist_source: use_cases.update_blocklist_source,
            delete_blocklist_source: use_cases.delete_blocklist_source,
            sync_blocklist_sources: use_cases.sync_blocklist_sources,
            get_whitelist: use_cases.get_whitelist,
            get_whitelist_sources: use_cases.get_whitelist_sources,
            create_whitelist_source: use_cases.create_whitelist_source,
            update_whitelist_source: use_cases.update_whitelist_source,
            delete_whitelist_source: use_cases.delete_whitelist_source,
            get_managed_domains: use_cases.get_managed_domains,
            create_managed_domain: use_cases.create_managed_domain,
            update_managed_domain: use_cases.update_managed_domain,
            delete_managed_domain: use_cases.delete_managed_domain,
            get_regex_filters: use_cases.get_regex_filters,
            create_regex_filter: use_cases.create_regex_filter,
            update_regex_filter: use_cases.update_regex_filter,
            delete_regex_filter: use_cases.delete_regex_filter,
            get_block_filter_stats: use_cases.get_block_filter_stats,
            test_domain: use_cases.test_domain,
            backtest: use_cases.backtest,
        },
        services: ServiceUseCases {
            get_service_catalog: use_cases.get_service_catalog,
            get_blocked_services: use_cases.get_blocked_services,
            block_service: use_cases.block_service,
            unblock_service: use_cases.unblock_service,
            create_custom_service: use_cases.create_custom_service,
            get_custom_services: use_cases.get_custom_services,
            update_custom_service: use_cases.update_custom_service,
            delete_custom_service: use_cases.delete_custom_service,
        },
        safe_search: SafeSearchUseCases {
            get_configs: use_cases.get_safe_search_configs,
            toggle: use_cases.toggle_safe_search,
            delete_configs: use_cases.delete_safe_search_configs,
        },
        schedule: ScheduleUseCases {
            get_profiles: use_cases.get_schedule_profiles,
            create_profile: use_cases.create_schedule_profile,
            update_profile: use_cases.update_schedule_profile,
            delete_profile: use_cases.delete_schedule_profile,
            manage_slots: use_cases.manage_time_slots,
            assign_profile: use_cases.assign_schedule_profile,
        },
        auth,
        backup,
        tls_enabled: https_active,
        restart_pending: Default::default(),
        config,
        config_file_persistence: config_persistence,
        config_path,
        tls_cert: Arc::new(TlsCertificateService),
        webauthn_configured,
    }
}
