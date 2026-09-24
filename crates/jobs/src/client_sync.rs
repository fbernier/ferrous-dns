use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

pub struct ClientSyncJob {
    sync_arp: Arc<SyncArpCacheUseCase>,
    sync_hostnames: Arc<SyncHostnamesUseCase>,
    arp_interval_secs: u64,
    hostname_interval_secs: u64,
}

impl ClientSyncJob {
    pub fn new(
        sync_arp: Arc<SyncArpCacheUseCase>,
        sync_hostnames: Arc<SyncHostnamesUseCase>,
    ) -> Self {
        Self {
            sync_arp,
            sync_hostnames,
            arp_interval_secs: 60,
            hostname_interval_secs: 300,
        }
    }

    pub fn with_intervals(mut self, arp_secs: u64, hostname_secs: u64) -> Self {
        self.arp_interval_secs = arp_secs.max(1);
        self.hostname_interval_secs = hostname_secs.max(1);
        self
    }

    pub fn spawn(self) {
        info!("Starting client sync background jobs");

        let Self {
            sync_arp,
            sync_hostnames,
            arp_interval_secs,
            hostname_interval_secs,
        } = self;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(arp_interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = sync_arp.execute().await {
                    error!(error = %e, "ARP sync failed");
                }
            }
        });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(hostname_interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = sync_hostnames.execute(50).await {
                    error!(error = %e, "Hostname sync failed");
                }
            }
        });
    }
}
