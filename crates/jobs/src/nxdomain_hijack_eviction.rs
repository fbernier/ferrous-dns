use ferrous_dns_application::ports::NxdomainHijackProbeTarget;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Background job that periodically evicts stale NXDomain hijack IPs.
pub struct NxdomainHijackEvictionJob {
    detector: Arc<dyn NxdomainHijackProbeTarget>,
    interval_secs: u64,
}

impl NxdomainHijackEvictionJob {
    pub fn new(detector: Arc<dyn NxdomainHijackProbeTarget>, interval_secs: u64) -> Self {
        Self {
            detector,
            interval_secs: interval_secs.max(30),
        }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = self.interval_secs,
            "Starting NXDomain hijack eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                self.detector.evict_stale_ips();
                debug!(
                    hijack_ips = self.detector.hijack_ip_count(),
                    hijacking_upstreams = self.detector.hijacking_upstream_count(),
                    "NXDomain hijack eviction cycle"
                );
            }
        });
    }
}
