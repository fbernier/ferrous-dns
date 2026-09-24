use ferrous_dns_application::ports::ResponseIpFilterEvictionTarget;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Background job that periodically evicts stale C2 IPs from the filter.
pub struct ResponseIpFilterEvictionJob {
    detector: Arc<dyn ResponseIpFilterEvictionTarget>,
    interval_secs: u64,
}

impl ResponseIpFilterEvictionJob {
    pub fn new(detector: Arc<dyn ResponseIpFilterEvictionTarget>, interval_secs: u64) -> Self {
        Self {
            detector,
            interval_secs: interval_secs.max(30),
        }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = self.interval_secs,
            "Starting response IP filter eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                self.detector.evict_stale_ips();
                debug!(
                    blocked_ips = self.detector.blocked_ip_count(),
                    "Response IP filter eviction cycle"
                );
            }
        });
    }
}
