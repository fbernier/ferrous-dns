use ferrous_dns_application::ports::TunnelingEvictionTarget;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

pub struct TunnelingEvictionJob {
    detector: Arc<dyn TunnelingEvictionTarget>,
    interval_secs: u64,
}

impl TunnelingEvictionJob {
    pub fn new(detector: Arc<dyn TunnelingEvictionTarget>, interval_secs: u64) -> Self {
        Self {
            detector,
            interval_secs: interval_secs.max(30),
        }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = self.interval_secs,
            "Starting tunneling eviction job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                self.detector.evict_stale();
                debug!(
                    tracked = self.detector.tracked_count(),
                    flagged = self.detector.flagged_count(),
                    "Tunneling eviction cycle"
                );
            }
        });
    }
}
