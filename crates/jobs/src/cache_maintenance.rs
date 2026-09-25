use ferrous_dns_application::ports::CacheMaintenancePort;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// How often the eviction and refresh cycle runs.
///
/// Shared rather than repeated at each call site: the optimistic pacer divides
/// this interval by the backlog to spread a cycle's work across it, so a copy
/// that drifts from the value actually driving the job would silently mis-pace
/// every drain.
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 60;

pub struct CacheMaintenanceJob {
    maintenance: Arc<dyn CacheMaintenancePort>,
    refresh_interval_secs: u64,
    compaction_interval_secs: u64,
}

impl CacheMaintenanceJob {
    pub fn new(
        maintenance: Arc<dyn CacheMaintenancePort>,
        refresh_interval_secs: u64,
        compaction_interval_secs: u64,
    ) -> Self {
        Self {
            maintenance,
            refresh_interval_secs,
            compaction_interval_secs,
        }
    }

    pub fn spawn(self) {
        info!("Starting cache maintenance background jobs");

        let Self {
            maintenance,
            refresh_interval_secs,
            compaction_interval_secs,
        } = self;

        let cycle = Arc::clone(&maintenance);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = cycle.run_eviction_cycle().await {
                    error!(error = %e, "Cache eviction cycle failed");
                }
                match cycle.run_refresh_cycle().await {
                    Ok(outcome) => {
                        // Losing candidates is not routine: it means the
                        // eligible working set no longer fits the queue,
                        // and the entries cut are the ones that will be
                        // resolved upstream instead of served warm.
                        if outcome.shed > 0 || outcome.dropped > 0 {
                            warn!(
                                candidates = outcome.candidates_found,
                                shed = outcome.shed,
                                dropped = outcome.dropped,
                                cache_size = outcome.cache_size,
                                "Cache refresh cycle could not queue every candidate — \
                                 lower cache_access_window_secs or cache_max_entries, \
                                 or expect these entries to miss"
                            );
                        }
                        if outcome.candidates_found > 0 {
                            info!(
                                candidates = outcome.candidates_found,
                                enqueued = outcome.enqueued,
                                dropped = outcome.dropped,
                                shed = outcome.shed,
                                period_ms = outcome.paced_period_ms,
                                cache_size = outcome.cache_size,
                                "Cache refresh cycle queued candidates"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Cache refresh cycle failed");
                    }
                }
            }
        });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(compaction_interval_secs));
            loop {
                interval.tick().await;
                match maintenance.run_compaction_cycle().await {
                    Ok(outcome) => {
                        if outcome.entries_removed > 0 {
                            info!(
                                entries_removed = outcome.entries_removed,
                                cache_size = outcome.cache_size,
                                "Cache compaction cycle completed"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Cache compaction cycle failed");
                    }
                }
            }
        });
    }
}
