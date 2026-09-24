use sqlx::SqlitePool;
use std::time::Duration;
use tracing::{error, info};

pub struct WalCheckpointJob {
    pool: SqlitePool,
    interval_secs: u64,
}

impl WalCheckpointJob {
    pub fn new(pool: SqlitePool, interval_secs: u64) -> Self {
        // `tokio::time::interval` panics on a zero period, and config does not reject 0.
        Self {
            pool,
            interval_secs: interval_secs.max(1),
        }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = self.interval_secs,
            "Starting WAL checkpoint job (PASSIVE mode)"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                match sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
                    .execute(&self.pool)
                    .await
                {
                    Ok(_) => info!("WAL passive checkpoint completed"),
                    Err(e) => error!(error = %e, "WAL checkpoint failed"),
                }
            }
        });
    }
}
