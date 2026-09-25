use ferrous_dns_domain::DomainError;
use sqlx::SqlitePool;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Result of one `PRAGMA wal_checkpoint(PASSIVE)`, parsed from its `(busy, log, checkpointed)` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalCheckpointOutcome {
    /// Every WAL frame was copied back into the database file.
    Complete { frames: i64 },
    /// A reader's snapshot pinned the WAL, so only a prefix of the frames was copied back.
    Partial {
        log_frames: i64,
        checkpointed_frames: i64,
    },
    /// Another connection held a lock the checkpoint needed.
    Busy {
        log_frames: i64,
        checkpointed_frames: i64,
    },
    /// The database is not in WAL mode.
    NotWal,
}

impl WalCheckpointOutcome {
    fn from_row((busy, log_frames, checkpointed_frames): (i64, i64, i64)) -> Self {
        if log_frames == -1 {
            Self::NotWal
        } else if busy != 0 {
            Self::Busy {
                log_frames,
                checkpointed_frames,
            }
        } else if checkpointed_frames < log_frames {
            Self::Partial {
                log_frames,
                checkpointed_frames,
            }
        } else {
            Self::Complete { frames: log_frames }
        }
    }
}

pub struct WalCheckpointJob {
    pool: SqlitePool,
    interval_secs: u64,
}

impl WalCheckpointJob {
    pub fn new(pool: SqlitePool, interval_secs: u64) -> Self {
        Self {
            pool,
            interval_secs,
        }
    }

    pub async fn checkpoint_once(&self) -> Result<WalCheckpointOutcome, DomainError> {
        sqlx::query_as::<_, (i64, i64, i64)>("PRAGMA wal_checkpoint(PASSIVE)")
            .fetch_one(&self.pool)
            .await
            .map(WalCheckpointOutcome::from_row)
            .map_err(|e| DomainError::DatabaseError(e.to_string()))
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
                match self.checkpoint_once().await {
                    Ok(WalCheckpointOutcome::Complete { frames }) => {
                        info!(frames, "WAL passive checkpoint completed")
                    }
                    Ok(WalCheckpointOutcome::Partial {
                        log_frames,
                        checkpointed_frames,
                    }) => warn!(
                        log_frames,
                        checkpointed_frames, "WAL passive checkpoint partial: readers pin the WAL"
                    ),
                    Ok(WalCheckpointOutcome::Busy {
                        log_frames,
                        checkpointed_frames,
                    }) => warn!(
                        log_frames,
                        checkpointed_frames, "WAL passive checkpoint blocked by a busy lock"
                    ),
                    Ok(WalCheckpointOutcome::NotWal) => {
                        debug!("WAL checkpoint skipped: database is not in WAL mode")
                    }
                    Err(e) => error!(error = %e, "WAL checkpoint failed"),
                }
            }
        });
    }
}
