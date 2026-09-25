use ferrous_dns_jobs::{WalCheckpointJob, WalCheckpointOutcome};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Connection, SqliteConnection};
use std::path::PathBuf;

struct TempDb(PathBuf);

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
    }
}

#[tokio::test]
async fn test_wal_checkpoint_reports_reader_pinned_wal_as_partial() {
    let db = TempDb(std::env::temp_dir().join(format!(
        "ferrous-jobs-wal-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap()
    )));
    let options = SqliteConnectOptions::new()
        .filename(&db.0)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .pragma("wal_autocheckpoint", "0");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();

    sqlx::query("CREATE TABLE t (v INTEGER)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES (1)")
        .execute(&pool)
        .await
        .unwrap();

    // The reader's snapshot ends at the current WAL frame, so later frames cannot be copied back.
    let mut reader = SqliteConnection::connect_with(&options).await.unwrap();
    let mut snapshot = reader.begin().await.unwrap();
    sqlx::query("SELECT count(*) FROM t")
        .fetch_one(&mut *snapshot)
        .await
        .unwrap();

    sqlx::query("INSERT INTO t VALUES (2)")
        .execute(&pool)
        .await
        .unwrap();

    let job = WalCheckpointJob::new(pool.clone(), 1);

    let pinned = job.checkpoint_once().await.unwrap();
    assert!(
        matches!(
            pinned,
            WalCheckpointOutcome::Partial { log_frames, checkpointed_frames }
                if checkpointed_frames < log_frames
        ),
        "pinned WAL reported as {pinned:?}"
    );

    snapshot.rollback().await.unwrap();

    let released = job.checkpoint_once().await.unwrap();
    assert!(
        matches!(released, WalCheckpointOutcome::Complete { frames } if frames > 0),
        "released WAL reported as {released:?}"
    );

    reader.close().await.unwrap();
    pool.close().await;
}
