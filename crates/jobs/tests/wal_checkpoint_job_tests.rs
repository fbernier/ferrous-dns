use ferrous_dns_jobs::WalCheckpointJob;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::path::PathBuf;
use tokio::time::{sleep, Duration};

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
async fn test_wal_checkpoint_job_zero_interval_still_checkpoints() {
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
        .connect_with(options)
        .await
        .unwrap();

    sqlx::query("CREATE TABLE t (b BLOB)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES (zeroblob(1048576))")
        .execute(&pool)
        .await
        .unwrap();
    // With autocheckpoint off the blob lives only in the WAL until a checkpoint copies it back.
    let before = std::fs::metadata(&db.0).unwrap().len();
    assert!(before < 1_048_576, "main db file already holds the blob");

    WalCheckpointJob::new(pool.clone(), 0).spawn();
    sleep(Duration::from_millis(300)).await;

    let after = std::fs::metadata(&db.0).unwrap().len();
    pool.close().await;
    assert!(
        after >= 1_048_576,
        "no checkpoint ran (db file is {after} bytes)"
    );
}
