use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
use sqlx::SqlitePool;

async fn autocheckpoint_of_every_connection(pool: &SqlitePool, connections: u32) -> Vec<i64> {
    let mut held = Vec::new();
    for _ in 0..connections {
        held.push(pool.acquire().await.expect("acquire"));
    }
    let mut values = Vec::new();
    for conn in &mut held {
        let (pages,): (i64,) = sqlx::query_as("PRAGMA wal_autocheckpoint")
            .fetch_one(&mut **conn)
            .await
            .expect("read pragma");
        values.push(pages);
    }
    values
}

#[tokio::test]
async fn test_wal_autocheckpoint_applies_to_every_connection_of_every_pool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let cfg = DatabaseConfig {
        wal_autocheckpoint: 321,
        write_pool_max_connections: 3,
        query_log_pool_max_connections: 3,
        read_pool_max_connections: 3,
        ..DatabaseConfig::default()
    };

    let write = create_write_pool(&url, &cfg).await.expect("write pool");
    let query_log = create_query_log_pool(&url, &cfg)
        .await
        .expect("query log pool");
    let read = create_read_pool(&url, &cfg).await.expect("read pool");

    for (name, pool) in [
        ("write", &write),
        ("query_log", &query_log),
        ("read", &read),
    ] {
        assert_eq!(
            autocheckpoint_of_every_connection(pool, 3).await,
            vec![321; 3],
            "{name} pool"
        );
    }
}
