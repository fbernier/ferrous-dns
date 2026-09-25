use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: String,
    pub log_queries: bool,
    pub queries_log_stored: u32,
    pub client_tracking_interval: u64,
    pub query_log_channel_capacity: usize,
    pub query_log_max_batch_size: usize,
    pub query_log_flush_interval_ms: u64,
    pub query_log_sample_rate: u32,
    pub client_channel_capacity: usize,
    pub write_pool_max_connections: u32,
    pub query_log_pool_max_connections: u32,
    pub read_pool_max_connections: u32,
    pub write_busy_timeout_secs: u64,
    pub read_busy_timeout_secs: u64,
    pub read_acquire_timeout_secs: u64,
    pub wal_autocheckpoint: u32,
    pub sqlite_cache_size_kb: u32,
    pub sqlite_mmap_size_mb: u32,
    pub wal_checkpoint_interval_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./ferrous-dns.db".to_string(),
            log_queries: true,
            queries_log_stored: 30,
            client_tracking_interval: 60,
            query_log_channel_capacity: 10_000,
            query_log_max_batch_size: 500,
            query_log_flush_interval_ms: 100,
            query_log_sample_rate: 1,
            client_channel_capacity: 4_096,
            write_pool_max_connections: 2,
            query_log_pool_max_connections: 2,
            read_pool_max_connections: 4,
            write_busy_timeout_secs: 30,
            read_busy_timeout_secs: 15,
            read_acquire_timeout_secs: 15,
            wal_autocheckpoint: 0,
            sqlite_cache_size_kb: 16_384,
            sqlite_mmap_size_mb: 64,
            wal_checkpoint_interval_secs: 120,
        }
    }
}
