use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheCompactionOutcome, CacheMaintenancePort, CacheRefreshOutcome,
};
use ferrous_dns_domain::DomainError;
use ferrous_dns_jobs::CacheMaintenanceJob;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Default)]
struct MockCacheMaintenancePort {
    refresh_calls: AtomicU64,
    compaction_calls: AtomicU64,
    fail_refresh: AtomicBool,
    fail_compaction: AtomicBool,
}

impl MockCacheMaintenancePort {
    fn failing_refresh() -> Self {
        Self {
            fail_refresh: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn failing_compaction() -> Self {
        Self {
            fail_compaction: AtomicBool::new(true),
            ..Self::default()
        }
    }

    fn refresh_call_count(&self) -> u64 {
        self.refresh_calls.load(Ordering::Relaxed)
    }

    fn compaction_call_count(&self) -> u64 {
        self.compaction_calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl CacheMaintenancePort for MockCacheMaintenancePort {
    async fn run_refresh_cycle(&self) -> Result<CacheRefreshOutcome, DomainError> {
        self.refresh_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_refresh.load(Ordering::Relaxed) {
            return Err(DomainError::IoError("mock refresh failure".into()));
        }
        Ok(CacheRefreshOutcome::default())
    }

    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError> {
        self.compaction_calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_compaction.load(Ordering::Relaxed) {
            return Err(DomainError::IoError("mock compaction failure".into()));
        }
        Ok(CacheCompactionOutcome::default())
    }
}

// Both tasks tick once immediately, so only a second tick proves an interval is honoured.

#[tokio::test]
async fn test_cache_maintenance_job_refresh_runs_on_its_own_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::default());
    CacheMaintenanceJob::new(mock.clone(), 1, 3600).spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(mock.refresh_call_count() >= 2);
    assert_eq!(mock.compaction_call_count(), 1);
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_runs_on_its_own_interval() {
    let mock = Arc::new(MockCacheMaintenancePort::default());
    CacheMaintenanceJob::new(mock.clone(), 3600, 1).spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(mock.compaction_call_count() >= 2);
    assert_eq!(mock.refresh_call_count(), 1);
}

#[tokio::test]
async fn test_cache_maintenance_job_zero_interval_does_not_kill_task() {
    let mock = Arc::new(MockCacheMaintenancePort::default());
    CacheMaintenanceJob::new(mock.clone(), 0, 0).spawn();

    sleep(Duration::from_millis(1500)).await;

    assert!(mock.refresh_call_count() >= 1);
    assert!(mock.compaction_call_count() >= 1);
}

#[tokio::test]
async fn test_cache_maintenance_job_refresh_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::failing_refresh());

    CacheMaintenanceJob::new(mock.clone(), 1, 3600).spawn();

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.refresh_call_count() >= 2,
        "Job should continue running after refresh errors"
    );
}

#[tokio::test]
async fn test_cache_maintenance_job_compaction_error_is_non_fatal() {
    let mock = Arc::new(MockCacheMaintenancePort::failing_compaction());

    CacheMaintenanceJob::new(mock.clone(), 3600, 1).spawn();

    sleep(Duration::from_millis(2200)).await;

    assert!(
        mock.compaction_call_count() >= 2,
        "Job should continue running after compaction errors"
    );
}
