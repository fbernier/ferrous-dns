use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed-point multiplier for sub-token precision.
const MILLI: u64 = 1000;

/// NX burst capacity is this multiple of `nx_qps`.
const NX_BURST_MULTIPLIER: u64 = 2;

/// Per-subnet token bucket state using atomics for lock-free hot-path access.
///
/// Uses `Ordering::Relaxed` throughout: slight over-admission under contention
/// is acceptable for rate limiting and avoids the cost of sequential consistency.
pub(crate) struct TokenBucket {
    tokens_milli: AtomicU64,
    last_refill_ns: AtomicU64,
    nxdomain_tokens_milli: AtomicU64,
}

impl TokenBucket {
    pub(crate) fn new(burst: u32, nx_qps: u32, now_ns: u64) -> Self {
        Self {
            tokens_milli: AtomicU64::new(burst as u64 * MILLI),
            last_refill_ns: AtomicU64::new(now_ns),
            nxdomain_tokens_milli: AtomicU64::new(nx_burst_milli(nx_qps)),
        }
    }

    /// Returns the timestamp of the last refill (for eviction staleness checks).
    #[inline]
    pub(crate) fn last_refill_ns(&self) -> u64 {
        self.last_refill_ns.load(Ordering::Relaxed)
    }

    /// Read-only peek: `true` if a query would currently be admitted.
    #[inline]
    pub(crate) fn has_tokens(&self) -> bool {
        self.tokens_milli.load(Ordering::Relaxed) >= MILLI
    }

    /// Refills tokens based on elapsed time, then tries to consume one general
    /// token. Returns `true` if the query is allowed.
    #[inline]
    pub(crate) fn try_consume(&self, now_ns: u64, qps: u32, burst: u32, nx_qps: u32) -> bool {
        self.refill(now_ns, qps, burst, nx_qps);
        try_decrement(&self.tokens_milli)
    }

    /// Charges one NXDOMAIN answer against the NXDOMAIN budget. Returns `true`
    /// if the budget covered it, `false` if this answer is over budget.
    #[inline]
    pub(crate) fn try_charge_nxdomain(
        &self,
        now_ns: u64,
        qps: u32,
        burst: u32,
        nx_qps: u32,
    ) -> bool {
        self.refill(now_ns, qps, burst, nx_qps);
        try_decrement(&self.nxdomain_tokens_milli)
    }

    #[inline]
    fn refill(&self, now_ns: u64, qps: u32, burst: u32, nx_qps: u32) {
        let prev_ns = self.last_refill_ns.load(Ordering::Relaxed);
        let elapsed_ns = now_ns.saturating_sub(prev_ns);
        if elapsed_ns == 0 {
            return;
        }

        // Relaxed CAS: if another thread already refilled, we skip — acceptable.
        if self
            .last_refill_ns
            .compare_exchange(prev_ns, now_ns, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let add_milli = (elapsed_ns as u128 * qps as u128 * MILLI as u128) / 1_000_000_000;
        let cap_milli = burst as u64 * MILLI;
        add_capped(&self.tokens_milli, add_milli as u64, cap_milli);

        let nx_add = (elapsed_ns as u128 * nx_qps as u128 * MILLI as u128) / 1_000_000_000;
        add_capped(
            &self.nxdomain_tokens_milli,
            nx_add as u64,
            nx_burst_milli(nx_qps),
        );
    }
}

#[inline]
fn nx_burst_milli(nx_qps: u32) -> u64 {
    nx_qps as u64 * MILLI * NX_BURST_MULTIPLIER
}

#[inline]
fn try_decrement(counter: &AtomicU64) -> bool {
    loop {
        let current = counter.load(Ordering::Relaxed);
        if current < MILLI {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current - MILLI,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
}

#[inline]
fn add_capped(counter: &AtomicU64, add: u64, cap: u64) {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let new_val = (current + add).min(cap);
        if current == new_val {
            return;
        }
        match counter.compare_exchange_weak(current, new_val, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QPS: u32 = 10;
    const BURST: u32 = 5;
    const NX_QPS: u32 = 3;
    const ONE_SEC_NS: u64 = 1_000_000_000;

    #[test]
    fn consumes_within_burst() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);
        for _ in 0..BURST {
            assert!(bucket.try_consume(0, QPS, BURST, NX_QPS));
        }
    }

    #[test]
    fn refuses_after_burst_exhausted() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);
        for _ in 0..BURST {
            bucket.try_consume(0, QPS, BURST, NX_QPS);
        }
        assert!(!bucket.try_consume(0, QPS, BURST, NX_QPS));
    }

    #[test]
    fn refills_over_time() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);
        // Drain all tokens
        for _ in 0..BURST {
            bucket.try_consume(0, QPS, BURST, NX_QPS);
        }
        assert!(!bucket.try_consume(0, QPS, BURST, NX_QPS));

        // Advance 1 second — should refill QPS tokens (10), but capped at BURST (5)
        assert!(bucket.try_consume(ONE_SEC_NS, QPS, BURST, NX_QPS));
    }

    #[test]
    fn nxdomain_budget_covers_its_burst_then_refills() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);

        // NX capacity is NX_QPS * 2 = 6 answers.
        for _ in 0..(NX_QPS * 2) {
            assert!(bucket.try_charge_nxdomain(0, QPS, BURST, NX_QPS));
        }
        assert!(!bucket.try_charge_nxdomain(0, QPS, BURST, NX_QPS));

        assert!(bucket.try_charge_nxdomain(ONE_SEC_NS, QPS, BURST, NX_QPS));
    }

    #[test]
    fn spent_nxdomain_budget_leaves_general_admission_alone() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);
        while bucket.try_charge_nxdomain(0, QPS, BURST, NX_QPS) {}

        assert!(bucket.has_tokens());
        for _ in 0..BURST {
            assert!(bucket.try_consume(0, QPS, BURST, NX_QPS));
        }
    }

    #[test]
    fn partial_refill_fraction_of_second() {
        let bucket = TokenBucket::new(1, NX_QPS, 0);
        // Drain the single token
        assert!(bucket.try_consume(0, QPS, 1, NX_QPS));
        assert!(!bucket.try_consume(0, QPS, 1, NX_QPS));

        // Advance 100ms — refills 10 QPS * 0.1s = 1 token
        assert!(bucket.try_consume(ONE_SEC_NS / 10, QPS, 1, NX_QPS));
    }

    #[test]
    fn refill_does_not_exceed_cap() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 0);
        // Consume 1, then advance a long time
        bucket.try_consume(0, QPS, BURST, NX_QPS);
        // Advance 10 seconds — would add 100 tokens, but cap is BURST (5)
        let mut allowed = 0;
        for _ in 0..20 {
            if bucket.try_consume(10 * ONE_SEC_NS, QPS, BURST, NX_QPS) {
                allowed += 1;
            }
        }
        // Should only get BURST tokens back (we consumed 1 earlier, refilled to cap)
        assert_eq!(allowed, BURST as usize);
    }

    #[test]
    fn last_refill_ns_tracks_time() {
        let bucket = TokenBucket::new(BURST, NX_QPS, 42);
        assert_eq!(bucket.last_refill_ns(), 42);
        bucket.try_consume(1000, QPS, BURST, NX_QPS);
        assert_eq!(bucket.last_refill_ns(), 1000);
    }
}
