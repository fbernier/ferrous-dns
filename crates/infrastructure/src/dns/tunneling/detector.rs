use super::client_stats::{
    fx_hash_str, subnet_key_from_ip, ClientApexStats, StatsMap, TrackingKey,
};
use super::entropy::extract_subdomain;
use super::signal::SignalScore;
use dashmap::DashMap;
use ferrous_dns_application::ports::{TunnelingEvictionTarget, TunnelingFlagStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_application::use_cases::dns::domain_heuristics::{extract_apex, shannon_entropy};
use ferrous_dns_application::use_cases::dns::TunnelingAnalysisEvent;
use ferrous_dns_domain::{RecordType, TunnelingDetectionConfig};
use rustc_hash::FxBuildHasher;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const CHANNEL_CAPACITY: usize = 4096;
const WINDOW_DURATION_NS: u64 = 60_000_000_000; // 1 minute
/// Flagged domains live this many times longer than stats entries before eviction.
const FLAGGED_DOMAIN_TTL_MULTIPLIER: u64 = 2;

/// Background DNS tunneling detector.
///
/// Consumes `TunnelingAnalysisEvent`s from the hot path via an mpsc channel,
/// maintains per-client/apex statistics, and flags domains when the confidence
/// score exceeds the configured threshold.
pub struct TunnelingDetector {
    config: TunnelingDetectionConfig,
    #[doc(hidden)]
    pub stats: StatsMap,
    /// Flagged apex → when it was last flagged (coarse ns).
    #[doc(hidden)]
    pub flagged_domains: DashMap<Arc<str>, u64, FxBuildHasher>,
}

impl TunnelingDetector {
    /// Creates a detector and returns the sender half of the analysis channel.
    pub fn new(
        config: &TunnelingDetectionConfig,
    ) -> (
        Self,
        mpsc::Sender<TunnelingAnalysisEvent>,
        mpsc::Receiver<TunnelingAnalysisEvent>,
    ) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let detector = Self {
            config: config.clone(),
            stats: DashMap::with_hasher(FxBuildHasher),
            flagged_domains: DashMap::with_hasher(FxBuildHasher),
        };
        (detector, tx, rx)
    }

    pub fn stale_entry_ttl_secs(&self) -> u64 {
        self.config.stale_entry_ttl_secs
    }

    pub async fn run_analysis_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<TunnelingAnalysisEvent>,
    ) {
        info!("DNS tunneling analysis loop started");
        while let Some(event) = rx.recv().await {
            self.process_event(&event);
        }
        info!("DNS tunneling analysis loop stopped");
    }

    #[doc(hidden)]
    pub fn process_event(&self, event: &TunnelingAnalysisEvent) {
        let apex = extract_apex(&event.domain);
        let key = TrackingKey {
            subnet: subnet_key_from_ip(event.client_ip),
            apex_hash: fx_hash_str(apex),
        };

        let now_ns = coarse_now_ns();

        let entry = self
            .stats
            .entry(key)
            .or_insert_with(|| ClientApexStats::new(now_ns));
        let stats = entry.value();

        // CAS so concurrent events cannot both reset the same window.
        let window_start = stats.window_start_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(window_start) > WINDOW_DURATION_NS
            && stats
                .window_start_ns
                .compare_exchange(window_start, now_ns, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            stats.reset_window(now_ns);
        }

        stats.last_seen_ns.store(now_ns, Ordering::Relaxed);
        stats.query_count.fetch_add(1, Ordering::Relaxed);

        if event.record_type == RecordType::TXT {
            stats.txt_query_count.fetch_add(1, Ordering::Relaxed);
        }

        if event.was_nxdomain {
            stats.nxdomain_count.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(subdomain) = extract_subdomain(&event.domain) {
            if stats.bloom_add(fx_hash_str(subdomain)) {
                stats.unique_subdomain_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        let score = self.compute_confidence(stats, &event.domain);

        if score.confidence >= self.config.confidence_threshold {
            match self.flagged_domains.get_mut(apex) {
                Some(mut flagged_at) => *flagged_at = now_ns,
                None => {
                    warn!(
                        domain = apex,
                        signal = score.top_signal,
                        confidence = score.confidence,
                        measured = score.top_measured,
                        threshold = score.top_threshold,
                        "DNS tunneling detected — domain flagged"
                    );
                    self.flagged_domains.insert(Arc::from(apex), now_ns);
                }
            }
        }
    }

    fn compute_confidence(&self, stats: &ClientApexStats, domain: &str) -> SignalScore {
        let mut score = SignalScore::new();

        if let Some(subdomain) = extract_subdomain(domain) {
            let entropy = shannon_entropy(subdomain.as_bytes());
            if entropy > self.config.entropy_threshold {
                score.add(0.30, "entropy", entropy, self.config.entropy_threshold);
            }
        }

        let query_count = stats.query_count.load(Ordering::Relaxed);
        if query_count > self.config.query_rate_per_apex {
            score.add(
                0.25,
                "query_rate",
                query_count as f32,
                self.config.query_rate_per_apex as f32,
            );
        }

        let unique_count = stats.unique_subdomain_count.load(Ordering::Relaxed);
        if unique_count > self.config.unique_subdomain_threshold {
            score.add(
                0.25,
                "unique_subdomains",
                unique_count as f32,
                self.config.unique_subdomain_threshold as f32,
            );
        }

        if query_count > 0 {
            let txt_count = stats.txt_query_count.load(Ordering::Relaxed);
            let txt_ratio = txt_count as f32 / query_count as f32;
            if txt_ratio > self.config.txt_proportion_threshold {
                score.add(
                    0.10,
                    "txt_proportion",
                    txt_ratio,
                    self.config.txt_proportion_threshold,
                );
            }

            let nx_count = stats.nxdomain_count.load(Ordering::Relaxed);
            let nx_ratio = nx_count as f32 / query_count as f32;
            if nx_ratio > self.config.nxdomain_ratio_threshold {
                score.add(
                    0.10,
                    "nxdomain_ratio",
                    nx_ratio,
                    self.config.nxdomain_ratio_threshold,
                );
            }
        }

        score
    }
}

impl TunnelingEvictionTarget for TunnelingDetector {
    fn evict_stale(&self) {
        let now_ns = coarse_now_ns();
        let ttl_ns = self
            .config
            .stale_entry_ttl_secs
            .saturating_mul(1_000_000_000);
        let flagged_ttl_ns = ttl_ns.saturating_mul(FLAGGED_DOMAIN_TTL_MULTIPLIER);

        // saturating_sub: the analysis loop can stamp an entry after `now_ns` was read.
        let evicted = {
            let before = self.stats.len();
            self.stats.retain(|_, stats| {
                now_ns.saturating_sub(stats.last_seen_ns.load(Ordering::Relaxed)) < ttl_ns
            });
            before.saturating_sub(self.stats.len())
        };
        let flagged_evicted = {
            let before = self.flagged_domains.len();
            self.flagged_domains
                .retain(|_, flagged_at| now_ns.saturating_sub(*flagged_at) < flagged_ttl_ns);
            before.saturating_sub(self.flagged_domains.len())
        };

        if evicted > 0 || flagged_evicted > 0 {
            debug!(
                evicted,
                flagged_evicted,
                remaining = self.stats.len(),
                flagged = self.flagged_domains.len(),
                "Tunneling detector stale eviction"
            );
        }
    }

    fn tracked_count(&self) -> usize {
        self.stats.len()
    }

    fn flagged_count(&self) -> usize {
        self.flagged_domains.len()
    }
}

impl TunnelingFlagStore for TunnelingDetector {
    fn is_flagged(&self, domain: &str) -> bool {
        self.flagged_domains.contains_key(extract_apex(domain))
    }
}
