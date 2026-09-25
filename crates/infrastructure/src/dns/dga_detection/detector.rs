use super::ngram::bigram_deviation_score;
use crate::dns::tunneling::client_stats::subnet_key_from_ip;
use crate::dns::tunneling::signal::SignalScore;
use dashmap::DashMap;
use ferrous_dns_application::ports::{DgaEvictionTarget, DgaFlagStore};
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_application::use_cases::dns::domain_heuristics::{
    char_ratios, extract_apex, shannon_entropy,
};
use ferrous_dns_application::use_cases::dns::DgaAnalysisEvent;
use ferrous_dns_domain::DgaDetectionConfig;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const CHANNEL_CAPACITY: usize = 4096;
const WINDOW_DURATION_NS: u64 = 60_000_000_000; // 1 minute
/// Flagged domains live this many times longer than stats entries before eviction.
const FLAGGED_DOMAIN_TTL_MULTIPLIER: u64 = 2;

/// Signal weights for DGA confidence scoring.
const WEIGHT_SLD_ENTROPY: f32 = 0.25;
const WEIGHT_CONSONANT_RATIO: f32 = 0.15;
const WEIGHT_DIGIT_RATIO: f32 = 0.15;
const WEIGHT_SLD_LENGTH: f32 = 0.10;
const WEIGHT_NGRAM_SCORE: f32 = 0.25;
const WEIGHT_DGA_RATE: f32 = 0.10;

/// Per-client DGA tracking statistics.
struct ClientDgaStats {
    dga_domain_count: AtomicU32,
    last_seen_ns: AtomicU64,
    window_start_ns: AtomicU64,
}

impl ClientDgaStats {
    fn new(now_ns: u64) -> Self {
        Self {
            dga_domain_count: AtomicU32::new(0),
            last_seen_ns: AtomicU64::new(now_ns),
            window_start_ns: AtomicU64::new(now_ns),
        }
    }

    fn reset_window(&self, now_ns: u64) {
        self.dga_domain_count.store(0, Ordering::Relaxed);
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
    }
}

/// Background DGA detector.
///
/// Consumes `DgaAnalysisEvent`s from the hot path via an mpsc channel,
/// computes weighted confidence scores using entropy, character ratios,
/// n-gram analysis, and per-client DGA rate, and flags domains when
/// the confidence exceeds the configured threshold.
pub struct DgaDetector {
    config: DgaDetectionConfig,
    /// Per-client subnet stats: DGA domain count per time window.
    stats: DashMap<u64, ClientDgaStats, FxBuildHasher>,
    /// Flagged apex → when it was last flagged (coarse ns).
    flagged_domains: DashMap<Arc<str>, u64, FxBuildHasher>,
}

impl DgaDetector {
    /// Creates a detector and returns the sender/receiver halves of the analysis channel.
    pub fn new(
        config: &DgaDetectionConfig,
    ) -> (
        Self,
        mpsc::Sender<DgaAnalysisEvent>,
        mpsc::Receiver<DgaAnalysisEvent>,
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

    pub async fn run_analysis_loop(self: Arc<Self>, mut rx: mpsc::Receiver<DgaAnalysisEvent>) {
        info!("DGA analysis loop started");
        while let Some(event) = rx.recv().await {
            self.process_event(&event);
        }
        info!("DGA analysis loop stopped");
    }

    fn process_event(&self, event: &DgaAnalysisEvent) {
        let apex = extract_apex(&event.domain);
        let sld = match apex.split('.').next() {
            Some(s) if s.len() > 3 => s,
            _ => return,
        };

        let now_ns = coarse_now_ns();
        let subnet_key = subnet_key_from_ip(event.client_ip);

        let entropy = shannon_entropy(sld.as_bytes());
        let (consonants, vowels, digits, total) = char_ratios(sld);
        let ngram_score = bigram_deviation_score(sld);

        let mut score = SignalScore::new();

        if entropy > self.config.sld_entropy_threshold {
            score.add(
                WEIGHT_SLD_ENTROPY,
                "sld_entropy",
                entropy,
                self.config.sld_entropy_threshold,
            );
        }

        let alpha = consonants + vowels;
        if alpha > 0 {
            let consonant_ratio = consonants as f32 / alpha as f32;
            if consonant_ratio > self.config.consonant_ratio_threshold {
                score.add(
                    WEIGHT_CONSONANT_RATIO,
                    "consonant_ratio",
                    consonant_ratio,
                    self.config.consonant_ratio_threshold,
                );
            }
        }

        if total > 0 {
            let digit_ratio = digits as f32 / total as f32;
            if digit_ratio > self.config.digit_ratio_threshold {
                score.add(
                    WEIGHT_DIGIT_RATIO,
                    "digit_ratio",
                    digit_ratio,
                    self.config.digit_ratio_threshold,
                );
            }
        }

        if sld.len() > self.config.sld_max_length {
            score.add(
                WEIGHT_SLD_LENGTH,
                "sld_length",
                sld.len() as f32,
                self.config.sld_max_length as f32,
            );
        }

        if ngram_score > self.config.ngram_score_threshold {
            score.add(
                WEIGHT_NGRAM_SCORE,
                "ngram_score",
                ngram_score,
                self.config.ngram_score_threshold,
            );
        }

        let entry = self
            .stats
            .entry(subnet_key)
            .or_insert_with(|| ClientDgaStats::new(now_ns));
        let stats = entry.value();

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

        // Only domains with at least one lexical signal count toward the client's DGA rate.
        if score.confidence > 0.0 {
            let dga_count = stats.dga_domain_count.fetch_add(1, Ordering::Relaxed) + 1;
            if dga_count > self.config.dga_rate_per_client {
                score.add(
                    WEIGHT_DGA_RATE,
                    "dga_rate",
                    dga_count as f32,
                    self.config.dga_rate_per_client as f32,
                );
            }
        }

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
                        "DGA domain detected — domain flagged"
                    );
                    self.flagged_domains.insert(Arc::from(apex), now_ns);
                }
            }
        }
    }
}

impl DgaFlagStore for DgaDetector {
    fn is_flagged(&self, domain: &str) -> bool {
        let apex = extract_apex(domain);
        self.flagged_domains.contains_key(apex)
    }
}

impl DgaEvictionTarget for DgaDetector {
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
                "DGA detector stale eviction"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn default_config() -> DgaDetectionConfig {
        DgaDetectionConfig::default()
    }

    fn stats_seen_at(last_seen_ns: u64) -> ClientDgaStats {
        ClientDgaStats {
            dga_domain_count: AtomicU32::new(1),
            last_seen_ns: AtomicU64::new(last_seen_ns),
            window_start_ns: AtomicU64::new(last_seen_ns),
        }
    }

    #[test]
    fn unknown_domain_not_flagged() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());
        assert!(!detector.is_flagged("example.com"));
    }

    #[test]
    fn flagged_domain_detected() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());
        detector
            .flagged_domains
            .insert(Arc::from("xjk4f9a2h.com"), coarse_now_ns());
        assert!(detector.is_flagged("xjk4f9a2h.com"));
        assert!(detector.is_flagged("sub.xjk4f9a2h.com"));
    }

    #[test]
    fn eviction_removes_stale_entries() {
        let mut config = default_config();
        config.stale_entry_ttl_secs = 0; // immediate expiry
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        detector.stats.insert(12345, stats_seen_at(0));
        detector.flagged_domains.insert(Arc::from("old.com"), 0);

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 0);
        assert_eq!(detector.flagged_domains.len(), 0);
    }

    #[test]
    fn eviction_keeps_fresh_entries() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());

        let now = coarse_now_ns();
        detector.stats.insert(12345, stats_seen_at(now));
        detector.flagged_domains.insert(Arc::from("fresh.com"), now);

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 1);
        assert_eq!(detector.flagged_domains.len(), 1);
    }

    #[test]
    fn eviction_keeps_entries_stamped_after_it_read_the_clock() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());

        let later = coarse_now_ns() + 60_000_000_000;
        detector.stats.insert(12345, stats_seen_at(later));
        detector
            .flagged_domains
            .insert(Arc::from("racing.com"), later);

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 1);
        assert_eq!(detector.flagged_domains.len(), 1);
    }

    #[test]
    fn eviction_with_unbounded_ttl_keeps_everything() {
        let mut config = default_config();
        config.stale_entry_ttl_secs = u64::MAX;
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        detector.stats.insert(12345, stats_seen_at(0));
        detector.flagged_domains.insert(Arc::from("old.com"), 0);

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 1);
        assert_eq!(detector.flagged_domains.len(), 1);
    }

    #[test]
    fn process_event_flags_random_domain() {
        let mut config = default_config();
        config.confidence_threshold = 0.35; // lower for test
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        let event = DgaAnalysisEvent {
            domain: Arc::from("xjk4f9a2h3b5c7d.com"),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        detector.process_event(&event);
        assert!(
            detector.is_flagged("xjk4f9a2h3b5c7d.com"),
            "Random-looking domain should be flagged"
        );
    }

    #[test]
    fn process_event_does_not_flag_normal_domain() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());

        let event = DgaAnalysisEvent {
            domain: Arc::from("google.com"),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        detector.process_event(&event);
        assert!(
            !detector.is_flagged("google.com"),
            "Normal domain should not be flagged"
        );
    }
}
