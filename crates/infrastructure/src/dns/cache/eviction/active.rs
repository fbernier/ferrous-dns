use super::strategy::EvictionStrategy;

/// Scores an entry for eviction; the lowest score goes first.
pub enum ActiveEvictionPolicy {
    Lru,
    HitRate,
    Lfu { min_frequency: u64 },
    Lfuk { min_lfuk_score: f64, k_value: f64 },
}

impl ActiveEvictionPolicy {
    pub fn from_config(
        strategy: EvictionStrategy,
        min_frequency: u64,
        min_lfuk_score: f64,
        lfuk_k_value: f64,
    ) -> Self {
        match strategy {
            EvictionStrategy::LRU => Self::Lru,
            EvictionStrategy::HitRate => Self::HitRate,
            EvictionStrategy::LFU => Self::Lfu { min_frequency },
            EvictionStrategy::LFUK => Self::Lfuk {
                min_lfuk_score,
                k_value: lfuk_k_value,
            },
        }
    }

    /// `last_access`, `inserted_at` and `now_secs` are coarse-clock seconds.
    pub fn score(&self, hit_count: u64, last_access: u64, inserted_at: u64, now_secs: u64) -> f64 {
        match *self {
            Self::Lru => last_access as f64,
            Self::HitRate => {
                let age_secs = now_secs.saturating_sub(last_access) as f64;
                let recency = 1.0 / (age_secs + 1.0);
                ((hit_count as f64) / (hit_count + 1) as f64) * recency
            }
            Self::Lfu { min_frequency } => {
                if min_frequency > 0 && hit_count < min_frequency {
                    -(min_frequency as f64 - hit_count as f64)
                } else {
                    hit_count as f64
                }
            }
            Self::Lfuk {
                min_lfuk_score,
                k_value,
            } => {
                let hits = hit_count as f64;
                if hits == 0.0 {
                    return min_lfuk_score;
                }
                let age_secs = now_secs.saturating_sub(inserted_at).max(1) as f64;
                let idle_secs = now_secs.saturating_sub(last_access) as f64;
                let age_decay = if (k_value - 0.5).abs() < f64::EPSILON {
                    age_secs.sqrt().max(1.0)
                } else {
                    age_secs.powf(k_value).max(1.0)
                };
                let score = hits / age_decay * (1.0 / (idle_secs + 1.0));
                if min_lfuk_score > 0.0 && score < min_lfuk_score {
                    score - min_lfuk_score
                } else {
                    score
                }
            }
        }
    }
}
