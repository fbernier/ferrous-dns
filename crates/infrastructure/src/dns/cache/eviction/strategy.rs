use ferrous_dns_domain::DomainError;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
    LRU,
    HitRate,
    LFU,
    LFUK,
}

impl FromStr for EvictionStrategy {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "lru" => Ok(Self::LRU),
            "hit_rate" | "hitrate" => Ok(Self::HitRate),
            "lfu" => Ok(Self::LFU),
            "lfu-k" | "lfuk" => Ok(Self::LFUK),
            _ => Err(DomainError::ConfigError(format!(
                "invalid eviction strategy: {s}"
            ))),
        }
    }
}

impl EvictionStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LRU => "lru",
            Self::HitRate => "hit_rate",
            Self::LFU => "lfu",
            Self::LFUK => "lfu-k",
        }
    }
}
