use crate::DomainError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// `[dns] cache_eviction_strategy`: which cached entries a full cache drops first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheEvictionStrategy {
    /// Least recently used.
    Lru,
    /// Fewest hits per minute since insertion.
    #[default]
    HitRate,
    /// Fewest hits overall.
    Lfu,
    /// LFU-K: hit frequency over a sliding window.
    LfuK,
}

impl CacheEvictionStrategy {
    /// Config, API and backup spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lru => "lru",
            Self::HitRate => "hit_rate",
            Self::Lfu => "lfu",
            Self::LfuK => "lfu-k",
        }
    }
}

impl fmt::Display for CacheEvictionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CacheEvictionStrategy {
    type Err = DomainError;

    /// Case-insensitive; also accepts `hitrate` and `lfuk`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "lru" => Ok(Self::Lru),
            "hit_rate" | "hitrate" => Ok(Self::HitRate),
            "lfu" => Ok(Self::Lfu),
            "lfu-k" | "lfuk" => Ok(Self::LfuK),
            _ => Err(DomainError::ConfigError(format!(
                "invalid cache_eviction_strategy '{s}': expected lru, hit_rate, lfu or lfu-k"
            ))),
        }
    }
}

impl Serialize for CacheEvictionStrategy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CacheEvictionStrategy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    struct Holder {
        strategy: CacheEvictionStrategy,
    }

    #[test]
    fn accepts_every_spelling_the_cache_ever_honoured() {
        for (name, expected) in [
            ("lru", CacheEvictionStrategy::Lru),
            ("LRU", CacheEvictionStrategy::Lru),
            ("hit_rate", CacheEvictionStrategy::HitRate),
            ("HitRate", CacheEvictionStrategy::HitRate),
            ("lfu", CacheEvictionStrategy::Lfu),
            ("lfu-k", CacheEvictionStrategy::LfuK),
            ("LFUK", CacheEvictionStrategy::LfuK),
        ] {
            let holder: Holder = toml::from_str(&format!("strategy = \"{name}\"")).unwrap();
            assert_eq!(holder.strategy, expected, "{name}");
        }
    }

    #[test]
    fn unknown_strategy_fails_to_load_naming_the_value() {
        let err = toml::from_str::<Holder>("strategy = \"fifo\"").unwrap_err();
        assert!(err.to_string().contains("fifo"), "{err}");
    }

    #[test]
    fn writes_the_canonical_name_and_reads_it_back() {
        for strategy in [
            CacheEvictionStrategy::Lru,
            CacheEvictionStrategy::HitRate,
            CacheEvictionStrategy::Lfu,
            CacheEvictionStrategy::LfuK,
        ] {
            let written = toml::to_string(&Holder { strategy }).unwrap();
            assert_eq!(written.trim(), format!("strategy = \"{strategy}\""));
            let back: Holder = toml::from_str(&written).unwrap();
            assert_eq!(back.strategy, strategy);
        }
    }
}
