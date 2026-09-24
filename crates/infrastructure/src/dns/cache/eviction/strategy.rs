#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionStrategy {
    LRU,
    HitRate,
    LFU,
    LFUK,
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
