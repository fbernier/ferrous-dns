#[derive(Clone)]
pub struct ResolverConfig {
    pub cache_ttl: u32,

    pub inflight_shards: usize,

    pub query_timeout_ms: u64,

    pub dnssec_enabled: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            cache_ttl: 3600,
            inflight_shards: 64,
            query_timeout_ms: 2000,
            dnssec_enabled: false,
        }
    }
}

impl ResolverConfig {
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.query_timeout_ms = timeout_ms;
        self
    }

    pub fn with_dnssec(mut self) -> Self {
        self.dnssec_enabled = true;
        self
    }
}
