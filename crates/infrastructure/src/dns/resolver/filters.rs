use ferrous_dns_domain::{DnsQuery, DomainError, FqdnFilter, PrivateIpFilter};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::debug;

/// What happens to a single-label (non-FQDN) query name.
#[derive(Clone)]
pub enum NonFqdn {
    Block,
    /// Append this local domain.
    Qualify(String),
    Pass,
}

#[derive(Clone)]
pub struct QueryFilters {
    block_private_ptr: bool,
    non_fqdn: NonFqdn,
}

impl QueryFilters {
    /// `block_private_ptr` must already be off when a local DNS server answers
    /// private PTRs.
    pub fn new(block_private_ptr: bool, non_fqdn: NonFqdn) -> Self {
        Self {
            block_private_ptr,
            non_fqdn,
        }
    }

    pub fn apply(&self, mut query: DnsQuery) -> Result<DnsQuery, DomainError> {
        match self.decide(&query.domain) {
            Ok(Cow::Borrowed(_)) => Ok(query),
            Ok(Cow::Owned(qualified)) => {
                debug!(
                    original = %query.domain,
                    qualified = %qualified,
                    "Appending local domain to non-FQDN query"
                );
                query.domain = Arc::from(qualified);
                Ok(query)
            }
            Err(reason) => Err(DomainError::FilteredQuery(format!(
                "{reason}: {}",
                query.domain
            ))),
        }
    }

    /// Same decision as [`apply`](Self::apply) on a borrowed name, so the cache
    /// fast path pays no `Arc` allocation. `None` means the query is dropped.
    pub fn apply_str<'a>(&self, domain: &'a str) -> Option<Cow<'a, str>> {
        self.decide(domain).ok()
    }

    fn decide<'a>(&self, domain: &'a str) -> Result<Cow<'a, str>, &'static str> {
        if self.block_private_ptr && PrivateIpFilter::is_private_ptr_query(domain) {
            return Err("Private PTR query blocked");
        }

        match &self.non_fqdn {
            NonFqdn::Block if FqdnFilter::is_local_hostname(domain) => {
                Err("Non-FQDN query blocked")
            }
            NonFqdn::Qualify(local_domain) if !domain.contains('.') => {
                Ok(Cow::Owned(format!("{domain}.{local_domain}")))
            }
            NonFqdn::Block | NonFqdn::Qualify(_) | NonFqdn::Pass => Ok(Cow::Borrowed(domain)),
        }
    }
}
