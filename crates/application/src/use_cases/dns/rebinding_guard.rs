use crate::ports::DnsResolution;
use ferrous_dns_domain::PrivateIpFilter;

/// Guards DNS responses against DNS rebinding attacks.
///
/// Blocks resolutions where a public domain resolves to a private/RFC1918 IP address,
/// with configurable exemptions for local domains and explicitly allowlisted entries.
pub(super) struct RebindingGuard {
    /// `.{local_domain}`, lowercased.
    local_domain_suffix: Option<Box<str>>,
    allowlist: Box<[Box<str>]>,
}

impl RebindingGuard {
    /// Subdomains of `local_domain` (e.g. `"local"`) and exact `allowlist` names are exempt.
    pub(super) fn new(local_domain: Option<&str>, allowlist: &[String]) -> Self {
        Self {
            local_domain_suffix: local_domain.map(|d| format!(".{}", d.to_lowercase()).into()),
            allowlist: allowlist.iter().map(|s| s.to_lowercase().into()).collect(),
        }
    }

    /// Returns `true` when the resolution should be blocked as a rebinding attempt.
    pub(super) fn is_rebinding_attempt(&self, domain: &str, resolution: &DnsResolution) -> bool {
        if resolution.local_dns {
            return false;
        }
        if let Some(ref suffix) = self.local_domain_suffix {
            let exact = suffix.trim_start_matches('.');
            if domain.eq_ignore_ascii_case(exact)
                || domain
                    .get(domain.len().saturating_sub(suffix.len())..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
            {
                return false;
            }
        }
        if self
            .allowlist
            .iter()
            .any(|allowed| domain.eq_ignore_ascii_case(allowed))
        {
            return false;
        }
        resolution
            .addresses
            .iter()
            .any(PrivateIpFilter::is_private_ip)
    }
}
