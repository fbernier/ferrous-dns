use ferrous_dns_application::use_cases::dns::domain_heuristics::extract_apex;

/// The labels before the apex (`sub.example.co.uk` → `sub`), or `None` when
/// `domain` is its own apex.
pub fn extract_subdomain(domain: &str) -> Option<&str> {
    let apex = extract_apex(domain);
    // Excludes the dot joining the subdomain to the apex.
    let prefix_len = domain.len().checked_sub(apex.len() + 1)?;
    (prefix_len > 0).then(|| &domain[..prefix_len])
}
