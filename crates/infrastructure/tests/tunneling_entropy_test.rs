use ferrous_dns_infrastructure::dns::tunneling::entropy::extract_subdomain;

#[test]
fn extract_subdomain_returns_none_for_apex() {
    assert_eq!(extract_subdomain("example.com"), None);
}

#[test]
fn extract_subdomain_returns_none_for_single_label() {
    assert_eq!(extract_subdomain("localhost"), None);
}

#[test]
fn extract_subdomain_returns_single_label_before_apex() {
    assert_eq!(extract_subdomain("sub.example.com"), Some("sub"));
}

#[test]
fn extract_subdomain_returns_multiple_labels_before_apex() {
    assert_eq!(extract_subdomain("foo.bar.example.com"), Some("foo.bar"));
}

#[test]
fn extract_subdomain_deeply_nested() {
    assert_eq!(extract_subdomain("a.b.c.d.example.com"), Some("a.b.c.d"));
}

#[test]
fn extract_subdomain_with_compound_tld() {
    assert_eq!(extract_subdomain("sub.example.co.uk"), Some("sub"));
}

#[test]
fn extract_subdomain_returns_none_for_compound_apex() {
    assert_eq!(extract_subdomain("example.co.uk"), None);
}
