use ferrous_dns_domain::{ClientSubnet, SubnetMatcher};
use std::net::IpAddr;
use std::sync::Arc;

fn subnet(cidr: &str, group_id: i64) -> ClientSubnet {
    ClientSubnet {
        id: None,
        subnet_cidr: Arc::from(cidr),
        group_id,
        comment: None,
        created_at: None,
        updated_at: None,
    }
}

#[test]
fn test_client_subnet_parse_cidr_missing_mask() {
    let result = ClientSubnet::parse_cidr("192.168.1.0");

    assert!(result.unwrap_err().contains("must include prefix"));
}

#[test]
fn test_client_subnet_parse_cidr_empty() {
    let result = ClientSubnet::parse_cidr("");

    assert!(result.unwrap_err().contains("cannot be empty"));
}

#[test]
fn test_client_subnet_parse_cidr_rejects_garbage() {
    assert!(ClientSubnet::parse_cidr("192.168.1.0/33").is_err());
    assert!(ClientSubnet::parse_cidr("not-an-ip/24").is_err());
}

#[test]
fn test_client_subnet_parse_cidr_canonicalises_network() {
    let parse = |s: &str| ClientSubnet::parse_cidr(s).unwrap().to_string();

    assert_eq!(parse("192.168.1.0/24"), "192.168.1.0/24");
    assert_eq!(parse("192.168.1.5/24"), "192.168.1.0/24");
    assert_eq!(parse("2001:DB8:0:0::1/32"), "2001:db8::/32");
    assert_eq!(parse("2001:db8::/32"), "2001:db8::/32");
}

#[test]
fn test_subnet_matcher_finds_match() {
    let subnets = vec![subnet("192.168.1.0/24", 2), subnet("10.0.0.0/8", 3)];

    let matcher = SubnetMatcher::new(subnets).unwrap();

    let ip: IpAddr = "192.168.1.50".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip), Some(2));

    let ip2: IpAddr = "10.5.10.20".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip2), Some(3));

    let ip3: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip3), None);
}

#[test]
fn test_subnet_matcher_most_specific_wins() {
    let subnets = vec![
        subnet("10.0.0.0/8", 3),
        subnet("10.1.0.0/16", 4),
        subnet("10.1.1.0/24", 5),
    ];

    let matcher = SubnetMatcher::new(subnets).unwrap();

    let ip: IpAddr = "10.1.1.50".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip), Some(5));
}

#[test]
fn equal_prefix_overlap_resolves_to_the_first_subnet() {
    let subnets = vec![subnet("10.0.0.0/8", 7), subnet("10.0.0.0/8", 8)];
    let matcher = SubnetMatcher::new(subnets).unwrap();
    assert_eq!(
        matcher.find_group_for_ip("10.2.3.4".parse().unwrap()),
        Some(7)
    );
}
