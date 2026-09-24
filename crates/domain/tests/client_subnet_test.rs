use ferrous_dns_domain::{ClientSubnet, SubnetMatcher};
use std::net::IpAddr;

#[test]
fn test_client_subnet_validate_cidr_missing_mask() {
    let result = ClientSubnet::validate_cidr("192.168.1.0");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must include prefix"));
}

#[test]
fn test_client_subnet_validate_cidr_empty() {
    let result = ClientSubnet::validate_cidr("");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("cannot be empty"));
}

#[test]
fn test_client_subnet_validate_cidr_valid() {
    let result = ClientSubnet::validate_cidr("192.168.1.0/24");
    assert!(result.is_ok());
}

#[test]
fn test_subnet_matcher_finds_match() {
    let subnets = vec![
        ClientSubnet::new("192.168.1.0/24".to_string(), 2, None),
        ClientSubnet::new("10.0.0.0/8".to_string(), 3, None),
    ];

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
        ClientSubnet::new("10.0.0.0/8".to_string(), 3, None),
        ClientSubnet::new("10.1.0.0/16".to_string(), 4, None),
        ClientSubnet::new("10.1.1.0/24".to_string(), 5, None),
    ];

    let matcher = SubnetMatcher::new(subnets).unwrap();

    let ip: IpAddr = "10.1.1.50".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip), Some(5));
}

#[test]
fn equal_prefix_overlap_resolves_to_the_first_subnet() {
    let subnets = vec![
        ClientSubnet::new("10.0.0.0/8".to_string(), 7, None),
        ClientSubnet::new("10.0.0.0/8".to_string(), 8, None),
    ];
    let matcher = SubnetMatcher::new(subnets).unwrap();
    assert_eq!(
        matcher.find_group_for_ip("10.2.3.4".parse().unwrap()),
        Some(7)
    );
}
