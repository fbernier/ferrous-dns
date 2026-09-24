use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::dnssec::{
    crypto, DnskeyRecord, DnssecCache, DsRecord, RrsigRecord,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

#[test]
fn cache_serves_unexpired_sets_and_drops_expired_ones() {
    let cache = DnssecCache::new();
    let key = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };

    cache.cache_dnskey("fresh.example.", vec![key.clone()], 300);
    cache.cache_dnskey("expired.example.", vec![key], 0);
    cache.cache_ds("expired.example.", Vec::new(), 0);

    assert_eq!(cache.get_dnskey("fresh.example.").unwrap().len(), 1);
    assert!(cache.get_dnskey("expired.example.").is_none());
    assert!(cache.get_ds("expired.example.").is_none());

    let stats = cache.stats();
    assert_eq!(stats.total_dnskey_hits, 1);
    assert_eq!(stats.total_dnskey_misses, 1);
    assert_eq!(stats.total_ds_misses, 1);
    assert_eq!(
        stats.dnskey_entries, 1,
        "expired entry is removed on lookup"
    );
    assert_eq!(stats.ds_entries, 0);
}

#[test]
fn key_tag_of_an_oversized_key_does_not_overflow() {
    // Trust anchor files are not RDLENGTH-bounded, so the sum must not overflow.
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![0xFF; 140_000],
    };

    let _ = dnskey.calculate_key_tag();
}

#[test]
fn test_verify_ds_key_tag_mismatch() {
    let ds = DsRecord {
        key_tag: 9999,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0u8; 32],
    };

    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };

    // Different key_tag → must return false without computing digest
    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_algorithm_mismatch() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 13, // Different algorithm than dnskey.algorithm (8)
        digest_type: 2,
        digest: vec![0u8; 32],
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result);
}

#[test]
fn test_verify_ds_wrong_digest() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB, 0xCD],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 8,
        digest_type: 2,
        digest: vec![0u8; 32], // Wrong digest (all zeros)
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.").unwrap();
    assert!(!result, "Wrong digest should not match");
}

#[test]
fn test_verify_ds_unsupported_digest_type() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1],
    };
    let key_tag = dnskey.calculate_key_tag();

    let ds = DsRecord {
        key_tag,
        algorithm: 8,
        digest_type: 99, // Unsupported
        digest: vec![0u8; 20],
    };

    let result = crypto::verify_ds(&ds, &dnskey, "example.com.");
    assert!(
        result.is_err(),
        "Unsupported digest type should return error"
    );
}

#[test]
fn test_is_supported_algorithm_matches_dispatch_arms() {
    // The RFC 6840 §5.2 "insecure, not bogus" decision in `validate_delegation`
    // keys off this predicate, so it MUST stay in lockstep with the algorithms
    // `verify_rrsig_with_name` can actually dispatch. Supported today: RSA/SHA-1
    // (5,7), RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256/P-384 (13,14),
    // Ed25519 (15). Notably Ed448 (16) is NOT implemented.
    for alg in [5, 7, 8, 10, 13, 14, 15] {
        assert!(
            crypto::is_supported_algorithm(alg),
            "algorithm {alg} should be reported as supported"
        );
    }
    for alg in [0, 1, 3, 6, 12, 16, 17, 252, 253, 254] {
        assert!(
            !crypto::is_supported_algorithm(alg),
            "algorithm {alg} should be reported as unsupported"
        );
    }
}

#[test]
fn test_verify_rrsig_expired_signature() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB],
    };
    let key_tag = dnskey.calculate_key_tag();

    let rrsig = RrsigRecord {
        type_covered: RecordType::A,
        algorithm: 8,
        labels: 2,
        original_ttl: 300,
        signature_expiration: 1000,
        signature_inception: 1,
        key_tag,
        signer_name: "example.com.".to_string(),
        signature: vec![0u8; 64],
    };

    let result = crypto::verify_rrsig(&rrsig, &dnskey, "example.com.", &[], now_secs()).unwrap();
    assert!(!result, "Expired RRSIG should return false");
}

#[test]
fn test_verify_rrsig_key_tag_mismatch() {
    let dnskey = DnskeyRecord {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: vec![3, 1, 0, 1, 0xAB],
    };

    let now = now_secs();

    let rrsig = RrsigRecord {
        type_covered: RecordType::A,
        algorithm: 8,
        labels: 2,
        original_ttl: 300,
        signature_expiration: now + 3600,
        signature_inception: now - 60,
        key_tag: 9999, // Deliberately wrong key_tag
        signer_name: "example.com.".to_string(),
        signature: vec![0u8; 64],
    };

    let result = crypto::verify_rrsig(&rrsig, &dnskey, "example.com.", &[], now).unwrap();
    assert!(!result, "Key tag mismatch should return false");
}
