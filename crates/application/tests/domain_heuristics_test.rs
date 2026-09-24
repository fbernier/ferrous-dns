use ferrous_dns_application::use_cases::dns::domain_heuristics::{extract_apex, shannon_entropy};

#[test]
fn entropy_is_zero_without_variety() {
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy(b"aaaa"), 0.0);
}

#[test]
fn two_equal_chars_carry_one_bit() {
    let e = shannon_entropy(b"ab");
    assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
}

#[test]
fn encoded_payloads_score_above_words() {
    for word in [b"google".as_slice(), b"www"] {
        let e = shannon_entropy(word);
        assert!(
            e < 2.6,
            "{}: expected < 2.6, got {e}",
            String::from_utf8_lossy(word)
        );
    }
    for payload in [
        b"a3f8d2e1b7c4a9f0".as_slice(),
        b"dGhpcyBpcyBhIHRlc3Q=",
        b"mfzwizltoq2gk3djorugk",
    ] {
        let e = shannon_entropy(payload);
        assert!(
            e > 3.0,
            "{}: expected > 3.0, got {e}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn apex_is_the_last_two_labels() {
    assert_eq!(extract_apex("example.com"), "example.com");
    assert_eq!(extract_apex("sub.example.com"), "example.com");
    assert_eq!(extract_apex("a.b.c.example.com"), "example.com");
    assert_eq!(extract_apex("localhost"), "localhost");
}

#[test]
fn apex_preserves_case() {
    assert_eq!(extract_apex("Sub.Example.COM"), "Example.COM");
}

#[test]
fn apex_under_a_compound_suffix_takes_three_labels() {
    assert_eq!(extract_apex("sub.example.co.uk"), "example.co.uk");
    assert_eq!(extract_apex("data.corp.com.br"), "corp.com.br");
    assert_eq!(extract_apex("sub.example.CO.UK"), "example.CO.UK");
}
