use ferrous_dns_api::utils::period_hours;

#[test]
fn converts_each_unit_to_hours() {
    assert_eq!(period_hours("30m"), 0.5);
    assert_eq!(period_hours("90m"), 1.5);
    assert_eq!(period_hours("48h"), 48.0);
    assert_eq!(period_hours("0.5h"), 0.5);
    assert_eq!(period_hours("7d"), 168.0);
    assert_eq!(period_hours("2w"), 336.0);
}

#[test]
fn caps_at_30_days() {
    assert_eq!(period_hours("720h"), 720.0);
    assert_eq!(period_hours("721h"), 720.0);
    assert_eq!(period_hours("5w"), 720.0);
}

#[test]
fn invalid_input_falls_back_to_24h() {
    for input in ["", "invalid", "24x", "h", "123", "abc123", "0h", "-1h"] {
        assert_eq!(period_hours(input), 24.0, "{input:?}");
    }
}

#[test]
fn multibyte_unit_falls_back_instead_of_panicking() {
    assert_eq!(period_hours("24é"), 24.0);
    assert_eq!(period_hours("é"), 24.0);
}

#[test]
fn nan_falls_back_instead_of_selecting_the_max_range() {
    assert_eq!(period_hours("NaNh"), 24.0);
}
