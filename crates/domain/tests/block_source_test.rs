use ferrous_dns_domain::BlockSource;

#[test]
fn codes_and_names_round_trip_for_every_variant() {
    for (code, source) in BlockSource::ALL.into_iter().enumerate() {
        assert_eq!(usize::from(source.as_u8()), code, "{source}");
        assert_eq!(BlockSource::from_u8(source.as_u8()), Some(source));
        assert_eq!(source.to_str().parse::<BlockSource>().ok(), Some(source));
    }
    let past_end = u8::try_from(BlockSource::ALL.len()).unwrap();
    assert_eq!(BlockSource::from_u8(past_end), None);
    assert!("Blocklist".parse::<BlockSource>().is_err());
}
