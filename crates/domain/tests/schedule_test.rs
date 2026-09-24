use chrono::NaiveTime;
use ferrous_dns_domain::{ScheduleProfile, TimeSlot};

#[test]
fn test_schedule_profile_validate_name_empty_returns_error() {
    let result = ScheduleProfile::validate_name("");
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_validate_name_valid() {
    let result = ScheduleProfile::validate_name("Kids Weeknight");
    assert!(result.is_ok());
}

#[test]
fn test_schedule_profile_validate_name_too_long_returns_error() {
    let long_name = "a".repeat(101);
    let result = ScheduleProfile::validate_name(&long_name);
    assert!(result.is_err());
}

#[test]
fn test_schedule_profile_parse_timezone_utc() {
    assert_eq!(ScheduleProfile::parse_timezone("UTC"), Ok(chrono_tz::UTC));
}

#[test]
fn test_schedule_profile_parse_timezone_iana() {
    assert_eq!(
        ScheduleProfile::parse_timezone("America/Sao_Paulo"),
        Ok(chrono_tz::America::Sao_Paulo)
    );
}

#[test]
fn test_schedule_profile_parse_timezone_empty_returns_error() {
    assert!(ScheduleProfile::parse_timezone("").is_err());
}

#[test]
fn test_schedule_profile_parse_timezone_unknown_name_returns_error() {
    for tz in ["Mars/Olympus", "america/sao_paulo", " UTC", "UTC+3"] {
        assert!(
            ScheduleProfile::parse_timezone(tz).is_err(),
            "{tz:?} accepted"
        );
    }
}

#[test]
fn test_time_slot_validate_days_zero_returns_error() {
    let result = TimeSlot::validate_days(0);
    assert!(result.is_err());
}

#[test]
fn test_time_slot_validate_days_max_127_is_valid() {
    let result = TimeSlot::validate_days(127);
    assert!(result.is_ok());
}

#[test]
fn test_time_slot_validate_days_above_127_returns_error() {
    let result = TimeSlot::validate_days(128);
    assert!(result.is_err());
}

#[test]
fn test_time_slot_parse_time_hhmm() {
    assert_eq!(TimeSlot::parse_time("00:00"), Ok(hm(0, 0)));
    assert_eq!(TimeSlot::parse_time("23:59"), Ok(hm(23, 59)));
    assert_eq!(TimeSlot::parse_time("17:30"), Ok(hm(17, 30)));
}

#[test]
fn test_time_slot_parse_time_invalid_returns_error() {
    for time in [
        "25:00",
        "24:00",
        "12:60",
        "1200",
        "",
        "9:00",
        "+9:05",
        "09:5",
        "09:+5",
        " 9:00",
        "09:00:00",
        "٠٩:٠٠",
    ] {
        assert!(TimeSlot::parse_time(time).is_err(), "{time:?} accepted");
    }
}

#[test]
fn test_time_slot_validate_time_range_start_before_end_is_ok() {
    let result = TimeSlot::validate_time_range(hm(8, 0), hm(17, 0));
    assert!(result.is_ok());
}

#[test]
fn test_time_slot_validate_time_range_start_equals_end_returns_error() {
    let result = TimeSlot::validate_time_range(hm(8, 0), hm(8, 0));
    assert!(result.is_err());
}

#[test]
fn test_time_slot_validate_time_range_start_after_end_returns_error() {
    let result = TimeSlot::validate_time_range(hm(17, 0), hm(8, 0));
    assert!(result.is_err());
}

fn hm(hour: u32, minute: u32) -> NaiveTime {
    NaiveTime::from_hms_opt(hour, minute, 0).unwrap()
}
