use chrono::{Days, NaiveDate, NaiveDateTime, NaiveTime};
use ferrous_dns_domain::{evaluate_slots, ScheduleAction, TimeSlot};

fn make_slot(days: u8, start: &str, end: &str, action: ScheduleAction) -> TimeSlot {
    TimeSlot {
        id: None,
        profile_id: 1,
        days,
        start_time: TimeSlot::parse_time(start).unwrap(),
        end_time: TimeSlot::parse_time(end).unwrap(),
        action,
        created_at: None,
    }
}

/// Local wall-clock time on weekday `index` (0 = Mon .. 6 = Sun) at `HH:MM[:SS]`.
fn at(index: u64, time: &str) -> NaiveDateTime {
    let monday = NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
    let time = NaiveTime::parse_from_str(time, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(time, "%H:%M"))
        .unwrap();
    (monday + Days::new(index)).and_time(time)
}

#[test]
fn test_evaluate_slots_empty_list_returns_none() {
    assert_eq!(evaluate_slots(&[], at(0, "10:00")), None);
}

#[test]
fn test_evaluate_slots_day_not_matching_returns_none() {
    let monday_only = make_slot(0b0000001, "09:00", "18:00", ScheduleAction::BlockAll);
    assert_eq!(evaluate_slots(&[monday_only], at(1, "10:00")), None);
}

#[test]
fn test_evaluate_slots_time_after_end_returns_none() {
    let slot = make_slot(0b0000001, "09:00", "18:00", ScheduleAction::BlockAll);
    assert_eq!(evaluate_slots(&[slot], at(0, "20:00")), None);
}

#[test]
fn test_evaluate_slots_time_before_start_returns_none() {
    let slot = make_slot(0b1111111, "09:00", "18:00", ScheduleAction::BlockAll);
    assert_eq!(evaluate_slots(&[slot], at(2, "08:59")), None);
}

#[test]
fn test_evaluate_slots_time_at_end_is_exclusive_returns_none() {
    let slot = make_slot(0b1111111, "09:00", "18:00", ScheduleAction::AllowAll);
    assert_eq!(evaluate_slots(&[slot], at(2, "18:00")), None);
}

#[test]
fn test_evaluate_slots_last_second_before_end_matches() {
    let slot = make_slot(0b1111111, "09:00", "18:00", ScheduleAction::AllowAll);
    assert_eq!(
        evaluate_slots(&[slot], at(2, "17:59:59")),
        Some(ScheduleAction::AllowAll)
    );
}

#[test]
fn test_evaluate_slots_sunday_uses_bit_six() {
    let sunday_only = make_slot(0b1000000, "09:00", "18:00", ScheduleAction::BlockAll);
    assert_eq!(
        evaluate_slots(std::slice::from_ref(&sunday_only), at(6, "10:00")),
        Some(ScheduleAction::BlockAll)
    );
    assert_eq!(evaluate_slots(&[sunday_only], at(5, "10:00")), None);
}

#[test]
fn test_evaluate_slots_single_block_slot_returns_block_all() {
    let slot = make_slot(0b1111111, "21:00", "23:59", ScheduleAction::BlockAll);
    assert_eq!(
        evaluate_slots(&[slot], at(3, "22:00")),
        Some(ScheduleAction::BlockAll)
    );
}

#[test]
fn test_evaluate_slots_single_allow_slot_returns_allow_all() {
    let slot = make_slot(0b1111111, "17:00", "20:00", ScheduleAction::AllowAll);
    assert_eq!(
        evaluate_slots(&[slot], at(4, "18:30")),
        Some(ScheduleAction::AllowAll)
    );
}

#[test]
fn test_evaluate_slots_block_wins_over_allow_on_overlap() {
    let allow = make_slot(0b1111111, "17:00", "20:00", ScheduleAction::AllowAll);
    let block = make_slot(0b1111111, "17:00", "18:00", ScheduleAction::BlockAll);
    assert_eq!(
        evaluate_slots(&[allow, block], at(0, "17:30")),
        Some(ScheduleAction::BlockAll)
    );
}

#[test]
fn test_evaluate_slots_allow_only_no_conflicts_returns_allow_all() {
    let weekdays = make_slot(0b0011111, "17:00", "20:00", ScheduleAction::AllowAll);
    let weekend = make_slot(0b1100000, "12:00", "22:00", ScheduleAction::AllowAll);
    assert_eq!(
        evaluate_slots(&[weekdays, weekend], at(5, "15:00")),
        Some(ScheduleAction::AllowAll)
    );
}

#[test]
fn test_evaluate_slots_multiple_days_matches_correct_day() {
    let weekdays = make_slot(0b0011111, "08:00", "17:00", ScheduleAction::BlockAll);
    let slots = [weekdays];
    assert_eq!(
        evaluate_slots(&slots, at(1, "12:00")),
        Some(ScheduleAction::BlockAll)
    );
    assert_eq!(evaluate_slots(&slots, at(5, "12:00")), None);
}
