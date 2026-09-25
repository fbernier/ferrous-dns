use crate::errors::domain_error::DomainError;
use crate::value_objects::validators::exceeds_chars;
use chrono::{Datelike, NaiveDateTime, NaiveTime};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAction {
    BlockAll,
    AllowAll,
}

impl ScheduleAction {
    pub fn to_str(self) -> &'static str {
        match self {
            ScheduleAction::BlockAll => "block_all",
            ScheduleAction::AllowAll => "allow_all",
        }
    }
}

impl std::str::FromStr for ScheduleAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block_all" => Ok(ScheduleAction::BlockAll),
            "allow_all" => Ok(ScheduleAction::AllowAll),
            other => Err(DomainError::InvalidInput(format!(
                "unknown schedule action: '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScheduleProfile {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub timezone: Tz,
    pub comment: Option<Arc<str>>,
    pub created_at: Option<Arc<str>>,
    pub updated_at: Option<Arc<str>>,
}

impl ScheduleProfile {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("name cannot be empty".into());
        }
        if exceeds_chars(name, 100) {
            return Err("name cannot exceed 100 characters".into());
        }
        Ok(())
    }

    pub fn parse_timezone(tz: &str) -> Result<Tz, String> {
        if tz.is_empty() {
            return Err("timezone cannot be empty".into());
        }
        tz.parse::<Tz>()
            .map_err(|_| format!("unknown IANA timezone '{tz}'"))
    }
}

#[derive(Debug, Clone)]
pub struct TimeSlot {
    pub id: Option<i64>,
    pub profile_id: i64,
    pub days: u8,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
    pub action: ScheduleAction,
    pub created_at: Option<Arc<str>>,
}

impl TimeSlot {
    /// Wire format of slot times in the API and the `time_slots` columns.
    pub const TIME_FORMAT: &'static str = "%H:%M";

    pub fn validate_days(days: u8) -> Result<(), String> {
        if days == 0 {
            return Err("at least one day must be selected".into());
        }
        if days > 127 {
            return Err(format!("days bitmask must be 1–127, got {days}"));
        }
        Ok(())
    }

    /// Accepts only zero-padded `HH:MM`, the exact form written to the API and database.
    pub fn parse_time(time: &str) -> Result<NaiveTime, String> {
        let &[h1, h2, b':', m1, m2] = time.as_bytes() else {
            return Err(format!("time must be in HH:MM format, got '{time}'"));
        };
        if ![h1, h2, m1, m2].iter().all(u8::is_ascii_digit) {
            return Err(format!("time must be in HH:MM format, got '{time}'"));
        }
        let hours = u32::from(h1 - b'0') * 10 + u32::from(h2 - b'0');
        let minutes = u32::from(m1 - b'0') * 10 + u32::from(m2 - b'0');
        NaiveTime::from_hms_opt(hours, minutes, 0)
            .ok_or_else(|| format!("time must be between 00:00 and 23:59, got '{time}'"))
    }

    pub fn validate_time_range(start_time: NaiveTime, end_time: NaiveTime) -> Result<(), String> {
        if start_time >= end_time {
            return Err(format!(
                "start_time '{}' must be before end_time '{}'",
                start_time.format(Self::TIME_FORMAT),
                end_time.format(Self::TIME_FORMAT)
            ));
        }
        Ok(())
    }
}

/// `now` is the wall-clock time in the profile's timezone; slots are `[start, end)`.
pub fn evaluate_slots(slots: &[TimeSlot], now: NaiveDateTime) -> Option<ScheduleAction> {
    let weekday_bit = 1u8 << now.weekday().num_days_from_monday();
    let time = now.time();
    let mut found_allow = false;
    for slot in slots {
        if slot.days & weekday_bit == 0 {
            continue;
        }
        if time < slot.start_time || time >= slot.end_time {
            continue;
        }
        match slot.action {
            ScheduleAction::BlockAll => return Some(ScheduleAction::BlockAll),
            ScheduleAction::AllowAll => found_allow = true,
        }
    }
    if found_allow {
        Some(ScheduleAction::AllowAll)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOverride {
    BlockAll,
    AllowAll,
    TimedBypassUntil(u64),
    TimedBlockUntil(u64),
}
