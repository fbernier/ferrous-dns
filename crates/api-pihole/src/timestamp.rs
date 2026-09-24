use chrono::{DateTime, NaiveDateTime};

/// Parses an RFC 3339 timestamp, or a SQLite `YYYY-MM-DD HH:MM:SS[.fff]` one
/// taken as UTC, into a Unix epoch.
pub(crate) fn parse_unix_epoch(ts: &str) -> Option<i64> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.timestamp());
    }
    NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S%.f")
        .ok()
        .map(|dt| dt.and_utc().timestamp())
}

#[cfg(test)]
mod tests {
    use super::parse_unix_epoch;

    #[test]
    fn sqlite_timestamps_are_utc() {
        assert_eq!(parse_unix_epoch("2024-01-15 12:30:00"), Some(1_705_321_800));
        assert_eq!(
            parse_unix_epoch("2024-01-15 12:30:00.250"),
            Some(1_705_321_800)
        );
    }

    #[test]
    fn rfc3339_offsets_are_honoured() {
        assert_eq!(
            parse_unix_epoch("2024-01-15T12:30:00Z"),
            Some(1_705_321_800)
        );
        assert_eq!(
            parse_unix_epoch("2024-01-15T14:30:00+02:00"),
            Some(1_705_321_800)
        );
    }
}
