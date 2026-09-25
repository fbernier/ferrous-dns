const DEFAULT_PERIOD_HOURS: f32 = 24.0;
const MAX_PERIOD_HOURS: f32 = 720.0;

pub fn default_period() -> String {
    "24h".to_string()
}

/// Hours covered by a `period` query value (`30m`, `24h`, `7d`, `2w`), capped
/// at 30 days; empty or invalid input yields the 24h default.
pub fn period_hours(period: &str) -> f32 {
    parse_period(period).map_or(DEFAULT_PERIOD_HOURS, |hours| hours.min(MAX_PERIOD_HOURS))
}

fn parse_period(period: &str) -> Option<f32> {
    let unit = period.chars().next_back()?;
    let num: f32 = period[..period.len() - unit.len_utf8()].parse().ok()?;

    if num.is_nan() || num <= 0.0 {
        return None;
    }

    match unit {
        'm' => Some(num / 60.0),
        'h' => Some(num),
        'd' => Some(num * 24.0),
        'w' => Some(num * 24.0 * 7.0),
        _ => None,
    }
}
