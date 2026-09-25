use serde::{Deserialize, Deserializer};

/// Group ids for a new source: a non-empty `group_ids` wins over the legacy
/// single `group_id`; with neither, the source goes to `default_group_id`.
pub fn create_group_ids(
    group_ids: Option<Vec<i64>>,
    group_id: Option<i64>,
    default_group_id: i64,
) -> Vec<i64> {
    match group_ids {
        Some(ids) if !ids.is_empty() => ids,
        _ => vec![group_id.unwrap_or(default_group_id)],
    }
}

/// Group ids update: `group_ids` (even empty) wins over the legacy `group_id`;
/// `None` leaves the groups unchanged.
pub fn update_group_ids(group_ids: Option<Vec<i64>>, group_id: Option<i64>) -> Option<Vec<i64>> {
    group_ids.or_else(|| group_id.map(|gid| vec![gid]))
}

/// With `#[serde(default)]`, tells an absent field (`None`) from an explicit
/// `null` (`Some(None)`).
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
