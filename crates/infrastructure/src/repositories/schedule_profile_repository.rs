use crate::repositories::{db_err, is_fk_violation, is_unique_violation};
use async_trait::async_trait;
use chrono::NaiveTime;
use chrono_tz::Tz;
use ferrous_dns_application::ports::ScheduleProfileRepository;
use ferrous_dns_domain::{DomainError, ScheduleAction, ScheduleProfile, TimeSlot};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::warn;

type ProfileRow = (i64, String, String, Option<String>, String, String);
type SlotRow = (i64, i64, i64, String, String, String, String);

pub struct SqliteScheduleProfileRepository {
    pool: SqlitePool,
}

impl SqliteScheduleProfileRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_profile(row: ProfileRow) -> ScheduleProfile {
        let (id, name, timezone, comment, created_at, updated_at) = row;
        // An unparsable stored name falls back to UTC so the profile stays readable and enforced.
        let timezone = ScheduleProfile::parse_timezone(&timezone).unwrap_or_else(|e| {
            warn!(profile_id = id, error = %e, "Invalid schedule profile timezone in database, using UTC");
            chrono_tz::UTC
        });
        ScheduleProfile {
            id: Some(id),
            name: Arc::from(name.as_str()),
            timezone,
            comment: comment.as_deref().map(Arc::from),
            created_at: Some(Arc::from(created_at.as_str())),
            updated_at: Some(Arc::from(updated_at.as_str())),
        }
    }

    fn row_to_slot(row: SlotRow) -> Option<TimeSlot> {
        let (id, profile_id, days, start_time, end_time, action_str, created_at) = row;
        let action = action_str
            .parse::<ScheduleAction>()
            .map_err(|_| {
                warn!(action = %action_str, slot_id = id, "Unknown schedule action in database, skipping slot");
            })
            .ok()?;
        let parse_time = |time: &str| {
            TimeSlot::parse_time(time)
                .map_err(|e| {
                    warn!(slot_id = id, error = %e, "Invalid time slot time in database, skipping slot");
                })
                .ok()
        };
        Some(TimeSlot {
            id: Some(id),
            profile_id,
            // The column's CHECK constraint keeps days within 1..=127.
            days: days as u8,
            start_time: parse_time(&start_time)?,
            end_time: parse_time(&end_time)?,
            action,
            created_at: Some(Arc::from(created_at.as_str())),
        })
    }
}

#[async_trait]
impl ScheduleProfileRepository for SqliteScheduleProfileRepository {
    async fn create(
        &self,
        name: String,
        timezone: Tz,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, ProfileRow>(
            "INSERT INTO schedule_profiles (name, timezone, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, name, timezone, comment, created_at, updated_at",
        )
        .bind(&name)
        .bind(timezone.name())
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::DuplicateScheduleProfileName(name.clone())
            } else {
                db_err("Failed to create schedule profile")(e)
            }
        })?;

        Ok(Self::row_to_profile(row))
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<ScheduleProfile>, DomainError> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT id, name, timezone, comment, created_at, updated_at
             FROM schedule_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query schedule profile by id"))?;

        Ok(row.map(Self::row_to_profile))
    }

    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError> {
        let rows = sqlx::query_as::<_, ProfileRow>(
            "SELECT id, name, timezone, comment, created_at, updated_at
             FROM schedule_profiles ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all schedule profiles"))?;

        Ok(rows.into_iter().map(Self::row_to_profile).collect())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        timezone: Option<Tz>,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, ProfileRow>(
            "UPDATE schedule_profiles
             SET name       = COALESCE(?, name),
                 timezone   = COALESCE(?, timezone),
                 comment    = COALESCE(?, comment),
                 updated_at = ?
             WHERE id = ?
             RETURNING id, name, timezone, comment, created_at, updated_at",
        )
        .bind(&name)
        .bind(timezone.map(Tz::name))
        .bind(&comment)
        .bind(&now)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::DuplicateScheduleProfileName(name.clone().unwrap_or_default())
            } else {
                db_err("Failed to update schedule profile")(e)
            }
        })?
        .ok_or(DomainError::ScheduleProfileNotFound(id))?;

        Ok(Self::row_to_profile(row))
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM schedule_profiles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete schedule profile"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ScheduleProfileNotFound(id));
        }
        Ok(())
    }

    async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError> {
        let rows = sqlx::query_as::<_, SlotRow>(
            "SELECT id, profile_id, days, start_time, end_time, action, created_at
             FROM time_slots
             WHERE profile_id = ?
             ORDER BY days, start_time",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query time slots"))?;

        Ok(rows.into_iter().filter_map(Self::row_to_slot).collect())
    }

    async fn add_slot(
        &self,
        profile_id: i64,
        days: u8,
        start_time: NaiveTime,
        end_time: NaiveTime,
        action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();

        let row = sqlx::query_as::<_, SlotRow>(
            "INSERT INTO time_slots (profile_id, days, start_time, end_time, action, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id, profile_id, days, start_time, end_time, action, created_at",
        )
        .bind(profile_id)
        .bind(i64::from(days))
        .bind(start_time.format(TimeSlot::TIME_FORMAT).to_string())
        .bind(end_time.format(TimeSlot::TIME_FORMAT).to_string())
        .bind(action.to_str())
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                DomainError::ScheduleProfileNotFound(profile_id)
            } else {
                db_err("Failed to add time slot")(e)
            }
        })?;

        Self::row_to_slot(row)
            .ok_or_else(|| DomainError::DatabaseError("Invalid time slot row".into()))
    }

    async fn delete_slot(&self, slot_id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM time_slots WHERE id = ?")
            .bind(slot_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete time slot"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::TimeSlotNotFound(slot_id));
        }
        Ok(())
    }

    async fn assign_to_group(&self, group_id: i64, profile_id: i64) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO group_schedule_profiles (group_id, profile_id)
             VALUES (?, ?)
             ON CONFLICT(group_id) DO UPDATE SET profile_id = excluded.profile_id",
        )
        .bind(group_id)
        .bind(profile_id)
        .execute(&self.pool)
        .await
        .map_err(db_err("Failed to assign schedule profile to group"))?;
        Ok(())
    }

    async fn unassign_from_group(&self, group_id: i64) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM group_schedule_profiles WHERE group_id = ?")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to unassign schedule profile from group"))?;
        Ok(())
    }

    async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT profile_id FROM group_schedule_profiles WHERE group_id = ?",
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query group schedule assignment"))?;

        Ok(row.map(|(pid,)| pid))
    }

    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError> {
        sqlx::query_as::<_, (i64, i64)>("SELECT group_id, profile_id FROM group_schedule_profiles")
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to query group schedule assignments"))
    }
}
