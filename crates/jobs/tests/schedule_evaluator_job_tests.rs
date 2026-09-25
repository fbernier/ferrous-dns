use async_trait::async_trait;
use chrono::{NaiveTime, Timelike, Utc};
use chrono_tz::Tz;
use ferrous_dns_application::ports::{ScheduleProfileRepository, ScheduleStatePort};
use ferrous_dns_domain::{DomainError, GroupOverride, ScheduleAction, ScheduleProfile, TimeSlot};
use ferrous_dns_jobs::ScheduleEvaluatorJob;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

const GROUP_ID: i64 = 2;
const PROFILE_ID: i64 = 7;

#[derive(Default)]
struct MockScheduleRepo {
    assignments: Vec<(i64, i64)>,
    profiles: HashMap<i64, ScheduleProfile>,
    failing_profiles: HashSet<i64>,
    slots: HashMap<i64, Vec<TimeSlot>>,
}

#[async_trait]
impl ScheduleProfileRepository for MockScheduleRepo {
    async fn create(
        &self,
        _name: String,
        _timezone: Tz,
        _comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        unimplemented!()
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<ScheduleProfile>, DomainError> {
        if self.failing_profiles.contains(&id) {
            return Err(DomainError::DatabaseError("database is locked".into()));
        }
        Ok(self.profiles.get(&id).cloned())
    }

    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError> {
        Ok(self.profiles.values().cloned().collect())
    }

    async fn update(
        &self,
        _id: i64,
        _name: Option<String>,
        _timezone: Option<Tz>,
        _comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        unimplemented!()
    }

    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError> {
        Ok(self.slots.get(&profile_id).cloned().unwrap_or_default())
    }

    async fn add_slot(
        &self,
        _profile_id: i64,
        _days: u8,
        _start_time: NaiveTime,
        _end_time: NaiveTime,
        _action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError> {
        unimplemented!()
    }

    async fn delete_slot(&self, _slot_id: i64) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn assign_to_group(&self, _group_id: i64, _profile_id: i64) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn unassign_from_group(&self, _group_id: i64) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError> {
        Ok(self
            .assignments
            .iter()
            .find(|(gid, _)| *gid == group_id)
            .map(|(_, pid)| *pid))
    }

    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError> {
        Ok(self.assignments.clone())
    }
}

#[derive(Default)]
struct MockScheduleState {
    overrides: Mutex<HashMap<i64, GroupOverride>>,
}

impl ScheduleStatePort for MockScheduleState {
    fn get(&self, group_id: i64) -> Option<GroupOverride> {
        self.overrides.lock().get(&group_id).copied()
    }

    fn set(&self, group_id: i64, state: GroupOverride) {
        self.overrides.lock().insert(group_id, state);
    }

    fn clear(&self, group_id: i64) {
        self.overrides.lock().remove(&group_id);
    }

    fn is_empty(&self) -> bool {
        self.overrides.lock().is_empty()
    }

    fn sweep_expired(&self) {}
}

fn profile(timezone: Tz) -> ScheduleProfile {
    ScheduleProfile {
        id: Some(PROFILE_ID),
        name: Arc::from("Bedtime"),
        timezone,
        comment: None,
        created_at: None,
        updated_at: None,
    }
}

/// A BlockAll slot covering every day from 00:00 to 23:59, in a timezone whose local time
/// is currently far from 23:59 (the one minute such a slot cannot cover).
fn always_blocking_repo() -> MockScheduleRepo {
    let timezone = if Utc::now().hour() < 12 {
        chrono_tz::UTC
    } else {
        chrono_tz::Etc::GMTPlus6
    };
    let slot = TimeSlot {
        id: Some(1),
        profile_id: PROFILE_ID,
        days: 0b111_1111,
        start_time: TimeSlot::parse_time("00:00").unwrap(),
        end_time: TimeSlot::parse_time("23:59").unwrap(),
        action: ScheduleAction::BlockAll,
        created_at: None,
    };
    MockScheduleRepo {
        assignments: vec![(GROUP_ID, PROFILE_ID)],
        profiles: HashMap::from([(PROFILE_ID, profile(timezone))]),
        slots: HashMap::from([(PROFILE_ID, vec![slot])]),
        ..MockScheduleRepo::default()
    }
}

#[tokio::test]
async fn spawned_job_enforces_schedule_on_first_tick() {
    let state = Arc::new(MockScheduleState::default());
    ScheduleEvaluatorJob::new(Arc::new(always_blocking_repo()), state.clone()).spawn();

    let applied = tokio::time::timeout(Duration::from_secs(5), async {
        while state.get(GROUP_ID).is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    assert!(applied.is_ok(), "no override applied right after start");
    assert_eq!(state.get(GROUP_ID), Some(GroupOverride::BlockAll));
}

#[tokio::test]
async fn missing_assigned_profile_clears_group_override() {
    let repo = MockScheduleRepo {
        assignments: vec![(GROUP_ID, PROFILE_ID)],
        ..MockScheduleRepo::default()
    };
    let state = Arc::new(MockScheduleState::default());
    state.set(GROUP_ID, GroupOverride::BlockAll);
    let mut job = ScheduleEvaluatorJob::new(Arc::new(repo), state.clone());

    job.evaluate_once().await;

    assert_eq!(state.get(GROUP_ID), None);
}

#[tokio::test]
async fn profile_load_failure_keeps_group_override() {
    let repo = MockScheduleRepo {
        assignments: vec![(GROUP_ID, PROFILE_ID)],
        failing_profiles: HashSet::from([PROFILE_ID]),
        ..MockScheduleRepo::default()
    };
    let state = Arc::new(MockScheduleState::default());
    state.set(GROUP_ID, GroupOverride::BlockAll);
    let mut job = ScheduleEvaluatorJob::new(Arc::new(repo), state.clone());

    job.evaluate_once().await;

    assert_eq!(state.get(GROUP_ID), Some(GroupOverride::BlockAll));
}
