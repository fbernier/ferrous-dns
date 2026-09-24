use dashmap::DashMap;
use ferrous_dns_application::ports::ScheduleStatePort;
use ferrous_dns_domain::GroupOverride;
use rustc_hash::FxBuildHasher;

pub struct ScheduleStateStore {
    overrides: DashMap<i64, GroupOverride, FxBuildHasher>,
}

impl ScheduleStateStore {
    pub fn new() -> Self {
        Self {
            overrides: DashMap::with_hasher(FxBuildHasher),
        }
    }
}

impl Default for ScheduleStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleStatePort for ScheduleStateStore {
    fn get(&self, group_id: i64) -> Option<GroupOverride> {
        self.overrides.get(&group_id).map(|e| *e)
    }

    fn set(&self, group_id: i64, state: GroupOverride) {
        self.overrides.insert(group_id, state);
    }

    fn clear(&self, group_id: i64) {
        self.overrides.remove(&group_id);
    }

    fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    fn sweep_expired(&self) {
        let now = crate::dns::cache::coarse_clock::coarse_now_secs();
        self.overrides.retain(|_, state| match *state {
            GroupOverride::TimedBypassUntil(t) | GroupOverride::TimedBlockUntil(t) => now < t,
            GroupOverride::BlockAll | GroupOverride::AllowAll => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrous_dns_application::ports::ScheduleStatePort;
    use ferrous_dns_domain::GroupOverride;

    #[test]
    fn test_clear_override_removes_entry() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        store.clear(1);
        assert_eq!(store.get(1), None);
    }

    #[test]
    fn test_sweep_expired_removes_timed_block_past_deadline() {
        let store = ScheduleStateStore::new();
        // Deadline 0 is already in the past.
        store.set(1, GroupOverride::TimedBlockUntil(0));
        store.sweep_expired();
        assert_eq!(store.get(1), None);
    }

    #[test]
    fn test_sweep_expired_keeps_active_timed_bypass() {
        let store = ScheduleStateStore::new();
        // Deadline u64::MAX never passes.
        store.set(1, GroupOverride::TimedBypassUntil(u64::MAX));
        store.sweep_expired();
        assert_eq!(
            store.get(1),
            Some(GroupOverride::TimedBypassUntil(u64::MAX))
        );
    }

    #[test]
    fn test_sweep_expired_does_not_touch_non_timed_overrides() {
        let store = ScheduleStateStore::new();
        store.set(1, GroupOverride::BlockAll);
        store.set(2, GroupOverride::AllowAll);
        store.sweep_expired();
        assert_eq!(store.get(1), Some(GroupOverride::BlockAll));
        assert_eq!(store.get(2), Some(GroupOverride::AllowAll));
    }
}
