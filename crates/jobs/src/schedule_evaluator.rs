use ferrous_dns_application::ports::{ScheduleProfileRepository, ScheduleStatePort};
use ferrous_dns_domain::{evaluate_slots, GroupOverride, ScheduleAction};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

const INTERVAL_SECS: u64 = 60;

pub struct ScheduleEvaluatorJob {
    repo: Arc<dyn ScheduleProfileRepository>,
    state: Arc<dyn ScheduleStatePort>,
    active_groups: HashSet<i64>,
}

impl ScheduleEvaluatorJob {
    pub fn new(
        repo: Arc<dyn ScheduleProfileRepository>,
        state: Arc<dyn ScheduleStatePort>,
    ) -> Self {
        Self {
            repo,
            state,
            active_groups: HashSet::new(),
        }
    }

    pub fn spawn(mut self) {
        info!(
            interval_secs = INTERVAL_SECS,
            "Starting schedule evaluator job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));

            loop {
                // The first tick completes immediately, so schedules are enforced right at startup.
                interval.tick().await;
                self.evaluate_once().await;
            }
        });
    }

    pub async fn evaluate_once(&mut self) {
        self.state.sweep_expired();

        let assignments = match self.repo.get_all_group_assignments().await {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "ScheduleEvaluatorJob: failed to load group assignments");
                return;
            }
        };

        let current_group_ids: HashSet<i64> = assignments.iter().map(|(gid, _)| *gid).collect();
        for stale_id in self.active_groups.difference(&current_group_ids) {
            self.state.clear(*stale_id);
        }
        self.active_groups = current_group_ids;

        for (group_id, profile_id) in &assignments {
            // A transient load failure keeps the group's last override so enforcement does not flap.
            let profile = match self.repo.get_by_id(*profile_id).await {
                Ok(Some(p)) => p,
                Ok(None) => {
                    warn!(
                        group_id,
                        profile_id,
                        "ScheduleEvaluatorJob: assigned profile not found, clearing override"
                    );
                    self.state.clear(*group_id);
                    continue;
                }
                Err(e) => {
                    error!(error = %e, profile_id, "ScheduleEvaluatorJob: failed to load profile");
                    continue;
                }
            };

            let slots = match self.repo.get_slots(*profile_id).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, profile_id, "ScheduleEvaluatorJob: failed to load slots");
                    continue;
                }
            };

            let now = chrono::Utc::now()
                .with_timezone(&profile.timezone)
                .naive_local();

            match evaluate_slots(&slots, now) {
                Some(ScheduleAction::BlockAll) => {
                    self.state.set(*group_id, GroupOverride::BlockAll);
                }
                Some(ScheduleAction::AllowAll) => {
                    self.state.set(*group_id, GroupOverride::AllowAll);
                }
                None => {
                    self.state.clear(*group_id);
                }
            }
        }
    }
}
