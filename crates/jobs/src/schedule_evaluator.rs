use chrono::{Datelike, Timelike};
use chrono_tz::Tz;
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
            interval.tick().await;

            loop {
                interval.tick().await;
                self.state.sweep_expired();
                self.evaluate_all_schedules().await;
            }
        });
    }

    async fn evaluate_all_schedules(&mut self) {
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
            let profile = match self.repo.get_by_id(*profile_id).await {
                Ok(Some(p)) => p,
                Ok(None) => {
                    warn!(
                        profile_id,
                        "ScheduleEvaluatorJob: profile not found, skipping"
                    );
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

            let tz: Tz = match profile.timezone.parse() {
                Ok(tz) => tz,
                Err(_) => {
                    warn!(
                        timezone = %profile.timezone,
                        profile_id,
                        "ScheduleEvaluatorJob: invalid timezone, using UTC"
                    );
                    chrono_tz::UTC
                }
            };

            let now = chrono::Utc::now().with_timezone(&tz);
            let weekday_bit = 1u8 << now.weekday().num_days_from_monday();
            let now_time = format!("{:02}:{:02}", now.hour(), now.minute());

            match evaluate_slots(&slots, weekday_bit, &now_time) {
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
