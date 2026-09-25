use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, ScheduleProfile};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ScheduleProfileRepository;

pub struct CreateScheduleProfileUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
}

impl CreateScheduleProfileUseCase {
    pub fn new(repo: Arc<dyn ScheduleProfileRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        timezone: String,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        ScheduleProfile::validate_name(&name).map_err(DomainError::InvalidScheduleProfile)?;
        let timezone = ScheduleProfile::parse_timezone(&timezone)
            .map_err(DomainError::InvalidScheduleProfile)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidScheduleProfile)?;

        let profile = self.repo.create(name.clone(), timezone, comment).await?;

        info!(profile_id = ?profile.id, name = %name, "Schedule profile created");

        Ok(profile)
    }
}
