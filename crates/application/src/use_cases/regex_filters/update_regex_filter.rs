use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, RegexFilter};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, GroupRepository, RegexFilterRepository, RegexFilterUpdate,
};

pub struct UpdateRegexFilterUseCase {
    repo: Arc<dyn RegexFilterRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateRegexFilterUseCase {
    pub fn new(
        repo: Arc<dyn RegexFilterRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        update: RegexFilterUpdate,
    ) -> Result<RegexFilter, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::RegexFilterNotFound(id))?;

        if let Some(ref n) = update.name {
            RegexFilter::validate_name(n).map_err(DomainError::InvalidRegexFilter)?;
        }

        if let Some(ref p) = update.pattern {
            RegexFilter::validate_pattern(p).map_err(DomainError::InvalidRegexFilter)?;
        }

        validate_comment(update.comment.as_ref().and_then(Option::as_deref))
            .map_err(DomainError::InvalidRegexFilter)?;

        if let Some(gid) = update.group_id {
            require_group(self.group_repo.as_ref(), gid).await?;
        }

        let updated = self.repo.update(id, update).await?;

        info!(
            filter_id = ?id,
            name = %updated.name,
            pattern = %updated.pattern,
            action = %updated.action.to_str(),
            enabled = %updated.enabled,
            "Regex filter updated successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after regex filter update");
        }

        Ok(updated)
    }
}
