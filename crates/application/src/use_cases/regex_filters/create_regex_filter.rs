use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, RegexFilterRepository};

pub struct CreateRegexFilterUseCase {
    repo: Arc<dyn RegexFilterRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateRegexFilterUseCase {
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
        name: String,
        pattern: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<RegexFilter, DomainError> {
        RegexFilter::validate_name(&name).map_err(DomainError::InvalidRegexFilter)?;
        RegexFilter::validate_pattern(&pattern).map_err(DomainError::InvalidRegexFilter)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidRegexFilter)?;

        require_group(self.group_repo.as_ref(), group_id).await?;

        let filter = self
            .repo
            .create(
                name.clone(),
                pattern.clone(),
                action,
                group_id,
                comment,
                enabled,
            )
            .await?;

        info!(
            filter_id = ?filter.id,
            name = %name,
            pattern = %pattern,
            action = %action.to_str(),
            group_id = group_id,
            "Regex filter created successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after regex filter creation");
        }

        Ok(filter)
    }
}
