use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::{validate_comment, validate_url};
use ferrous_dns_domain::{BlocklistSource, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, BlocklistSourceRepository, GroupRepository};

pub struct UpdateBlocklistSourceUseCase {
    repo: Arc<dyn BlocklistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateBlocklistSourceUseCase {
    pub fn new(
        repo: Arc<dyn BlocklistSourceRepository>,
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
        name: Option<String>,
        url: Option<Option<String>>,
        group_ids: Option<Vec<i64>>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<BlocklistSource, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        if let Some(ref n) = name {
            BlocklistSource::validate_name(n).map_err(DomainError::InvalidBlocklistSource)?;
        }

        if let Some(ref u_opt) = url {
            validate_url(u_opt.as_deref()).map_err(DomainError::InvalidBlocklistSource)?;
        }

        validate_comment(comment.as_deref()).map_err(DomainError::InvalidBlocklistSource)?;

        if let Some(ref ids) = group_ids {
            for &gid in ids {
                require_group(self.group_repo.as_ref(), gid).await?;
            }
        }

        let updated = self
            .repo
            .update(id, name, url, group_ids, comment, enabled)
            .await?;

        info!(
            source_id = ?id,
            name = %updated.name,
            enabled = %updated.enabled,
            "Blocklist source updated successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after blocklist source update");
        }

        Ok(updated)
    }
}
