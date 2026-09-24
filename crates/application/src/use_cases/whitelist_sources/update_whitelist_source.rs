use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::{validate_comment, validate_url};
use ferrous_dns_domain::{DomainError, WhitelistSource};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, WhitelistSourceRepository};

pub struct UpdateWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl UpdateWhitelistSourceUseCase {
    pub fn new(
        repo: Arc<dyn WhitelistSourceRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
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
    ) -> Result<WhitelistSource, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::WhitelistSourceNotFound(id))?;

        if let Some(ref n) = name {
            WhitelistSource::validate_name(n).map_err(DomainError::InvalidWhitelistSource)?;
        }

        if let Some(ref u_opt) = url {
            validate_url(u_opt.as_deref()).map_err(DomainError::InvalidWhitelistSource)?;
        }

        validate_comment(comment.as_deref()).map_err(DomainError::InvalidWhitelistSource)?;

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
            "Whitelist source updated successfully"
        );

        Ok(updated)
    }
}
