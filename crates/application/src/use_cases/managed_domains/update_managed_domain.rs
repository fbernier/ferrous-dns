use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, ManagedDomain};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{
    BlockFilterEnginePort, GroupRepository, ManagedDomainRepository, ManagedDomainUpdate,
};

pub struct UpdateManagedDomainUseCase {
    repo: Arc<dyn ManagedDomainRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateManagedDomainUseCase {
    pub fn new(
        repo: Arc<dyn ManagedDomainRepository>,
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
        update: ManagedDomainUpdate,
    ) -> Result<ManagedDomain, DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ManagedDomainNotFound(id))?;

        if let Some(ref n) = update.name {
            ManagedDomain::validate_name(n).map_err(DomainError::InvalidManagedDomain)?;
        }

        if let Some(ref d) = update.domain {
            ManagedDomain::validate_domain(d).map_err(DomainError::InvalidManagedDomain)?;
        }

        validate_comment(update.comment.as_deref()).map_err(DomainError::InvalidManagedDomain)?;

        if let Some(gid) = update.group_id {
            require_group(self.group_repo.as_ref(), gid).await?;
        }

        let updated = self.repo.update(id, update).await?;

        info!(
            domain_id = ?id,
            name = %updated.name,
            domain = %updated.domain,
            action = %updated.action.to_str(),
            enabled = %updated.enabled,
            "Managed domain updated successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after managed domain update");
        }

        Ok(updated)
    }
}
