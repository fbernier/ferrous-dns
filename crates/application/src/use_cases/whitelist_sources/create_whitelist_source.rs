use crate::use_cases::groups::require_group;
use ferrous_dns_domain::value_objects::validators::{validate_comment, validate_url};
use ferrous_dns_domain::{DomainError, WhitelistSource};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository, WhitelistSourceRepository};

pub struct CreateWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateWhitelistSourceUseCase {
    pub fn new(
        repo: Arc<dyn WhitelistSourceRepository>,
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
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<WhitelistSource, DomainError> {
        WhitelistSource::validate_name(&name).map_err(DomainError::InvalidWhitelistSource)?;

        validate_url(url.as_deref()).map_err(DomainError::InvalidWhitelistSource)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidWhitelistSource)?;

        for &gid in &group_ids {
            require_group(self.group_repo.as_ref(), gid).await?;
        }

        let source = self
            .repo
            .create(name.clone(), url, group_ids.clone(), comment, enabled)
            .await?;

        info!(
            source_id = ?source.id,
            name = %name,
            group_ids = ?group_ids,
            "Whitelist source created successfully"
        );

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after whitelist source creation");
        }

        Ok(source)
    }
}
