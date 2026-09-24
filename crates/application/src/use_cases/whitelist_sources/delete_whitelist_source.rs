use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, WhitelistSourceRepository};

pub struct DeleteWhitelistSourceUseCase {
    repo: Arc<dyn WhitelistSourceRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteWhitelistSourceUseCase {
    pub fn new(
        repo: Arc<dyn WhitelistSourceRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::WhitelistSourceNotFound(id))?;

        self.repo.delete(id).await?;

        info!(source_id = ?id, "Whitelist source deleted successfully");

        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after whitelist source deletion");
        }

        Ok(())
    }
}
