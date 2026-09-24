use super::require_group;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository};

pub struct DeleteGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteGroupUseCase {
    pub fn new(
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let group = require_group(self.group_repo.as_ref(), id).await?;

        if group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDeleted);
        }

        let client_count = self.group_repo.count_clients_in_group(id).await?;
        if client_count > 0 {
            return Err(DomainError::GroupHasAssignedClients(client_count));
        }

        self.group_repo.delete(id).await?;

        info!(
            group_id = ?id,
            name = %group.name,
            "Group deleted successfully"
        );

        // The delete cascades to managed domains and client subnets the engine still holds.
        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after group deletion");
        }

        Ok(())
    }
}
