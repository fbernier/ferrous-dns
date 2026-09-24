use super::require_group;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

pub struct DeleteGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl DeleteGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
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

        Ok(())
    }
}
