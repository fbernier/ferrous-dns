use async_trait::async_trait;
use ferrous_dns_domain::value_objects::validators::validate_comment;
use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupCreator, GroupRepository};

pub struct CreateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<Group, DomainError> {
        Group::validate_name(&name).map_err(DomainError::InvalidGroupName)?;
        validate_comment(comment.as_deref()).map_err(DomainError::InvalidGroupName)?;

        let group = self
            .group_repo
            .create(name.clone(), comment, enabled)
            .await?;

        info!(
            group_id = ?group.id,
            name = %name,
            enabled,
            "Group created successfully"
        );

        Ok(group)
    }
}

#[async_trait]
impl GroupCreator for CreateGroupUseCase {
    async fn create_group(
        &self,
        name: String,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        // Backup snapshots carry no enabled flag; restored groups start enabled.
        self.execute(name, comment, true).await
    }
}
