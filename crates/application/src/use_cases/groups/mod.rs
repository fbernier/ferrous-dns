mod assign_client_group;
mod create_group;
mod delete_group;
mod get_groups;
mod update_group;

pub use assign_client_group::AssignClientGroupUseCase;
pub use create_group::CreateGroupUseCase;
pub use delete_group::DeleteGroupUseCase;
pub use get_groups::GetGroupsUseCase;
pub use update_group::UpdateGroupUseCase;

use crate::ports::GroupRepository;
use ferrous_dns_domain::{DomainError, Group};

/// Loads group `id`, mapping absence to [`DomainError::GroupNotFound`].
pub(crate) async fn require_group(
    repo: &dyn GroupRepository,
    id: i64,
) -> Result<Group, DomainError> {
    repo.get_by_id(id)
        .await?
        .ok_or(DomainError::GroupNotFound(id))
}
