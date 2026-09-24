use crate::use_cases::groups::require_group;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientSubnetRepository, GroupRepository};

pub struct CreateClientSubnetUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl CreateClientSubnetUseCase {
    pub fn new(
        subnet_repo: Arc<dyn ClientSubnetRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            subnet_repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let network = ClientSubnet::parse_cidr(&subnet_cidr).map_err(DomainError::InvalidCidr)?;

        require_group(self.group_repo.as_ref(), group_id).await?;

        if self.subnet_repo.exists(network).await? {
            return Err(DomainError::SubnetConflict(format!(
                "Subnet {network} already exists"
            )));
        }

        let subnet = self.subnet_repo.create(network, group_id, comment).await?;

        info!(
            subnet_id = ?subnet.id,
            cidr = %subnet.subnet_cidr,
            group_id = group_id,
            "Client subnet created successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after subnet creation");
        }

        Ok(subnet)
    }
}
