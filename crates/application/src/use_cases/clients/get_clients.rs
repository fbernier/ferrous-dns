use crate::ports::ClientRepository;
use ferrous_dns_domain::{Client, ClientStats, DomainError};
use std::net::IpAddr;
use std::sync::Arc;

pub struct GetClientsUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl GetClientsUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    pub async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError> {
        self.client_repo.get_all(limit, offset).await
    }

    pub async fn get_by_ip(&self, ip: IpAddr) -> Result<Option<Client>, DomainError> {
        self.client_repo.get_by_ip(ip).await
    }

    pub async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError> {
        self.client_repo.get_active(days, limit).await
    }

    pub async fn get_stats(&self) -> Result<ClientStats, DomainError> {
        self.client_repo.get_stats().await
    }
}
