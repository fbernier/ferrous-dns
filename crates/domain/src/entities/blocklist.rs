#[derive(Debug, Clone)]
pub struct BlockedDomain {
    pub id: Option<i64>,
    pub domain: String,
    pub added_at: Option<String>,
}
