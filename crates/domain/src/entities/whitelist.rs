#[derive(Debug, Clone)]
pub struct WhitelistedDomain {
    pub id: Option<i64>,
    pub domain: String,
    pub added_at: Option<String>,
}
