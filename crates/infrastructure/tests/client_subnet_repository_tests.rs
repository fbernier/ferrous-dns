#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::SqliteClientSubnetRepository;
use sqlx::SqlitePool;

const GUEST: i64 = 2;

async fn repo() -> (SqliteClientSubnetRepository, SqlitePool) {
    let pool = db::migrated_pool().await;
    sqlx::query("INSERT INTO groups (id, name) VALUES (?, 'Guest')")
        .bind(GUEST)
        .execute(&pool)
        .await
        .unwrap();
    (SqliteClientSubnetRepository::new(pool.clone()), pool)
}

#[tokio::test]
async fn test_create_subnet_success() {
    let (repo, _pool) = repo().await;

    let created = repo
        .create(
            "192.168.1.0/24".to_string(),
            1,
            Some("Office network".to_string()),
        )
        .await
        .unwrap();

    assert!(created.id.is_some());
    assert_eq!(created.subnet_cidr.as_ref(), "192.168.1.0/24");
    assert_eq!(created.group_id, 1);
    assert_eq!(created.comment.as_deref(), Some("Office network"));
    assert!(created.created_at.is_some());
}

#[tokio::test]
async fn test_create_subnet_duplicate() {
    let (repo, _pool) = repo().await;
    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();

    let result = repo.create("192.168.1.0/24".to_string(), GUEST, None).await;

    assert!(
        matches!(result, Err(DomainError::SubnetConflict(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_create_subnet_invalid_group() {
    let (repo, _pool) = repo().await;

    let result = repo.create("192.168.1.0/24".to_string(), 999, None).await;

    assert!(
        matches!(result, Err(DomainError::GroupNotFound(999))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_get_all_with_various_cidrs() {
    let (repo, _pool) = repo().await;
    let cidrs = [
        ("192.168.1.0/24", 1),
        ("10.0.0.0/8", GUEST),
        ("172.16.0.0/12", 1),
        ("2001:db8::/32", GUEST),
    ];
    for (cidr, group_id) in cidrs {
        repo.create(cidr.to_string(), group_id, None).await.unwrap();
    }

    let mut all: Vec<String> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.subnet_cidr.to_string())
        .collect();
    all.sort();

    assert_eq!(
        all,
        vec![
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "2001:db8::/32"
        ]
    );
}

#[tokio::test]
async fn test_get_by_id_success() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("192.168.1.0/24".to_string(), 1, Some("Test".to_string()))
        .await
        .unwrap()
        .id
        .unwrap();

    let subnet = repo.get_by_id(id).await.unwrap().unwrap();

    assert_eq!(subnet.id, Some(id));
    assert_eq!(subnet.subnet_cidr.as_ref(), "192.168.1.0/24");
    assert_eq!(subnet.comment.as_deref(), Some("Test"));
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let (repo, _pool) = repo().await;

    assert!(repo.get_by_id(999).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_subnet_success() {
    let (repo, _pool) = repo().await;
    let id = repo
        .create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap()
        .id
        .unwrap();

    repo.delete(id).await.unwrap();

    assert!(repo.get_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_subnet_not_found() {
    let (repo, _pool) = repo().await;

    let result = repo.delete(999).await;

    assert!(
        matches!(result, Err(DomainError::SubnetNotFound(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn test_exists() {
    let (repo, _pool) = repo().await;
    repo.create("192.168.1.0/24".to_string(), 1, None)
        .await
        .unwrap();

    assert!(repo.exists("192.168.1.0/24").await.unwrap());
    assert!(!repo.exists("192.168.2.0/24").await.unwrap());
}

#[tokio::test]
async fn test_delete_cascades_on_group_deletion() {
    let (repo, pool) = repo().await;
    repo.create("192.168.1.0/24".to_string(), GUEST, None)
        .await
        .unwrap();
    repo.create("10.0.0.0/8".to_string(), 1, None)
        .await
        .unwrap();

    sqlx::query("DELETE FROM groups WHERE id = ?")
        .bind(GUEST)
        .execute(&pool)
        .await
        .unwrap();

    let remaining: Vec<String> = repo
        .get_all()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.subnet_cidr.to_string())
        .collect();
    assert_eq!(remaining, vec!["10.0.0.0/8"]);
}
