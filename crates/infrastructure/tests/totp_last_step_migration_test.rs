//! Exercises `20260924000100_add_totp_last_step` on a database created by the
//! earlier `user_mfa` schema, holding an enrolled user.

use ferrous_dns_application::ports::MfaRepository;
use ferrous_dns_infrastructure::auth::SqliteMfaRepository;
use sqlx::sqlite::SqlitePoolOptions;

const CREATE_USER_MFA: &str =
    include_str!("../../../migrations/20260718000001_create_user_mfa.sql");
const ADD_TOTP_LAST_STEP: &str =
    include_str!("../../../migrations/20260924000100_add_totp_last_step.sql");

#[tokio::test]
async fn an_enrolled_user_keeps_totp_and_starts_without_a_spent_step() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(CREATE_USER_MFA).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO user_mfa (username, totp_secret, totp_enabled, confirmed_at)
         VALUES ('admin', 'SECRET32', 1, '2026-07-18 00:00:00')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(ADD_TOTP_LAST_STEP)
        .execute(&pool)
        .await
        .unwrap();

    let last_step: Option<i64> =
        sqlx::query_scalar("SELECT totp_last_step FROM user_mfa WHERE username = 'admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(last_step, None);

    let repo = SqliteMfaRepository::new(pool);
    let mfa = repo.get("admin").await.unwrap().unwrap();
    assert_eq!(mfa.totp_secret.as_ref(), "SECRET32");
    assert!(mfa.totp_enabled);
    assert!(repo.advance_totp_step("admin", 1).await.unwrap());
    assert!(!repo.advance_totp_step("admin", 1).await.unwrap());
}
