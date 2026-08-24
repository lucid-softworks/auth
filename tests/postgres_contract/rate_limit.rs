use lucid_auth::{RateLimitOutcome, RateLimitRule, SecurityStore, postgres::PostgresStore};
use std::sync::Arc;

pub(super) async fn assert_atomic(
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Utc::now();
    let key = format!("192.0.2.10|/concurrent/{}", uuid::Uuid::new_v4());
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let store = store.clone();
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            store
                .consume_rate_limit(&key, now, RateLimitRule::new(60, 5), 60)
                .await
        }));
    }
    let mut allowed = 0;
    let mut denied = 0;
    for task in tasks {
        match task.await?? {
            RateLimitOutcome { allowed: true, .. } => allowed += 1,
            RateLimitOutcome {
                allowed: false,
                retry_after: Some(60),
            } => denied += 1,
            outcome => panic!("unexpected rate-limit outcome {outcome:?}"),
        }
    }
    assert_eq!(allowed, 5);
    assert_eq!(denied, 15);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count FROM lucid_auth_rate_limits WHERE key = $1",)
            .bind(&key)
            .fetch_one(pool)
            .await?,
        5
    );

    let stale = format!("stale|/{}", uuid::Uuid::new_v4());
    sqlx::query("INSERT INTO lucid_auth_rate_limits (key, count, last_request) VALUES ($1, 1, $2)")
        .bind(&stale)
        .bind((now - chrono::Duration::minutes(2)).timestamp_millis())
        .execute(pool)
        .await?;
    store
        .consume_rate_limit("cleanup|/probe", now, RateLimitRule::new(10, 100), 60)
        .await?;
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM lucid_auth_rate_limits WHERE key = $1)",
        )
        .bind(stale)
        .fetch_one(pool)
        .await?
    );
    Ok(())
}
