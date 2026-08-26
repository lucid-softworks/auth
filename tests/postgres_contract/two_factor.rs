use chrono::{Duration, Utc};
use lucid_auth::{TwoFactorRecord, TwoFactorStore, postgres::PostgresStore};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn assert_exact_schema(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('\"twoFactor\"')::TEXT")
            .fetch_one(pool)
            .await?,
        Some("\"twoFactor\"".into())
    );
    sqlx::query(
        "SELECT \"secret\", \"backupCodes\", \"userId\", \"verified\", \
         \"failedVerificationCount\", \"lockedUntil\" FROM \"twoFactor\" LIMIT 0",
    )
    .execute(pool)
    .await?;
    sqlx::query("SELECT \"twoFactorEnabled\" FROM \"user\" LIMIT 0")
        .execute(pool)
        .await?;
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_two_factors') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    Ok(())
}

pub(super) async fn assert_atomic(
    store: &PostgresStore,
    pool: &PgPool,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = store
        .upsert_two_factor(TwoFactorRecord {
            id: Uuid::new_v4(),
            user_id: user_id.to_owned(),
            encrypted_secret: "encrypted-secret".into(),
            encrypted_backup_codes: "encrypted-backup-codes".into(),
            verified: true,
            failed_verification_count: 0,
            locked_until: None,
        })
        .await?;
    assert_eq!(record.user_id, user_id);

    store.set_two_factor_enabled(user_id, true).await?;
    assert!(store.two_factor_enabled(user_id).await?);

    let expected = record.encrypted_backup_codes.as_str();
    let (left, right) = tokio::join!(
        store.replace_backup_codes(user_id, expected, "replacement-left".into()),
        store.replace_backup_codes(user_id, expected, "replacement-right".into())
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);

    let locked_until = Utc::now() + Duration::minutes(15);
    let (left, right) = tokio::join!(
        store.record_two_factor_failure(user_id, 2, locked_until),
        store.record_two_factor_failure(user_id, 2, locked_until)
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);
    let locked = store.find_two_factor(user_id).await?.unwrap();
    assert_eq!(locked.failed_verification_count, 2);
    assert_eq!(
        locked.locked_until.map(|value| value.timestamp_micros()),
        Some(locked_until.timestamp_micros())
    );

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM \"twoFactor\" WHERE \"userId\" = $1",)
            .bind(user_id)
            .fetch_one(pool)
            .await?,
        1
    );
    Ok(())
}
