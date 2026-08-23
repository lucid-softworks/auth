use chrono::{Duration, Utc};
use lucid_auth::{TwoFactorRecord, TwoFactorStore, postgres::PostgresStore};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn assert_table_absent(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_two_factors') IS NOT NULL",)
            .fetch_one(pool)
            .await?
    );
    Ok(())
}

pub(super) async fn assert_atomic(
    store: &PostgresStore,
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = store
        .upsert_two_factor(TwoFactorRecord {
            id: Uuid::new_v4(),
            user_id,
            enabled: true,
            encrypted_secret: Some("encrypted-secret".into()),
            encrypted_backup_codes: Some("encrypted-backup-codes".into()),
            verified: true,
            failed_verification_count: 0,
            locked_until: None,
            last_totp_counter: None,
        })
        .await?;
    assert_eq!(record.user_id, user_id);

    let (left, right) = tokio::join!(
        store.accept_totp_counter(user_id, 42, false),
        store.accept_totp_counter(user_id, 42, false)
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);

    let expected = record.encrypted_backup_codes.as_deref().unwrap();
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
    assert_eq!(locked.locked_until, Some(locked_until));

    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_two_factors WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}
