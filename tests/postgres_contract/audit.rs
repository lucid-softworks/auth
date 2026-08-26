use chrono::{Duration, Utc};
use lucid_auth::{AuditEvent, AuditMetadata, AuditOutcome, AuditStore, postgres::PostgresStore};
use serde_json::json;
use uuid::Uuid;

pub(super) async fn assert_table_absent(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_audit_events') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    Ok(())
}

pub(super) async fn assert_retention_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("TRUNCATE lucid_auth_audit_events")
        .execute(pool)
        .await?;
    let baseline = event(user_id, "audit.baseline", AuditOutcome::Success, 2)?;
    store.record_audit_event(baseline.clone(), 10).await?;

    sqlx::raw_sql(
        "CREATE FUNCTION lucid_auth_reject_audit_delete() RETURNS trigger \
           LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reject audit retention'; END $$; \
         CREATE TRIGGER lucid_auth_reject_audit_delete \
           BEFORE DELETE ON lucid_auth_audit_events \
           FOR EACH ROW EXECUTE FUNCTION lucid_auth_reject_audit_delete();",
    )
    .execute(pool)
    .await?;
    let rejected = event(user_id, "audit.rejected", AuditOutcome::Failure, 1)?;
    assert!(store.record_audit_event(rejected.clone(), 1).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lucid_auth_audit_events WHERE id = $1",)
            .bind(rejected.id)
            .fetch_one(pool)
            .await?,
        0,
        "the insert rolls back when retention fails"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lucid_auth_audit_events WHERE id = $1",)
            .bind(baseline.id)
            .fetch_one(pool)
            .await?,
        1
    );
    sqlx::raw_sql(
        "DROP TRIGGER lucid_auth_reject_audit_delete ON lucid_auth_audit_events; \
         DROP FUNCTION lucid_auth_reject_audit_delete();",
    )
    .execute(pool)
    .await?;

    let middle = event(user_id, "audit.middle", AuditOutcome::Success, 1)?;
    let newest = event(user_id, "audit.newest", AuditOutcome::Failure, 0)?;
    store.record_audit_event(middle, 2).await?;
    store.record_audit_event(newest, 2).await?;
    let retained = store.list_audit_events(10).await?;
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].action, "audit.newest");
    assert_eq!(retained[0].outcome, AuditOutcome::Failure);
    assert_eq!(retained[1].action, "audit.middle");
    Ok(())
}

fn event(
    user_id: Uuid,
    action: &str,
    outcome: AuditOutcome,
    age_minutes: i64,
) -> Result<AuditEvent, Box<dyn std::error::Error>> {
    Ok(AuditEvent {
        id: Uuid::new_v4(),
        actor_user_id: None,
        subject_user_id: Some(user_id),
        action: action.into(),
        target: Some(user_id.to_string()),
        outcome,
        metadata: AuditMetadata::new(json!({ "sequence": age_minutes }))?,
        created_at: Utc::now() - Duration::minutes(age_minutes),
    })
}
