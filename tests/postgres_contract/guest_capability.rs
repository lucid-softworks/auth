use chrono::{Duration, Utc};
use lucid_auth::{
    AuthService, GuestCapabilityStore, GuestGrant, NewGuestGrant, SessionWithUser,
    postgres::PostgresStore,
};
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn insert_legacy_shape(
    pool: &sqlx::PgPool,
    owner_id: Uuid,
) -> Result<(Uuid, Uuid), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        "CREATE TABLE lucid_auth_guest_grants (\
           id UUID PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT UNIQUE, \
           permissions JSONB NOT NULL DEFAULT '[]'::jsonb, \
           resource_scopes JSONB NOT NULL DEFAULT '[]'::jsonb, \
           valid_from TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, \
           max_uses INTEGER, uses INTEGER NOT NULL DEFAULT 0, \
           created_by UUID NOT NULL REFERENCES lucid_auth_users(id), \
           revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL\
         ); \
         ALTER TABLE lucid_auth_sessions ADD COLUMN guest_grant_id UUID \
           REFERENCES lucid_auth_guest_grants(id) ON DELETE CASCADE;",
    )
    .execute(pool)
    .await?;
    let grant_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO lucid_auth_guest_grants \
         (id, label, token_hash, permissions, resource_scopes, valid_from, expires_at, \
          max_uses, uses, created_by, revoked_at, created_at) \
         VALUES ($1, 'Legacy guest', NULL, '[]', '[]', $2, $3, NULL, 0, $4, NULL, $2)",
    )
    .bind(grant_id)
    .bind(now)
    .bind(now + Duration::hours(1))
    .bind(owner_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO lucid_auth_sessions \
         (id, user_id, token, actor_user_id, authentication_method, expires_at, created_at, \
          updated_at, ip_address, user_agent, guest_grant_id) \
         VALUES ($1, $2, $3, NULL, 'anonymous', $4, $5, $5, NULL, NULL, $6)",
    )
    .bind(session_id)
    .bind(owner_id)
    .bind(format!("legacy-guest-{session_id}"))
    .bind(now + Duration::hours(1))
    .bind(now)
    .bind(grant_id)
    .execute(pool)
    .await?;
    Ok((session_id, grant_id))
}

pub(super) async fn assert_legacy_migrated(
    pool: &sqlx::PgPool,
    (session_id, grant_id): (Uuid, Uuid),
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy_column = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'lucid_auth_sessions' \
           AND column_name = 'guest_grant_id')",
    )
    .fetch_one(pool)
    .await?;
    assert!(!legacy_column);
    let migrated = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM lucid_auth_guest_grant_sessions \
         WHERE session_id = $1 AND grant_id = $2)",
    )
    .bind(session_id)
    .bind(grant_id)
    .fetch_one(pool)
    .await?;
    assert!(migrated);
    Ok(())
}

pub(super) async fn assert_atomic(
    store: &PostgresStore,
    service: &Arc<AuthService>,
    pool: &sqlx::PgPool,
    owner: &SessionWithUser,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_guest_grants') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    let mut owner = owner.clone();
    owner.session.authentication_method = lucid_auth::AuthenticationMethod::Passkey;
    let now = Utc::now();
    let issued = service
        .issue_guest_grant(
            &owner,
            NewGuestGrant {
                label: "PostgreSQL guest".into(),
                permissions: vec!["devices:read".into()],
                resource_scopes: vec!["room:kitchen".into()],
                valid_from: now,
                expires_at: now + Duration::hours(1),
                max_uses: Some(1),
            },
        )
        .await?;
    let left = service.clone();
    let right = service.clone();
    let left_token = issued.token.clone();
    let right_token = issued.token;
    let (left, right) = tokio::join!(
        left.redeem_guest_grant(&left_token, None, None),
        right.redeem_guest_grant(&right_token, None, None),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let redeemed = left.or(right)?;
    assert!(service.session(&redeemed.token).await?.is_some());
    service.revoke_guest_grant(&owner, issued.grant.id).await?;
    assert!(service.session(&redeemed.token).await?.is_none());

    let expired = GuestGrant {
        id: Uuid::new_v4(),
        label: "Expired PostgreSQL guest".into(),
        token_hash: Some("expired-guest-token".into()),
        permissions: vec!["devices:read".into()],
        resource_scopes: Vec::new(),
        valid_from: now - Duration::days(2),
        expires_at: now - Duration::days(1),
        max_uses: None,
        uses: 0,
        created_by: owner.user.id,
        revoked_at: None,
        created_at: now - Duration::days(2),
    };
    store.create_guest_grant(expired).await?;
    assert!(
        store
            .consume_guest_grant("expired-guest-token", Utc::now())
            .await?
            .is_none()
    );
    Ok(())
}
