use chrono::{Duration, Utc};
use lucid_auth::{
    AuthService, GuestCapabilityStore, GuestGrant, NewGuestGrant, SessionWithUser,
    postgres::PostgresStore,
};
use std::sync::Arc;
use uuid::Uuid;

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
    owner.session.authentication_method = Some(lucid_auth::AuthenticationMethod::Passkey);
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
