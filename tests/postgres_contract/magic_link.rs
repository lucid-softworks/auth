use chrono::{Duration, Utc};
use lucid_auth::{
    AuthSession, AuthStore, AuthUser, AuthenticationMethod, OAuthAccount, VerificationStore,
    VerificationValue, postgres::PostgresStore,
};
use serde_json::json;
use uuid::Uuid;

pub(super) async fn assert_promotion_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let user = store
        .create_password_user(
            AuthUser {
                id: user_id,
                username: None,
                display_username: None,
                name: "Unverified magic-link user".into(),
                email: "postgres-magic@example.com".into(),
                email_verified: false,
                image: None,
                additional_fields: serde_json::Map::new(),
                role: "member".into(),
                is_anonymous: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
            credential_account(user_id, now),
        )
        .await?;
    store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token: "unproven-magic-session".into(),
            actor_user_id: None,
            authentication_method: AuthenticationMethod::Password,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields: serde_json::Map::new(),
        })
        .await?;
    store
        .create_verification(VerificationValue {
            purpose: "magic-link".into(),
            identifier: "postgres-magic-token".into(),
            payload: json!({ "email": user.email }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("magic-link", "postgres-magic-token", now),
        store.consume_verification("magic-link", "postgres-magic-token", now)
    );
    assert_eq!(
        usize::from(left?.is_some()) + usize::from(right?.is_some()),
        1
    );
    let promoted = store.promote_email_owner(user.id, now).await?.unwrap();
    assert!(promoted.email_verified);
    assert!(store.find_password_hash(user.id).await?.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_sessions WHERE user_id = $1",
        )
        .bind(user.id)
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

fn credential_account(user_id: Uuid, now: chrono::DateTime<Utc>) -> OAuthAccount {
    OAuthAccount {
        id: Uuid::new_v4(),
        user_id,
        issuer: "local:credential".into(),
        account_id: user_id.to_string(),
        provider_id: "credential".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some("credential-hash".into()),
        additional_fields: serde_json::Map::new(),
        created_at: now,
        updated_at: now,
    }
}
