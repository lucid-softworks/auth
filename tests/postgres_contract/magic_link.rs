use super::{CredentialAccountFixture, database_create};
use chrono::{Duration, Utc};
use lucid_auth::{
    AuthSession, AuthStore, AuthUser, AuthenticationMethod, VerificationStore, VerificationValue,
    postgres::PostgresStore,
};
use serde_json::json;

pub(super) async fn assert_promotion_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let owner = store
        .create_password_user(
            database_create(
                AuthUser {
                    id: String::new(),
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
                "user",
            ),
            &CredentialAccountFixture::new("credential-hash", now),
        )
        .await?;
    let user = owner.user;
    store
        .create_session(database_create(
            AuthSession {
                id: String::new(),
                user_id: user.id.clone(),
                token: "unproven-magic-session".into(),
                actor_user_id: None,
                authentication_method: Some(AuthenticationMethod::Password),
                expires_at: now + Duration::hours(1),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: None,
                additional_fields: serde_json::Map::new(),
            },
            "session",
        ))
        .await?;
    store
        .create_verification(database_create(
            VerificationValue::new(
                "postgres-magic-token",
                json!({ "email": user.email }).to_string(),
                now + Duration::minutes(1),
            ),
            "verification",
        ))
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("postgres-magic-token"),
        store.consume_verification("postgres-magic-token")
    );
    assert_eq!(
        usize::from(left?.is_some()) + usize::from(right?.is_some()),
        1
    );
    let promoted = store.promote_email_owner(&user.id, now).await?.unwrap();
    assert!(promoted.email_verified);
    assert!(store.find_password_hash(&user.id).await?.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM \"session\" WHERE \"userId\" = $1",)
            .bind(&user.id)
            .fetch_one(pool)
            .await?,
        0
    );
    Ok(())
}
