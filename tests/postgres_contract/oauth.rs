use super::*;
use chrono::Utc;

pub(super) async fn assert_issuer_qualified_accounts(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user_id = Uuid::new_v4();
    let user = AuthUser {
        id: user_id,
        username: None,
        display_username: None,
        name: "PostgreSQL OAuth User".into(),
        email: "postgres-oauth@example.com".into(),
        email_verified: true,
        image: None,
        additional_fields: serde_json::Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    };
    let account = fixture_account(
        user_id,
        "https://issuer-one.example",
        "shared-subject",
        "provider-one",
    );
    let owner = store
        .create_oauth_user(user.clone(), account.clone())
        .await?;
    assert_eq!(owner.user.id, user.id);
    assert_eq!(owner.user.email, user.email);
    assert_eq!(owner.user.name, user.name);
    assert_eq!(owner.user.email_verified, user.email_verified);
    let loaded = store
        .find_oauth_account_owner("https://issuer-one.example", "shared-subject")
        .await?
        .expect("issuer-qualified account");
    assert_eq!(loaded.account.id, account.id);
    assert_eq!(
        loaded.account.access_token.as_deref(),
        Some("encrypted-one")
    );

    let second = fixture_account(
        user_id,
        "https://issuer-two.example",
        "shared-subject",
        "provider-two",
    );
    store.link_oauth_account(second).await?;
    assert_eq!(
        store
            .find_oauth_account_owner("https://issuer-two.example", "shared-subject")
            .await?
            .expect("same subject under a different issuer")
            .account
            .provider_id,
        "provider-two"
    );

    let collision = fixture_account(
        user_id,
        "https://issuer-one.example",
        "shared-subject",
        "renamed-provider",
    );
    assert!(matches!(
        store.link_oauth_account(collision).await,
        Err(AuthError::UserAlreadyExists)
    ));

    assert_oauth_columns(pool).await?;
    Ok(())
}

async fn assert_oauth_columns(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'lucid_auth_accounts' \
         AND column_name IN ('issuer', 'access_token', 'refresh_token', 'id_token', \
           'access_token_expires_at', 'refresh_token_expires_at', 'scope') \
         ORDER BY column_name",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(columns.len(), 7);
    Ok(())
}

fn fixture_account(
    user_id: Uuid,
    issuer: &str,
    account_id: &str,
    provider_id: &str,
) -> OAuthAccount {
    let now = Utc::now();
    OAuthAccount {
        id: Uuid::new_v4(),
        user_id,
        issuer: issuer.into(),
        account_id: account_id.into(),
        provider_id: provider_id.into(),
        access_token: Some("encrypted-one".into()),
        refresh_token: Some("encrypted-two".into()),
        id_token: Some("encrypted-three".into()),
        access_token_expires_at: Some(now + chrono::Duration::hours(1)),
        refresh_token_expires_at: Some(now + chrono::Duration::days(30)),
        scope: Some("openid,email".into()),
        password: None,
        created_at: now,
        updated_at: now,
    }
}
