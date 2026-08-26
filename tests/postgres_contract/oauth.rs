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
    assert_eq!(loaded.account.additional_fields["tenant"], "alpha");
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
    store.link_oauth_account(second.clone()).await?;
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

    assert_token_rotation_is_atomic(store, user_id, &second).await?;
    assert_oauth_columns(pool).await?;
    Ok(())
}

pub(super) async fn assert_one_tap_account_and_session_persistence(
    store: &PostgresStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user = AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: "PostgreSQL One Tap User".into(),
        email: "postgres-one-tap@example.com".into(),
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
    let mut account = fixture_account(
        user.id,
        "https://accounts.google.com",
        "postgres-one-tap-subject",
        "google",
    );
    account.access_token = None;
    account.refresh_token = None;
    account.id_token = Some("encrypted-google-id-token".into());
    account.scope = Some("openid,profile,email".into());
    store.create_oauth_user(user.clone(), account).await?;

    let session = AuthSession {
        id: Uuid::new_v4(),
        user_id: user.id,
        token: "postgres-one-tap-session".into(),
        actor_user_id: None,
        authentication_method: Some(AuthenticationMethod::OAuth),
        expires_at: now + chrono::Duration::days(7),
        created_at: now,
        updated_at: now,
        ip_address: Some("192.0.2.55".into()),
        user_agent: Some("one-tap-postgres-contract".into()),
        additional_fields: serde_json::Map::new(),
    };
    store.create_session(session).await?;
    let persisted = store
        .find_session("postgres-one-tap-session")
        .await?
        .expect("One Tap session persists");
    assert_eq!(persisted.0.authentication_method, None);
    assert_eq!(persisted.1.id, user.id);
    let owner = store
        .find_oauth_account_owner("https://accounts.google.com", "postgres-one-tap-subject")
        .await?
        .expect("One Tap Google account persists");
    assert_eq!(owner.account.provider_id, "google");
    assert_eq!(owner.account.scope.as_deref(), Some("openid,profile,email"));
    assert_eq!(
        owner.account.id_token.as_deref(),
        Some("encrypted-google-id-token")
    );
    Ok(())
}

async fn assert_token_rotation_is_atomic(
    store: &PostgresStore,
    user_id: Uuid,
    second: &OAuthAccount,
) -> Result<(), AuthError> {
    let stored = store
        .find_oauth_account_owner(&second.issuer, &second.account_id)
        .await?
        .expect("linked account")
        .account;
    let mut rotated = stored.clone();
    rotated.access_token = Some("rotated-access".into());
    rotated.refresh_token = Some("rotated-refresh".into());
    rotated.updated_at += chrono::Duration::milliseconds(1);
    assert!(matches!(
        store
            .compare_and_swap_oauth_tokens(
                rotated,
                stored.refresh_token.as_deref(),
                stored.updated_at,
            )
            .await?,
        OAuthTokenUpdateOutcome::Updated(_)
    ));
    let mut stale = stored.clone();
    stale.access_token = Some("stale-access".into());
    stale.updated_at += chrono::Duration::milliseconds(2);
    let OAuthTokenUpdateOutcome::Stale(winner) = store
        .compare_and_swap_oauth_tokens(stale, stored.refresh_token.as_deref(), stored.updated_at)
        .await?
    else {
        panic!("stale refresh must reload the winning token set");
    };
    assert_eq!(winner.access_token.as_deref(), Some("rotated-access"));

    assert_eq!(
        store.delete_user_account(user_id, second.id, false).await?,
        AccountDeleteOutcome::Deleted
    );
    let final_account = store
        .list_user_accounts(user_id)
        .await?
        .into_iter()
        .next()
        .expect("remaining account");
    assert_eq!(
        store
            .delete_user_account(user_id, final_account.id, false)
            .await?,
        AccountDeleteOutcome::LastAccount
    );
    Ok(())
}

async fn assert_oauth_columns(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'account' \
         AND column_name IN ('issuer', 'accessToken', 'refreshToken', 'idToken', \
           'accessTokenExpiresAt', 'refreshTokenExpiresAt', 'scope') \
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
        additional_fields: serde_json::Map::from_iter([(
            "tenant".into(),
            serde_json::json!("alpha"),
        )]),
        created_at: now,
        updated_at: now,
    }
}
