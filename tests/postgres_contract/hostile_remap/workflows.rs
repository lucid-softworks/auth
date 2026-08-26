use super::super::{database_create, database_id_plan};
use chrono::{Duration, Utc};
use lucid_auth::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AuthService, AuthSession, AuthStore, AuthenticationMethod, NewPasswordUser, OAuthAccount,
    OAuthAccountStore, RateLimitRule, SecurityStore, VerificationStore, VerificationValue,
    postgres::PostgresStore,
};
use serde_json::{Map, json};
use std::sync::Arc;

pub(super) async fn assert_all(
    service: &AuthService,
    store: &Arc<PostgresStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = signup(service, "alpha", "Alpha Remap").await?;
    let second = signup(service, "zenith", "Zenith Remap").await?;
    let loaded = store
        .find_user_by_email("ALPHA@REMAP.EXAMPLE")
        .await?
        .expect("remapped user lookup");
    assert_eq!(loaded.id, first.id);

    assert_admin_queries(store, &first.id, &second.id).await?;
    assert_session_lifecycle(store, &first.id).await?;
    assert_oauth_lifecycle(store, &first.id).await?;
    assert_verification_lifecycle(store).await?;
    let id = database_id_plan("rateLimit");
    let prepare_id = || id.prepare(store.as_ref());
    let outcome = store
        .consume_rate_limit(
            &prepare_id,
            "hostile-remap-rate-key",
            Utc::now(),
            RateLimitRule::new(60, 2),
            60,
        )
        .await?;
    assert!(outcome.allowed);
    Ok(())
}

async fn signup(
    service: &AuthService,
    username: &str,
    name: &str,
) -> Result<lucid_auth::AuthUser, lucid_auth::AuthError> {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: name.into(),
            email: Some(format!("{username}@remap.example")),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
}

async fn assert_admin_queries(
    store: &PostgresStore,
    first: &str,
    second: &str,
) -> Result<(), lucid_auth::AuthError> {
    let conditions = vec![AdminListCondition {
        field: "email".into(),
        operator: AdminListOperator::EndsWith,
        value: json!("@remap.example"),
    }];
    let query = AdminListUsersQuery {
        limit: 10,
        offset: 0,
        sort_by: Some("name".into()),
        sort_direction: AdminSortDirection::Desc,
        conditions: conditions.clone(),
    };
    let users = store.list_users(&query).await?;
    assert_eq!(
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        [second, first]
    );
    assert_eq!(store.count_users(&conditions).await?, 2);
    Ok(())
}

async fn assert_session_lifecycle(
    store: &PostgresStore,
    user_id: &str,
) -> Result<(), lucid_auth::AuthError> {
    let now = Utc::now();
    let session = AuthSession {
        id: String::new(),
        user_id: user_id.to_owned(),
        token: "hostile-remap-session".into(),
        actor_user_id: None,
        authentication_method: Some(AuthenticationMethod::Password),
        expires_at: now + Duration::hours(1),
        created_at: now,
        updated_at: now,
        ip_address: Some("192.0.2.95".into()),
        user_agent: Some("hostile-remap/1.0".into()),
        additional_fields: Map::new(),
    };
    let session = store
        .create_session(database_create(session, "session"))
        .await?;
    let loaded = store
        .find_session(&session.token)
        .await?
        .expect("remapped session");
    assert_eq!(loaded.0.id, session.id);
    assert_eq!(loaded.1.id, user_id);

    let updated = store
        .update_session_fields(
            &session.id,
            Map::from_iter([
                ("ipAddress".into(), json!("198.51.100.95")),
                ("userAgent".into(), json!("updated-remap/1.0")),
            ]),
        )
        .await?
        .expect("updated remapped session");
    assert_eq!(updated.ip_address.as_deref(), Some("198.51.100.95"));
    assert_eq!(updated.user_agent.as_deref(), Some("updated-remap/1.0"));
    store.delete_session(&session.token).await?;
    assert!(store.find_session(&session.token).await?.is_none());
    Ok(())
}

async fn assert_oauth_lifecycle(
    store: &PostgresStore,
    user_id: &str,
) -> Result<(), lucid_auth::AuthError> {
    let now = Utc::now();
    let account = OAuthAccount {
        id: String::new(),
        user_id: user_id.to_owned(),
        issuer: "https://hostile-remap.example".into(),
        account_id: "remote-subject".into(),
        provider_id: "hostile-provider".into(),
        access_token: Some("first-access".into()),
        refresh_token: Some("first-refresh".into()),
        id_token: Some("first-id".into()),
        access_token_expires_at: Some(now + Duration::hours(1)),
        refresh_token_expires_at: Some(now + Duration::days(30)),
        scope: Some("openid profile".into()),
        password: None,
        additional_fields: Map::new(),
        created_at: now,
        updated_at: now,
    };
    let mut linked = store
        .link_oauth_account(database_create(account, "account"))
        .await?;
    let owner = store
        .find_oauth_account_owner(&linked.issuer, &linked.account_id)
        .await?
        .expect("remapped OAuth owner");
    assert_eq!(owner.user.id, user_id);
    assert_eq!(owner.account.id, linked.id);

    linked.access_token = Some("rotated-access".into());
    linked.refresh_token = Some("rotated-refresh".into());
    linked.updated_at += Duration::milliseconds(1);
    let updated = store.update_oauth_account_tokens(linked).await?;
    assert_eq!(updated.access_token.as_deref(), Some("rotated-access"));
    assert_eq!(updated.refresh_token.as_deref(), Some("rotated-refresh"));
    Ok(())
}

async fn assert_verification_lifecycle(store: &PostgresStore) -> Result<(), lucid_auth::AuthError> {
    let expires = Utc::now() + Duration::minutes(5);
    let consumed = store
        .create_verification(database_create(
            VerificationValue::new("remap-consume", "first", expires),
            "verification",
        ))
        .await?;
    assert_eq!(
        store
            .find_verification("remap-consume")
            .await?
            .expect("remapped verification")
            .id,
        consumed.id
    );
    let mut consumed = consumed;
    consumed.value = "updated".into();
    consumed.updated_at += Duration::milliseconds(1);
    let updated = store
        .update_verification(consumed)
        .await?
        .expect("updated remapped verification");
    assert_eq!(updated.value, "updated");
    assert_eq!(
        store
            .consume_verification("remap-consume")
            .await?
            .expect("consumed remapped verification")
            .value,
        "updated"
    );
    assert!(store.consume_verification("remap-consume").await?.is_none());

    store
        .create_verification(database_create(
            VerificationValue::new("remap-delete", "delete", expires),
            "verification",
        ))
        .await?;
    assert!(store.delete_verification("remap-delete").await?.is_some());
    assert!(store.delete_verification("remap-delete").await?.is_none());
    Ok(())
}
