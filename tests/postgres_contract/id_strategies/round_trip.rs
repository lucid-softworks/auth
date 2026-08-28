use super::{
    callback::{CallbackLedger, expected as callback},
    database::StrategyDatabase,
    oauth_provider_database, oauth_provider_round_trip, organization_database,
    organization_round_trip, plugin_round_trip,
};
use lucid_auth::{
    AuthStore, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, JwkStore, JwtAdapterContext,
    NewPasswordUser, OAuthAccountStore, TwoFactorRecord, TwoFactorStore,
};
use std::sync::Arc;

#[path = "round_trip/database_strategy.rs"]
mod database_strategy;
#[path = "round_trip/device_code.rs"]
mod device_code;

struct CoreRoundTrip {
    user_id: String,
    account_id: String,
    session_id: String,
    two_factor_id: String,
    jwks_id: String,
    device_code_id: String,
    device_code: String,
    plugins: plugin_round_trip::PluginIds,
    organization: organization_round_trip::OrganizationIds,
    oauth: oauth_provider_round_trip::OAuthIds,
    token: String,
}

pub(super) async fn all_application_and_native_strategies() -> Result<(), Box<dyn std::error::Error>>
{
    let database = StrategyDatabase::start(DatabaseIdGeneration::Default, "default").await?;
    let ids = exercise(&database, "default", "text", None).await?;
    for id in [
        &ids.user_id,
        &ids.account_id,
        &ids.session_id,
        &ids.two_factor_id,
        &ids.jwks_id,
        &ids.device_code_id,
        &ids.plugins.passkey_id,
        &ids.plugins.wallet_id,
    ] {
        assert!(is_base62(id, 32), "unexpected default ID: {id}");
    }
    for id in ids.organization.all() {
        assert!(is_base62(id, 32), "unexpected default ID: {id}");
    }
    for id in ids.oauth.all() {
        assert!(is_base62(id, 32), "unexpected default ID: {id}");
    }
    database.close().await?;

    let ledger = Arc::new(CallbackLedger::default());
    let database =
        StrategyDatabase::start(DatabaseIdGeneration::Callback(ledger.clone()), "callback").await?;
    let ids = exercise(&database, "callback", "text", Some(&ledger)).await?;
    assert_eq!(
        [
            &ids.user_id,
            &ids.account_id,
            &ids.session_id,
            &ids.two_factor_id,
            &ids.jwks_id,
            &ids.device_code_id,
            &ids.plugins.passkey_id,
            &ids.plugins.wallet_id,
        ],
        [
            "callback/user/1",
            "callback/account/2",
            "callback/session/3",
            "callback/twoFactor/4",
            "callback/jwks/5",
            "callback/deviceCode/6",
            "callback/passkey/7",
            "callback/walletAddress/10",
        ]
    );
    assert_eq!(
        &ledger.snapshot()[..12],
        [
            callback("user"),
            callback("account"),
            callback("session"),
            callback("twoFactor"),
            callback("jwks"),
            callback("deviceCode"),
            callback("passkey"),
            callback("verification"),
            callback("user"),
            callback("walletAddress"),
            callback("account"),
            callback("session"),
        ]
    );
    assert_lazy_two_factor_branches(&database, &ledger, &ids).await?;
    plugin_round_trip::assert_lazy_conflicts(&database, &ledger, &ids.user_id, &ids.plugins)
        .await?;
    database.close().await?;

    assert_serial_round_trip().await?;
    assert_uuid_round_trip().await?;
    database_strategy::assert_round_trip().await
}

async fn assert_serial_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Serial, "serial").await?;
    let ids = exercise(&database, "serial", "integer", None).await?;
    for id in [
        &ids.user_id,
        &ids.account_id,
        &ids.session_id,
        &ids.two_factor_id,
        &ids.jwks_id,
        &ids.device_code_id,
        &ids.plugins.passkey_id,
        &ids.plugins.wallet_id,
    ] {
        assert!(id.parse::<i32>()? > 0, "serial ID is not positive: {id}");
    }
    for id in ids.organization.all() {
        assert!(id.parse::<i32>()? > 0, "serial ID is not positive: {id}");
    }
    for id in ids.oauth.all() {
        assert!(id.parse::<i32>()? > 0, "serial ID is not positive: {id}");
    }
    database.close().await
}

async fn assert_uuid_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Uuid, "uuid").await?;
    let ids = exercise(&database, "uuid", "uuid", None).await?;
    for id in [
        &ids.user_id,
        &ids.account_id,
        &ids.session_id,
        &ids.two_factor_id,
        &ids.jwks_id,
        &ids.device_code_id,
        &ids.plugins.passkey_id,
        &ids.plugins.wallet_id,
    ] {
        uuid::Uuid::parse_str(id)?;
    }
    for id in ids.organization.all() {
        uuid::Uuid::parse_str(id)?;
    }
    for id in ids.oauth.all() {
        uuid::Uuid::parse_str(id)?;
    }
    database.close().await
}

async fn exercise(
    database: &StrategyDatabase,
    label: &str,
    physical_type: &str,
    callback_ledger: Option<&CallbackLedger>,
) -> Result<CoreRoundTrip, Box<dyn std::error::Error>> {
    let username = format!("strategy_{label}");
    let user = database
        .service
        .provision_password_user(NewPasswordUser {
            username: username.clone(),
            name: format!("{label} strategy user"),
            email: Some(format!("{label}-strategy@example.com")),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await?;
    let account = database.store.list_user_accounts(&user.id).await?.remove(0);
    let signed_in = database
        .service
        .sign_in_username(&username, "correct horse battery staple".into(), None, None)
        .await?;
    let id = DatabaseIdPlan::new(
        database.strategy.clone(),
        "twoFactor",
        DatabaseIdInput::Absent,
        false,
    );
    let two_factor = database
        .store
        .upsert_two_factor(
            &|| id.prepare(database.store.as_ref()),
            two_factor_record(&user.id, "encrypted-secret"),
        )
        .await?;
    let jwks = database
        .service
        .jwt()
        .expect("strategy fixture installs JWT")
        .create_jwk(&JwtAdapterContext::default(), None)
        .await?;
    let device_code = device_code::create(database, label, &user.id, &database.strategy).await?;
    let plugins = plugin_round_trip::exercise(database, label, &user.id).await?;
    let organization = organization_round_trip::exercise(
        database,
        label,
        &signed_in.session,
        callback_ledger,
        physical_type,
    )
    .await?;
    let oauth = oauth_provider_round_trip::exercise(
        database,
        label,
        &signed_in.session.user.id,
        &signed_in.session.session.id,
        callback_ledger,
        physical_type,
    )
    .await?;
    let ids = CoreRoundTrip {
        user_id: user.id,
        account_id: account.id,
        session_id: signed_in.session.session.id,
        two_factor_id: two_factor.id,
        jwks_id: jwks.id,
        device_code_id: device_code.id,
        device_code: device_code.device_code,
        plugins,
        organization,
        oauth,
        token: signed_in.token,
    };
    assert_round_trip(database, &ids, physical_type).await?;
    device_code::assert_crud(database, &ids).await?;
    assert!(is_base62(&ids.token, 32));
    assert_ne!(ids.token, ids.session_id);
    Ok(ids)
}

async fn assert_round_trip(
    database: &StrategyDatabase,
    ids: &CoreRoundTrip,
    physical_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        database
            .store
            .find_user_by_id(&ids.user_id)
            .await?
            .unwrap()
            .id,
        ids.user_id
    );
    let account = database
        .store
        .list_user_accounts(&ids.user_id)
        .await?
        .remove(0);
    assert_eq!(account.id, ids.account_id);
    assert_eq!(account.user_id, ids.user_id);
    let (session, session_user) = database.store.find_session(&ids.token).await?.unwrap();
    assert_eq!(session.id, ids.session_id);
    assert_eq!(session.user_id, ids.user_id);
    assert_eq!(session_user.id, ids.user_id);
    device_code::assert_round_trip(database, ids).await?;
    assert_physical_types(database, ids, physical_type).await?;
    plugin_round_trip::assert_round_trip(database, &ids.user_id, &ids.plugins, physical_type).await
}

async fn assert_physical_types(
    database: &StrategyDatabase,
    ids: &CoreRoundTrip,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let types = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(
        r#"SELECT pg_typeof(u.id)::text, pg_typeof(a.id)::text,
                  pg_typeof(a."userId")::text, pg_typeof(s.id)::text,
                  pg_typeof(s."userId")::text, pg_typeof(t.id)::text,
                  pg_typeof(t."userId")::text, pg_typeof(j.id)::text
             FROM "user" u
             JOIN "account" a ON a."userId" = u.id
             JOIN "session" s ON s."userId" = u.id
             JOIN "twoFactor" t ON t."userId" = u.id
             CROSS JOIN "jwks" j
            WHERE u.id::text = $1 AND a.id::text = $2 AND s.id::text = $3
              AND t.id::text = $4"#,
    )
    .bind(&ids.user_id)
    .bind(&ids.account_id)
    .bind(&ids.session_id)
    .bind(&ids.two_factor_id)
    .fetch_one(&database.pool)
    .await?;
    let expected = expected.to_owned();
    assert_eq!(
        types,
        (
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected.clone(),
        )
    );
    device_code::assert_physical_types(database, &ids.device_code_id, &expected).await?;
    Ok(())
}

async fn assert_lazy_two_factor_branches(
    database: &StrategyDatabase,
    ledger: &CallbackLedger,
    ids: &CoreRoundTrip,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = DatabaseIdPlan::new(
        database.strategy.clone(),
        "twoFactor",
        DatabaseIdInput::Absent,
        false,
    );
    let updated = database
        .store
        .upsert_two_factor(
            &|| plan.prepare(database.store.as_ref()),
            two_factor_record(&ids.user_id, "replacement-secret"),
        )
        .await?;
    assert_eq!(updated.id, ids.two_factor_id);
    assert_eq!(updated.encrypted_secret, "replacement-secret");
    let callback_count = ledger.snapshot().len();

    let error = database
        .store
        .upsert_two_factor(
            &|| plan.prepare(database.store.as_ref()),
            two_factor_record("missing-parent", "secret"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, lucid_auth::AuthError::NotFound));
    assert_eq!(ledger.snapshot().len(), callback_count);
    Ok(())
}

fn two_factor_record(user_id: &str, secret: &str) -> TwoFactorRecord {
    TwoFactorRecord {
        id: String::new(),
        user_id: user_id.into(),
        encrypted_secret: secret.into(),
        encrypted_backup_codes: "encrypted-codes".into(),
        verified: false,
        failed_verification_count: 0,
        locked_until: None,
    }
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
