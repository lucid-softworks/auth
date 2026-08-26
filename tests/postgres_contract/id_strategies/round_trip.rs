use super::database::StrategyDatabase;
use lucid_auth::{
    AuthStore, DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerationSize, DatabaseIdGenerator, NewPasswordUser, OAuthAccountStore,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq)]
struct CallbackCall {
    model: String,
    size: DatabaseIdGenerationSize,
}

#[derive(Debug, Default)]
struct CallbackLedger {
    calls: Mutex<Vec<CallbackCall>>,
}

impl CallbackLedger {
    fn snapshot(&self) -> Vec<CallbackCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl DatabaseIdGenerator for CallbackLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut calls = self.calls.lock().unwrap();
        calls.push(CallbackCall {
            model: request.model.to_owned(),
            size: request.size,
        });
        DatabaseIdGenerationResult::Id(format!("callback/{}/{}", request.model, calls.len()))
    }
}

struct CoreRoundTrip {
    user_id: String,
    account_id: String,
    session_id: String,
    token: String,
}

pub(super) async fn all_application_and_native_strategies() -> Result<(), Box<dyn std::error::Error>>
{
    let database = StrategyDatabase::start(DatabaseIdGeneration::Default, "default").await?;
    let ids = exercise(&database, "default", "text").await?;
    for id in [&ids.user_id, &ids.account_id, &ids.session_id] {
        assert!(is_base62(id, 32), "unexpected default ID: {id}");
    }
    database.close().await?;

    let ledger = Arc::new(CallbackLedger::default());
    let database =
        StrategyDatabase::start(DatabaseIdGeneration::Callback(ledger.clone()), "callback").await?;
    let ids = exercise(&database, "callback", "text").await?;
    assert_eq!(
        [&ids.user_id, &ids.account_id, &ids.session_id],
        [
            "callback/user/1",
            "callback/account/2",
            "callback/session/3"
        ]
    );
    assert_eq!(
        ledger.snapshot(),
        [callback("user"), callback("account"), callback("session"),]
    );
    database.close().await?;

    assert_serial_round_trip().await?;
    assert_uuid_round_trip().await
}

async fn assert_serial_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Serial, "serial").await?;
    let ids = exercise(&database, "serial", "integer").await?;
    for id in [&ids.user_id, &ids.account_id, &ids.session_id] {
        assert!(id.parse::<i32>()? > 0, "serial ID is not positive: {id}");
    }
    database.close().await
}

async fn assert_uuid_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Uuid, "uuid").await?;
    let ids = exercise(&database, "uuid", "uuid").await?;
    for id in [&ids.user_id, &ids.account_id, &ids.session_id] {
        uuid::Uuid::parse_str(id)?;
    }
    database.close().await
}

async fn exercise(
    database: &StrategyDatabase,
    label: &str,
    physical_type: &str,
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
    let ids = CoreRoundTrip {
        user_id: user.id,
        account_id: account.id,
        session_id: signed_in.session.session.id,
        token: signed_in.token,
    };
    assert_round_trip(database, &ids, physical_type).await?;
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
    assert_physical_types(database, ids, physical_type).await
}

async fn assert_physical_types(
    database: &StrategyDatabase,
    ids: &CoreRoundTrip,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let types = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"SELECT pg_typeof(u.id)::text, pg_typeof(a.id)::text,
                  pg_typeof(a."userId")::text, pg_typeof(s.id)::text,
                  pg_typeof(s."userId")::text
             FROM "user" u
             JOIN "account" a ON a."userId" = u.id
             JOIN "session" s ON s."userId" = u.id
            WHERE u.id::text = $1 AND a.id::text = $2 AND s.id::text = $3"#,
    )
    .bind(&ids.user_id)
    .bind(&ids.account_id)
    .bind(&ids.session_id)
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
            expected,
        )
    );
    Ok(())
}

fn callback(model: &str) -> CallbackCall {
    CallbackCall {
        model: model.into(),
        size: DatabaseIdGenerationSize::Omitted,
    }
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
