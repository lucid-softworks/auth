#![cfg(feature = "postgres")]

use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, BeforeDatabaseCreateHook, DatabaseCreate,
    DatabaseCreateRecord, DatabaseHookContext, DatabaseHooks, DatabaseIdGeneration,
    DatabaseIdInput, DatabaseIdPlan, DatabaseModel, DatabaseRecord, EmailSignUpInput,
    VerificationStore, VerificationValue,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct ReentrantHooks {
    store: PostgresStore,
    cancel_account: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<String>>>,
    verification_identifier: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl DatabaseHooks for ReentrantHooks {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        self.events
            .lock()
            .await
            .push(format!("before:{}", record.model().as_str()));
        context.transaction.as_ref().ok_or_else(|| {
            AuthError::Storage("before hook did not receive the active transaction".into())
        })?;
        if record.model() != DatabaseModel::Account {
            return Ok(BeforeDatabaseCreateHook::Continue);
        }
        let user_id = record
            .get("userId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AuthError::Storage("account hook did not receive a user ID".into()))?;
        assert!(self.store.find_user_by_id(user_id).await?.is_some());
        let identifier = format!("postgres-hook-{user_id}");
        let verification = VerificationValue::new(
            identifier.clone(),
            "staged",
            chrono::Utc::now() + chrono::Duration::minutes(5),
        );
        self.store
            .create_verification(DatabaseCreate::new(
                verification,
                DatabaseIdPlan::new(
                    DatabaseIdGeneration::Default,
                    "verification",
                    DatabaseIdInput::Absent,
                    true,
                ),
            ))
            .await?;
        *self.verification_identifier.lock().await = Some(identifier);
        Ok(if self.cancel_account.load(Ordering::Acquire) {
            BeforeDatabaseCreateHook::Cancel
        } else {
            BeforeDatabaseCreateHook::Continue
        })
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        assert!(context.transaction.is_none());
        if let DatabaseRecord::User(user) = record {
            assert!(self.store.find_user_by_id(&user.id).await?.is_some());
        }
        self.events
            .lock()
            .await
            .push(format!("after:{}", record.model().as_str()));
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn one_connection_hooks_reenter_the_active_remapped_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let database = IsolatedDatabase::connect().await?;
    let result = run_contract(&database.pool).await;
    let cleanup = database.close().await;
    result?;
    cleanup
}

async fn run_contract(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let store = PostgresStore::new(pool.clone(), PostgresAdapterConfig::default());
    let cancel_account = Arc::new(AtomicBool::new(false));
    let events = Arc::new(Mutex::new(Vec::new()));
    let verification_identifier = Arc::new(Mutex::new(None));
    let mut config = AuthConfig::new([67_u8; 32])?;
    config.email_and_password.enabled = true;
    config.email_and_password.auto_sign_in = false;
    config.user.model_name = Some("hook users".into());
    config.user.fields.email = Some("mail address".into());
    config.account.model_name = Some("hook accounts".into());
    config.account.fields.user_id = Some("owner id".into());
    config.verification.model_name = Some("hook verifications".into());
    config.verification.fields.identifier = Some("lookup key".into());
    config.database_hooks = Some(Arc::new(ReentrantHooks {
        store: store.clone(),
        cancel_account: cancel_account.clone(),
        events: events.clone(),
        verification_identifier: verification_identifier.clone(),
    }));
    let service = AuthService::try_new(Arc::new(store.clone()), config)?;
    store.migrate().await?;

    let created = service
        .sign_up_email(signup("postgres-hooks@example.com"), None, None)
        .await?;
    assert_eq!(
        *events.lock().await,
        [
            "before:user",
            "before:account",
            "after:user",
            "after:account"
        ]
    );
    let identifier = verification_identifier.lock().await.clone().unwrap();
    assert!(store.find_verification(&identifier).await?.is_some());
    assert!(store.find_user_by_id(&created.user.id).await?.is_some());

    events.lock().await.clear();
    cancel_account.store(true, Ordering::Release);
    let error = service
        .sign_up_email(signup("postgres-rollback@example.com"), None, None)
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::DatabaseHookCancelled { .. }));
    assert!(
        store
            .find_user_by_email("postgres-rollback@example.com")
            .await?
            .is_none()
    );
    let identifier = verification_identifier.lock().await.clone().unwrap();
    assert!(store.find_verification(&identifier).await?.is_none());
    assert_eq!(*events.lock().await, ["before:user", "before:account"]);
    Ok(())
}

fn signup(email: &str) -> EmailSignUpInput {
    EmailSignUpInput {
        name: "Postgres Hooks".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: None,
        display_username: None,
        additional_fields: serde_json::Map::new(),
    }
}

struct IsolatedDatabase {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
}

impl IsolatedDatabase {
    async fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let schema = format!("lucid_hooks_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&admin)
            .await?;
        let search_path = format!("SET search_path TO \"{schema}\"");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&search_path).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await?;
        Ok(Self {
            admin,
            pool,
            schema,
        })
    }

    async fn close(self) -> Result<(), Box<dyn std::error::Error>> {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
