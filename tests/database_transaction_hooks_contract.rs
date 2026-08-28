#![cfg(feature = "axum")]

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, BeforeDatabaseCreateHook,
    BeforeDatabaseUpdateHook, DatabaseCreate, DatabaseCreateRecord, DatabaseHookContext,
    DatabaseHooks, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, DatabaseModel,
    DatabaseRecord, DatabaseUpdatePatch, DatabaseUpdateRecord, MemoryStore, NewPasswordUser,
    VerificationStore, VerificationValue,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct ReentrantHooks {
    store: MemoryStore,
    events: Arc<Mutex<Vec<String>>>,
    cancel_account: bool,
    cancel_update_model: Arc<Mutex<Option<DatabaseModel>>>,
    verification_id: Arc<Mutex<Option<String>>>,
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
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage("account hook did not receive a user ID".into()))?;
        let committed_store = self.store.clone();
        let committed_id = user_id.to_owned();
        assert!(
            tokio::spawn(async move { committed_store.find_user_by_id(&committed_id).await })
                .await
                .map_err(|error| AuthError::Storage(format!("visibility task failed: {error}")))??
                .is_none()
        );
        assert!(self.store.find_user_by_id(user_id).await?.is_some());
        let verification = VerificationValue::new(
            format!("hook-{user_id}"),
            "staged",
            chrono::Utc::now() + chrono::Duration::minutes(5),
        );
        let verification = self
            .store
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
        *self.verification_id.lock().await = Some(verification.identifier);
        Ok(if self.cancel_account {
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
        self.events
            .lock()
            .await
            .push(format!("after:{}", record.model().as_str()));
        Ok(())
    }

    async fn before_update(
        &self,
        record: &DatabaseUpdateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseUpdateHook, AuthError> {
        self.events
            .lock()
            .await
            .push(format!("before-update:{}", record.model().as_str()));
        context.transaction.as_ref().ok_or_else(|| {
            AuthError::Storage("before-update hook did not receive the active transaction".into())
        })?;
        let user_id = match record.model() {
            DatabaseModel::User => record.get("id"),
            DatabaseModel::Account => record.get("userId"),
            _ => None,
        }
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Storage("update hook did not receive a user ID".into()))?;
        let staged_user = self.store.find_user_by_id(user_id).await?.ok_or_else(|| {
            AuthError::Storage("update hook could not read the staged user".into())
        })?;
        if record.model() == DatabaseModel::Account && staged_user.name != "Hooked by update" {
            return Err(AuthError::Storage(
                "account hook did not observe the staged user update".into(),
            ));
        }
        if self.cancel_update_model.lock().await.as_ref() == Some(&record.model()) {
            return Ok(BeforeDatabaseUpdateHook::Cancel);
        }
        Ok(if record.model() == DatabaseModel::User {
            BeforeDatabaseUpdateHook::merge(
                DatabaseUpdatePatch::new().with_field("name", json!("Hooked by update")),
            )
        } else {
            BeforeDatabaseUpdateHook::Continue
        })
    }

    async fn after_update(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        assert!(context.transaction.is_none());
        let suffix = match record {
            DatabaseRecord::User(user) => format!(":{}", user.name),
            _ => String::new(),
        };
        self.events
            .lock()
            .await
            .push(format!("after-update:{}{suffix}", record.model().as_str()));
        Ok(())
    }
}

async fn signup(app: &axum::Router, email: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Casey",
                        "email": email,
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, body)
}

#[tokio::test]
async fn account_hook_reentry_sees_the_staged_user_and_commits_with_the_pair() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let verification_id = Arc::new(Mutex::new(None));
    let store = MemoryStore::default();
    let mut config = AuthConfig::new([65_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.auto_sign_in = false;
    config.database_hooks = Some(Arc::new(ReentrantHooks {
        store: store.clone(),
        events: events.clone(),
        cancel_account: false,
        cancel_update_model: Arc::new(Mutex::new(None)),
        verification_id: verification_id.clone(),
    }));
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(Arc::new(store.clone()), config)));

    let (status, response) = signup(&app, "reentrant@example.com").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        *events.lock().await,
        [
            "before:user",
            "before:account",
            "after:user",
            "after:account"
        ]
    );
    let verification_identifier = verification_id.lock().await.clone().unwrap();
    assert!(
        store
            .find_verification(&verification_identifier)
            .await
            .unwrap()
            .is_some_and(|value| value.identifier == verification_identifier)
    );
}

#[tokio::test]
async fn account_hook_cancellation_rolls_back_user_and_reentrant_writes() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let verification_id = Arc::new(Mutex::new(None));
    let store = MemoryStore::default();
    let mut config = AuthConfig::new([66_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.database_hooks = Some(Arc::new(ReentrantHooks {
        store: store.clone(),
        events: events.clone(),
        cancel_account: true,
        cancel_update_model: Arc::new(Mutex::new(None)),
        verification_id: verification_id.clone(),
    }));
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(Arc::new(store.clone()), config)));

    let (status, _) = signup(&app, "rollback-account@example.com").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        store
            .find_user_by_email("rollback-account@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_verification(verification_id.lock().await.as_deref().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(*events.lock().await, ["before:user", "before:account"]);
}

#[tokio::test]
async fn credential_update_hooks_share_staged_state_and_account_cancellation_rolls_back() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let cancel_update_model = Arc::new(Mutex::new(None));
    let store = MemoryStore::default();
    let mut config = AuthConfig::new([67_u8; 32]).unwrap();
    config.database_hooks = Some(Arc::new(ReentrantHooks {
        store: store.clone(),
        events: events.clone(),
        cancel_account: false,
        cancel_update_model: cancel_update_model.clone(),
        verification_id: Arc::new(Mutex::new(None)),
    }));
    let service = AuthService::new(Arc::new(store.clone()), config);
    let input = |name: &str| NewPasswordUser {
        username: "update_hook_user".into(),
        name: name.into(),
        email: Some("update-hook@example.com".into()),
        password: "correct horse battery staple".into(),
        role: "user".into(),
    };

    service
        .provision_password_user(input("Initial"))
        .await
        .unwrap();
    events.lock().await.clear();

    let updated = service
        .provision_password_user(input("Candidate"))
        .await
        .unwrap();
    assert_eq!(updated.name, "Hooked by update");
    assert_eq!(
        *events.lock().await,
        [
            "before-update:user",
            "before-update:account",
            "after-update:user:Hooked by update",
            "after-update:account",
        ]
    );

    events.lock().await.clear();
    *cancel_update_model.lock().await = Some(DatabaseModel::Account);
    let error = service
        .provision_password_user(input("Must roll back"))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::DatabaseHookCancelled { .. }));
    assert_eq!(
        store
            .find_user_by_username("update_hook_user")
            .await
            .unwrap()
            .unwrap()
            .name,
        "Hooked by update"
    );
    assert_eq!(
        *events.lock().await,
        ["before-update:user", "before-update:account"]
    );
}
