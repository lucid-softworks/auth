use super::{ADDRESS, Nonce, Verifier, message};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, BeforeDatabaseCreateHook, DatabaseCreateRecord,
    DatabaseHookContext, DatabaseHooks, DatabaseIdInput, DatabaseModel, DatabaseRecord,
    MemoryStore, SiweConfig, SiwePlugin,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Default)]
struct CreateHookAudit {
    events: Mutex<Vec<String>>,
    cancel_account: bool,
}

#[async_trait]
impl DatabaseHooks for CreateHookAudit {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        match record.model() {
            DatabaseModel::User => {
                assert_eq!(record.id(), &DatabaseIdInput::Absent);
                self.events.lock().await.push("before:user:absent".into());
            }
            DatabaseModel::Account => {
                assert_eq!(record.id(), &DatabaseIdInput::Absent);
                assert!(
                    record
                        .get("userId")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !id.is_empty())
                );
                self.events
                    .lock()
                    .await
                    .push("before:account:persisted-user-id".into());
                if self.cancel_account {
                    return Ok(BeforeDatabaseCreateHook::Cancel);
                }
            }
            _ => {}
        }
        Ok(BeforeDatabaseCreateHook::Continue)
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        match record {
            DatabaseRecord::User(user) => {
                assert!(!user.id.is_empty());
                self.events.lock().await.push("after:user".into());
            }
            DatabaseRecord::Account(account) if account.provider_id == "siwe" => {
                assert!(!account.id.is_empty());
                assert!(!account.user_id.is_empty());
                self.events.lock().await.push("after:account".into());
            }
            _ => {}
        }
        Ok(())
    }
}

fn application(
    nonce: &'static str,
    hooks: Arc<CreateHookAudit>,
) -> (axum::Router, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([129_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.database_hooks = Some(hooks);
    config
        .add_plugin(SiwePlugin::new(
            store.clone(),
            SiweConfig::new("example.com", Arc::new(Nonce(nonce)), Arc::new(Verifier)),
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(store.clone(), config).unwrap());
    (lucid_auth::axum::router(service), store)
}

async fn verify(app: axum::Router, nonce: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    app.oneshot(
        Request::post("/api/auth/siwe/verify")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "https://example.com")
            .body(Body::from(
                json!({
                    "message": message(nonce, "example.com"),
                    "signature": "0xsigned"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn identity_create_hooks_observe_absent_then_persisted_ids_in_order() {
    let hooks = Arc::new(CreateHookAudit::default());
    let (app, _) = application("hooks001", hooks.clone());
    assert_eq!(verify(app, "hooks001").await.status(), StatusCode::OK);
    assert_eq!(
        *hooks.events.lock().await,
        vec![
            "before:user:absent".to_owned(),
            "before:account:persisted-user-id".to_owned(),
            "after:user".to_owned(),
            "after:account".to_owned(),
        ]
    );
}

#[tokio::test]
async fn cancelled_dependent_account_hook_rolls_back_the_siwe_user() {
    let hooks = Arc::new(CreateHookAudit {
        cancel_account: true,
        ..CreateHookAudit::default()
    });
    let (app, store) = application("hooks002", hooks.clone());
    assert_ne!(verify(app, "hooks002").await.status(), StatusCode::OK);
    assert!(
        store
            .find_user_by_email(&format!("{ADDRESS}@example.com"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *hooks.events.lock().await,
        vec![
            "before:user:absent".to_owned(),
            "before:account:persisted-user-id".to_owned(),
        ]
    );
}
