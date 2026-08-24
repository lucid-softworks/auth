#![cfg(feature = "axum")]

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdditionalField, AdditionalFieldTransform, AdditionalFieldType, AuthConfig, AuthError,
    AuthPlugin, AuthService, BeforeDatabaseHook, DatabaseHookContext, DatabaseHooks, DatabaseModel,
    DatabaseRecord, MemoryStore, PluginDescriptor, PluginSchemaField,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct RecordingHooks {
    label: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    cancel: bool,
    fail_after: bool,
}

#[async_trait]
impl DatabaseHooks for RecordingHooks {
    async fn before_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        let path = context
            .request
            .as_ref()
            .map(|request| request.path.as_str())
            .unwrap_or("native");
        self.events.lock().await.push(format!(
            "{}:before:{}:{path}",
            self.label,
            record.model().as_str()
        ));
        if self.cancel {
            return Ok(BeforeDatabaseHook::Cancel);
        }
        let mut replacement = record.clone();
        if let DatabaseRecord::User(user) = &mut replacement {
            user.name.push_str(self.label);
        }
        Ok(BeforeDatabaseHook::replace(replacement))
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.events
            .lock()
            .await
            .push(format!("{}:after:{}", self.label, record.model().as_str()));
        if self.fail_after {
            return Err(AuthError::Storage("after hook failed".into()));
        }
        Ok(())
    }

    async fn before_delete(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<bool, AuthError> {
        let path = context
            .request
            .as_ref()
            .map(|request| request.path.as_str())
            .unwrap_or("native");
        self.events.lock().await.push(format!(
            "{}:before-delete:{}:{path}",
            self.label,
            record.model().as_str()
        ));
        Ok(!self.cancel)
    }

    async fn after_delete(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.events.lock().await.push(format!(
            "{}:after-delete:{}",
            self.label,
            record.model().as_str()
        ));
        Ok(())
    }
}

struct SchemaPlugin {
    hooks: RecordingHooks,
}

#[async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "schema-test",
            display_name: "Schema test",
            version: "1.0.0",
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        vec![
            PluginSchemaField::new(
                DatabaseModel::User,
                "tier",
                AdditionalField::new(AdditionalFieldType::String).default_value(json!("free")),
            ),
            PluginSchemaField::new(
                DatabaseModel::Account,
                "credentialTag",
                AdditionalField::new(AdditionalFieldType::String).default_value(json!("local")),
            ),
        ]
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        Some(&self.hooks)
    }
}

async fn signup(app: &axum::Router, email: &str, fields: Value) -> (StatusCode, Value) {
    let mut body = json!({
        "name": "Casey",
        "email": email,
        "password": "correct horse battery staple"
    });
    body.as_object_mut()
        .unwrap()
        .extend(fields.as_object().cloned().unwrap_or_default());
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email?source=contract")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, body)
}

fn configured_hooks(events: Arc<Mutex<Vec<String>>>) -> AuthConfig {
    let mut config = AuthConfig::new([61_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.auto_sign_in = false;
    config.user.additional_fields.insert(
        "timezone".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .default_value(json!("UTC"))
            .transform_input(Arc::new(|value: Value| {
                Ok(Value::String(
                    value.as_str().unwrap_or_default().to_uppercase(),
                ))
            }) as Arc<dyn AdditionalFieldTransform>),
    );
    config.user.additional_fields.insert(
        "internalCode".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .default_value(json!("hidden"))
            .input(false)
            .returned(false),
    );
    config
        .add_plugin(SchemaPlugin {
            hooks: RecordingHooks {
                label: "-plugin",
                events: events.clone(),
                cancel: false,
                fail_after: false,
            },
        })
        .unwrap();
    config.database_hooks = Some(Arc::new(RecordingHooks {
        label: "-host",
        events,
        cancel: false,
        fail_after: false,
    }));
    config
}

#[tokio::test]
async fn plugin_and_host_hooks_wrap_typed_additional_fields_in_better_auth_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = configured_hooks(events.clone());
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    assert!(
        service
            .database_schema_fields(DatabaseModel::User)
            .contains_key("tier")
    );
    let app = lucid_auth::axum::router(service.clone());

    let (status, response) = signup(
        &app,
        "hooks@example.com",
        json!({ "timezone": "europe/london" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["user"]["name"], "Casey-plugin-host");
    assert_eq!(response["user"]["timezone"], "EUROPE/LONDON");
    assert_eq!(response["user"]["tier"], "free");
    assert!(response["user"].get("internalCode").is_none());
    let user_id = uuid::Uuid::parse_str(response["user"]["id"].as_str().unwrap()).unwrap();
    let credential = lucid_auth::OAuthAccountStore::find_oauth_account_owner(
        store.as_ref(),
        "local:credential",
        &user_id.to_string(),
    )
    .await
    .unwrap()
    .expect("credential account");
    assert_eq!(
        credential.account.additional_fields["credentialTag"],
        "local"
    );
    assert_eq!(
        *events.lock().await,
        vec![
            "-plugin:before:user:/sign-up/email",
            "-host:before:user:/sign-up/email",
            "-plugin:before:account:/sign-up/email",
            "-host:before:account:/sign-up/email",
            "-plugin:after:user",
            "-host:after:user",
            "-plugin:after:account",
            "-host:after:account",
        ]
    );
}

#[tokio::test]
async fn a_cancelled_before_hook_leaves_no_user_behind() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new([62_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.database_hooks = Some(Arc::new(RecordingHooks {
        label: "-host",
        events,
        cancel: true,
        fail_after: false,
    }));
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    let app = lucid_auth::axum::router(service);

    let (status, _) = signup(&app, "cancelled@example.com", json!({})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        lucid_auth::AuthStore::find_user_by_email(store.as_ref(), "cancelled@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn after_hook_errors_do_not_roll_back_a_committed_write() {
    let mut config = AuthConfig::new([63_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.auto_sign_in = false;
    config.database_hooks = Some(Arc::new(RecordingHooks {
        label: "-host",
        events: Arc::new(Mutex::new(Vec::new())),
        cancel: false,
        fail_after: true,
    }));
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    let app = lucid_auth::axum::router(service);

    let (status, _) = signup(&app, "committed@example.com", json!({})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        lucid_auth::AuthStore::find_user_by_email(store.as_ref(), "committed@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn session_create_and_delete_hooks_cover_sign_in_and_sign_out() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new([64_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("http://localhost").unwrap();
    config.database_hooks = Some(Arc::new(RecordingHooks {
        label: "-host",
        events: events.clone(),
        cancel: false,
        fail_after: false,
    }));
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let app = lucid_auth::axum::router(service.clone());
    let (status, response) = signup(&app, "session-hooks@example.com", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let token = response["token"].as_str().unwrap();
    let signed_token = service.signed_cookie_value(token);
    let response = app
        .oneshot(
            Request::post("/api/auth/sign-out")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .header(
                    header::COOKIE,
                    format!("better-auth.session_token={signed_token}"),
                )
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = events.lock().await;
    assert!(
        events
            .iter()
            .any(|event| event == "-host:before:session:/sign-up/email")
    );
    assert!(events.iter().any(|event| event == "-host:after:session"));
    assert!(
        events
            .iter()
            .any(|event| event == "-host:before-delete:session:/sign-out")
    );
    assert!(
        events
            .iter()
            .any(|event| event == "-host:after-delete:session")
    );
}
