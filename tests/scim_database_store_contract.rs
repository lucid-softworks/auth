#![cfg(all(feature = "axum", feature = "sqlite"))]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AuthStore, DatabaseScimStore, SCIM_GROUP_SCHEMA, SCIM_MEDIA_TYPE,
    SCIM_USER_SCHEMA, ScimAuthorizationSource, ScimBearerCredential, ScimConnection, ScimError,
    ScimIdentity, ScimIdentityResolution, ScimIdentityResolutionInput, ScimIdentityState,
    ScimOptions, ScimPlugin, ScimProjectedUserState, ScimProjection, ScimRoleExistenceInput,
    ScimRoleMappingInput, ScimRoleProjection, ScimStore, ScimTransactionContext,
    sqlite::{SqliteAdapterConfig, SqliteStore},
};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

const TOKEN: &str = "database-scim-token";

#[derive(Default)]
struct RecordingIdentity {
    resolutions: AtomicUsize,
    states: Mutex<Vec<ScimIdentityState>>,
}

#[async_trait]
impl ScimIdentity for RecordingIdentity {
    async fn resolve_user(
        &self,
        _input: ScimIdentityResolutionInput,
        context: ScimTransactionContext,
    ) -> Result<ScimIdentityResolution, ScimError> {
        assert_eq!(
            context
                .database
                .count_records("scimConnectionBinding", &[])
                .await
                .unwrap(),
            1
        );
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(ScimIdentityResolution::Create)
    }

    async fn reconcile_user(
        &self,
        input: ScimIdentityState,
        _context: ScimTransactionContext,
    ) -> Result<(), ScimError> {
        self.states.lock().unwrap().push(input);
        Ok(())
    }
}

#[derive(Default)]
struct RecordingProjection {
    states: Mutex<Vec<ScimProjectedUserState>>,
}

#[async_trait]
impl ScimRoleProjection for RecordingProjection {
    async fn map(
        &self,
        input: ScimRoleMappingInput,
        _context: ScimTransactionContext,
    ) -> Result<Option<Vec<String>>, ScimError> {
        let ScimAuthorizationSource::Group { display_name, .. } = input.source;
        Ok((display_name == "Engineering")
            .then(|| vec![" admin ".into(), "admin".into(), "missing".into()]))
    }

    async fn exists(
        &self,
        input: ScimRoleExistenceInput,
        _context: ScimTransactionContext,
    ) -> Result<bool, ScimError> {
        Ok(input.role != "missing")
    }
}

#[async_trait]
impl ScimProjection for RecordingProjection {
    fn roles(&self) -> Option<&dyn ScimRoleProjection> {
        Some(self)
    }

    async fn reconcile_user(
        &self,
        input: ScimProjectedUserState,
        context: ScimTransactionContext,
    ) -> Result<(), ScimError> {
        assert_eq!(
            context
                .database
                .count_records(
                    "scimProjectionGrant",
                    &[lucid_auth::DashAdapterWhere {
                        field: "userId".into(),
                        value: json!(&input.user_id),
                        operator: Default::default(),
                        connector: None,
                    }],
                )
                .await
                .unwrap(),
            input.grants.len() as u64
        );
        self.states.lock().unwrap().push(input);
        Ok(())
    }
}

async fn application() -> (
    Router,
    Arc<DatabaseScimStore>,
    Arc<SqliteStore>,
    Arc<RecordingIdentity>,
    Arc<RecordingProjection>,
) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth_store = Arc::new(SqliteStore::new(pool, SqliteAdapterConfig::default()));
    let scim_store = Arc::new(DatabaseScimStore::new(auth_store.clone()));
    let identity = Arc::new(RecordingIdentity::default());
    let projection = Arc::new(RecordingProjection::default());
    let options = ScimOptions {
        connections: vec![ScimConnection::new(
            "directory-1",
            vec![ScimBearerCredential::new("credential-1", TOKEN)],
        )],
        identity: Some(identity.clone()),
        projection: Some(projection.clone()),
        ..ScimOptions::default()
    };
    let plugin = ScimPlugin::new(options, scim_store.clone()).unwrap();
    let mut config = AuthConfig::new([232_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::new(auth_store.clone(), config));
    auth_store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    (
        lucid_auth::axum::router(service),
        scim_store,
        auth_store,
        identity,
        projection,
    )
}

fn request(method: &str, path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

async fn send_json(app: Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            request(method, path)
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

#[tokio::test]
async fn core_resources_round_trip_through_native_sqlite_transactions() {
    let (app, store, auth_store, identity, projection) = application().await;
    let (status, user) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "employee-1",
            "userName": "luna@example.com",
            "name": {"givenName": "Luna", "familyName": "Lake"},
            "emails": [{"value": "luna@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user:#}");
    let user_id = user["id"].as_str().unwrap();
    let persisted_user = store
        .find_user("directory-1", user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted_user.resource.user_name, "luna@example.com");
    let auth_user_id = persisted_user.user_id.clone();
    assert_eq!(identity.resolutions.load(Ordering::SeqCst), 1);
    assert!(identity.states.lock().unwrap().last().unwrap().active);

    let (status, duplicate) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "LUNA@example.com",
            "name": {"formatted": "Other User"},
            "emails": [{"value": "other@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{duplicate:#}");
    assert!(
        auth_store
            .find_user_by_email("other@example.com")
            .await
            .unwrap()
            .is_none(),
        "the Better Auth user must roll back with the duplicate SCIM row"
    );

    let (status, updated_user) = send_json(
        app.clone(),
        "PUT",
        &format!("/scim/v2/Users/{user_id}"),
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "employee-1",
            "userName": "luna.lake@example.com",
            "name": {"formatted": "Luna Rivers"},
            "emails": [{"value": "luna.rivers@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated_user:#}");
    let auth_user = auth_store
        .find_user_by_id(&auth_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth_user.name, "Luna Rivers");
    assert_eq!(auth_user.email, "luna.rivers@example.com");
    assert!(!auth_user.email_verified);

    let (status, group) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "externalId": "team-1",
            "displayName": "Engineering",
            "members": [{"value": user_id}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group:#}");
    let group_id = group["id"].as_str().unwrap();
    let persisted_group = store
        .find_group("directory-1", group_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted_group.resource.members.len(), 1);
    assert_eq!(persisted_group.resource.members[0].value, user_id);
    let projected = projection.states.lock().unwrap().last().unwrap().clone();
    assert_eq!(projected.grants.len(), 1);
    assert_eq!(projected.grants[0].role, "admin");

    let (status, updated) = send_json(
        app.clone(),
        "PUT",
        &format!("/scim/v2/Groups/{group_id}"),
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Platform",
            "members": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated:#}");
    assert_eq!(updated["displayName"], "Platform");
    assert!(
        projection
            .states
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .grants
            .is_empty()
    );

    let response = app
        .clone()
        .oneshot(
            request("DELETE", &format!("/scim/v2/Users/{user_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        store
            .find_user("directory-1", user_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!identity.states.lock().unwrap().last().unwrap().active);

    let resolutions_before_relink = identity.resolutions.load(Ordering::SeqCst);
    let (status, relinked) = send_json(
        app,
        "POST",
        "/scim/v2/Users",
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "employee-1",
            "userName": "returned@example.com",
            "name": {"formatted": "Luna Returned"},
            "emails": [{"value": "returned@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{relinked:#}");
    assert_eq!(
        identity.resolutions.load(Ordering::SeqCst),
        resolutions_before_relink,
        "a tombstone must resolve before the application callback"
    );
    let relinked_id = relinked["id"].as_str().unwrap();
    assert_eq!(
        store
            .find_user("directory-1", relinked_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        auth_user_id
    );
}
