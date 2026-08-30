#![cfg(all(feature = "axum", feature = "sqlite"))]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, DatabaseScimStore, SCIM_GROUP_SCHEMA,
    SCIM_MEDIA_TYPE, SCIM_USER_SCHEMA, ScimActiveUserLink, ScimAuthorizationSource,
    ScimBearerCredential, ScimConnection, ScimError, ScimIdentity, ScimIdentityResolution,
    ScimIdentityResolutionInput, ScimIdentityState, ScimManagedConnectionOptions, ScimOptions,
    ScimPlugin, ScimProjectedUserState, ScimProjection, ScimRoleExistenceInput,
    ScimRoleMappingInput, ScimRoleProjection, ScimScope, ScimStore, ScimTransactionContext,
    ScimUserExternalIdReference, acquire_active_scim_user_link, run_database_transaction,
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
    failures: AtomicUsize,
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
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ScimError::new(500, "injected projection failure"));
        }
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
    ScimPlugin,
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
        managed_connections: Some(ScimManagedConnectionOptions::new("m".repeat(32))),
        ..ScimOptions::default()
    };
    let plugin = ScimPlugin::new(options, scim_store.clone()).unwrap();
    let mut config = AuthConfig::new([232_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.add_plugin(plugin.clone()).unwrap();
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
        plugin,
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

async fn acquire_link(
    auth_store: &SqliteStore,
    connection_id: &str,
    external_id: &str,
) -> Option<ScimActiveUserLink> {
    let reference = ScimUserExternalIdReference {
        connection_id: connection_id.into(),
        external_id: external_id.into(),
    };
    run_database_transaction(auth_store, move |database| {
        Box::pin(async move {
            acquire_active_scim_user_link(reference, ScimTransactionContext { database })
                .await
                .map_err(|error| AuthError::Storage(error.to_string()))
        })
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn core_resources_round_trip_through_native_sqlite_transactions() {
    let (app, store, auth_store, identity, projection, plugin) = application().await;
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
    assert_eq!(
        acquire_link(auth_store.as_ref(), "directory-1", "employee-1")
            .await
            .unwrap(),
        ScimActiveUserLink {
            scim_user_id: user_id.into(),
            user_id: auth_user_id.clone(),
        }
    );
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
    assert!(
        acquire_link(auth_store.as_ref(), "directory-1", "employee-1")
            .await
            .is_none()
    );

    let resolutions_before_relink = identity.resolutions.load(Ordering::SeqCst);
    let (status, relinked) = send_json(
        app.clone(),
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

    projection.failures.store(1, Ordering::SeqCst);
    let interrupted = plugin
        .decommission_connection("directory-1", "directory-1")
        .await
        .unwrap_err();
    assert_eq!(interrupted.status, 500);
    assert_eq!(
        plugin
            .decommission_connection("directory-1", "directory-1")
            .await
            .unwrap(),
        1,
        "a callback failure must release the lease for a clean resume"
    );
    assert!(
        store
            .find_user("directory-1", relinked_id)
            .await
            .unwrap()
            .is_some(),
        "canonical source rows remain for lifecycle history"
    );
    assert!(!identity.states.lock().unwrap().last().unwrap().active);
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
    assert_eq!(
        plugin
            .decommission_connection("directory-1", "directory-1")
            .await
            .unwrap(),
        1,
        "completed retirement is resumable and idempotent"
    );
    let rejected = app
        .oneshot(
            request("GET", "/scim/v2/Users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn managed_catalog_round_trips_and_authenticates_through_sqlite() {
    let (app, _, _, _, _, plugin) = application().await;
    let expires_at = Utc::now() + Duration::hours(1);
    let (connection, credential, token) = plugin
        .create_managed_connection(
            "managed-request-0001",
            "managed-domain",
            "operator-1",
            ScimScope::ALL.to_vec(),
            expires_at,
        )
        .await
        .unwrap();
    assert_eq!(connection.revision, 2);
    assert_eq!(credential.status, "active");

    let duplicate = plugin
        .create_managed_connection(
            "managed-request-0001",
            "managed-domain",
            "operator-1",
            ScimScope::ALL.to_vec(),
            expires_at,
        )
        .await
        .unwrap_err();
    assert_eq!(duplicate.status, 409, "{duplicate:?}");

    let authenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);

    let (rotated_connection, rotated, _) = plugin
        .rotate_managed_credential(
            &connection.connection_id,
            "managed-domain",
            "operator-2",
            ScimScope::ALL.to_vec(),
            expires_at,
        )
        .await
        .unwrap();
    assert_eq!(rotated_connection.revision, 3);
    assert_eq!(rotated.status, "active");

    let (revoked_connection, credentials) = plugin
        .revoke_managed_credential(
            &connection.connection_id,
            "managed-domain",
            &credential.credential_id,
            "operator-3",
        )
        .await
        .unwrap();
    assert_eq!(revoked_connection.revision, 4);
    assert_eq!(credentials.len(), 2);
    assert!(credentials.iter().any(|item| item.status == "revoked"));

    let events = plugin
        .list_managed_connection_events(&connection.connection_id, "managed-domain")
        .await
        .unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let (decommissioned, credentials) = plugin
        .decommission_managed_connection(&connection.connection_id, "managed-domain", "operator-4")
        .await
        .unwrap();
    assert_eq!(decommissioned.status, "decommissioned");
    assert_eq!(decommissioned.revision, 6);
    assert!(credentials.iter().all(|item| item.status != "active"));

    let rejected = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}
