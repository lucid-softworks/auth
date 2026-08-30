use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AuthStore, MemoryScimStore, MemoryStore, OAuthAccountStore,
    SCIM_ENTERPRISE_USER_SCHEMA, SCIM_GROUP_SCHEMA, SCIM_LIST_RESPONSE_SCHEMA, SCIM_MEDIA_TYPE,
    SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA, ScimBearerCredential, ScimBearerTokenVerifier,
    ScimConnection, ScimError, ScimManagedConnectionOptions, ScimOptions, ScimPlugin, ScimScope,
    ScimVerifiedBearer,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

const TOKEN: &str = "scim-test-bearer-token";

struct CountingVerifier {
    calls: AtomicUsize,
    connection_id: String,
}

impl CountingVerifier {
    fn new(connection_id: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            connection_id: connection_id.into(),
        }
    }
}

#[async_trait]
impl ScimBearerTokenVerifier for CountingVerifier {
    async fn verify(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
        _headers: &BTreeMap<String, String>,
    ) -> Result<Option<ScimVerifiedBearer>, ScimError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ScimVerifiedBearer {
            connection_id: self.connection_id.clone(),
            provisioning_domain_id: self.connection_id.clone(),
            credential_id: "custom".into(),
            scopes: ScimScope::ALL.to_vec(),
            expires_at: None,
        }))
    }
}

fn options() -> ScimOptions {
    ScimOptions {
        connections: vec![ScimConnection::new(
            "directory-1",
            vec![ScimBearerCredential::new("credential-1", TOKEN)],
        )],
        ..ScimOptions::default()
    }
}

fn application_with_options(
    options: ScimOptions,
) -> (Router, Arc<AuthService>, ScimPlugin, Arc<MemoryStore>) {
    let auth_store = Arc::new(MemoryStore::default());
    let scim_store = Arc::new(MemoryScimStore::new());
    let plugin = ScimPlugin::new(options, scim_store).unwrap();
    let mut config = AuthConfig::new([213_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.add_plugin(plugin.clone()).unwrap();
    let service = Arc::new(AuthService::new(auth_store.clone(), config));
    (
        lucid_auth::axum::router(service.clone()),
        service,
        plugin,
        auth_store,
    )
}

fn application() -> (Router, Arc<AuthService>, ScimPlugin, Arc<MemoryStore>) {
    application_with_options(options())
}

fn request(method: &str, path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

async fn response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, value)
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
    response_json(response).await
}

fn user(user_name: &str) -> Value {
    json!({
        "schemas": [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA],
        "externalId": format!("external-{user_name}"),
        "userName": user_name,
        "name": { "givenName": "Luna", "familyName": "Lake" },
        "emails": [{ "value": user_name, "type": "WORK", "primary": "true" }],
        "active": "true",
        SCIM_ENTERPRISE_USER_SCHEMA: { "department": "Engineering" }
    })
}

#[tokio::test]
async fn descriptor_and_conditional_schema_match_the_pinned_package() {
    let (_, service, _, _) = application();
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "scim")
        .unwrap();
    assert_eq!(descriptor.version, "1.7.1");
    assert!(descriptor.client.is_none());
    assert_eq!(descriptor.endpoints.len(), 17);
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.method == lucid_auth::PluginHttpMethod::Get)
            .count(),
        9
    );
    assert!(service.plugin_migrations().is_empty());
    for (model, fields) in [
        ("scimConnectionBinding", 13),
        ("scimIdentityTombstone", 7),
        ("scimSubject", 5),
        ("scimUser", 21),
        ("scimProjectionGrant", 11),
        ("scimGroup", 10),
        ("scimGroupMember", 5),
    ] {
        assert_eq!(
            service.database_schema().table(model).unwrap().fields.len(),
            fields
        );
    }

    let mut managed = options();
    managed.managed_connections = Some(ScimManagedConnectionOptions::new("m".repeat(32)));
    let (_, managed_service, _, _) = application_with_options(managed);
    for model in [
        "scimManagedConnection",
        "scimManagedCredential",
        "scimManagedConnectionEvent",
    ] {
        assert!(managed_service.database_schema().table(model).is_some());
    }
    assert!(
        managed_service.database_schema().tables()["scimManagedConnection"].fields
            ["creationRequestId"]
            .returned
    );
    assert!(
        !managed_service.database_schema().tables()["scimManagedConnection"].fields["revision"]
            .returned
    );
}

#[tokio::test]
async fn public_discovery_is_exact_scim_json_with_absolute_locations() {
    let (app, _, _, _) = application();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/scim/v2/ServiceProviderConfig")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], SCIM_MEDIA_TYPE);
    let (_, config) = response_json(response).await;
    assert_eq!(config["patch"]["supported"], true);
    assert_eq!(config["filter"]["maxResults"], 100);
    assert_eq!(
        config["meta"]["location"],
        "https://example.com/api/auth/scim/v2/ServiceProviderConfig"
    );

    let (_, schemas) = response_json(
        app.clone()
            .oneshot(
                Request::get("/api/auth/scim/v2/Schemas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(schemas["schemas"][0], SCIM_LIST_RESPONSE_SCHEMA);
    assert_eq!(schemas["totalResults"], 3);

    let (_, resource_types) = response_json(
        app.oneshot(
            Request::get("/api/auth/scim/v2/ResourceTypes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(resource_types["totalResults"], 2);
    assert_eq!(resource_types["Resources"][0]["id"], "User");
}

#[tokio::test]
async fn bearer_scope_media_and_json_errors_use_scim_envelopes() {
    let (app, _, _, _) = application();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/scim/v2/Users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"SCIM\""
    );
    let (_, body) = response_json(response).await;
    assert_eq!(body["status"], "401");

    let response = app
        .clone()
        .oneshot(
            request("POST", "/scim/v2/Users")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let response = app
        .oneshot(
            request("POST", "/scim/v2/Users")
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn unsupported_user_attributes_are_rejected_instead_of_discarded() {
    let (app, _, _, _) = application();
    for attribute in ["password", "groups", "customExtension"] {
        let mut resource = user("unsupported@example.com");
        resource[attribute] = json!("forbidden");
        let (status, body) = send_json(app.clone(), "POST", "/scim/v2/Users", resource).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "attribute {attribute}");
        assert_eq!(body["scimType"], "invalidValue");
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("unknown field"))
        );
    }
}

#[tokio::test]
async fn structured_user_attributes_normalize_and_enforce_primary_type_rules() {
    let (app, _, _, _) = application();
    let mut resource = user("structured@example.com");
    resource["schemas"] = json!([SCIM_ENTERPRISE_USER_SCHEMA, SCIM_USER_SCHEMA]);
    resource["title"] = json!(" Principal Engineer ");
    resource["locale"] = json!(" en-GB ");
    resource["phoneNumbers"] = json!([
        { "value": " +44 20 0000 0000 ", "type": "WORK", "primary": "true" }
    ]);
    resource["roles"] = json!([
        { "value": " engineer ", "display": " Engineer ", "type": "APPLICATION" }
    ]);
    resource[SCIM_ENTERPRISE_USER_SCHEMA]["manager"] = json!([{
        "value": " manager-1 ",
        "$ref": " https://example.com/api/auth/scim/v2/Users/manager-1 ",
        "displayName": "Ignored on write"
    }]);
    let (status, created) = send_json(app.clone(), "POST", "/scim/v2/Users", resource).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        created["schemas"],
        json!([SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA])
    );
    assert_eq!(created["title"], "Principal Engineer");
    assert_eq!(created["locale"], "en-GB");
    assert_eq!(created["phoneNumbers"][0]["value"], "+44 20 0000 0000");
    assert_eq!(created["phoneNumbers"][0]["type"], "work");
    assert_eq!(created["phoneNumbers"][0]["primary"], true);
    assert_eq!(created["roles"][0]["value"], "engineer");
    assert_eq!(created["roles"][0]["type"], "application");
    assert_eq!(
        created[SCIM_ENTERPRISE_USER_SCHEMA]["manager"],
        json!({
            "value": "manager-1",
            "$ref": "https://example.com/api/auth/scim/v2/Users/manager-1"
        })
    );

    let mut duplicate = user("duplicate-types@example.com");
    duplicate["entitlements"] = json!([
        { "value": "first", "type": "LICENSE" },
        { "value": "second", "type": "license" }
    ]);
    let (status, body) = send_json(app, "POST", "/scim/v2/Users", duplicate).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidValue");
    assert_eq!(
        body["detail"],
        "entitlements cannot contain duplicate defined types"
    );
}

#[tokio::test]
async fn pinned_okta_google_and_entra_ingress_shapes_round_trip() {
    const ENTRA_GROUP_SCHEMA: &str =
        "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
    let (strict_app, _, _, _) = application();
    let (status, _) = send_json(
        strict_app,
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA, ENTRA_GROUP_SCHEMA],
            "displayName": "Strict Entra Group"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut provider_options = options();
    provider_options.microsoft_entra_legacy_group_schema = true;
    let (app, _, _, _) = application_with_options(provider_options);
    let provider_users = [
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": null,
            "externalId": "okta-001",
            "userName": "okta.user@example.com",
            "name": {"givenName": "Okta", "familyName": "User"},
            "displayName": "Okta User",
            "emails": [{"value": "okta.user@example.com", "type": "work", "primary": true}],
            "active": true
        }),
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "google-001",
            "userName": "google.user@example.com",
            "name": {"givenName": "Google", "familyName": "User"},
            "emails": [{"value": "google.user@example.com", "type": "work", "primary": true}],
            "active": true
        }),
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "entra-001",
            "userName": "entra.user@example.com",
            "name": {"givenName": "Entra", "familyName": "User"},
            "emails": [{"value": "entra.user@example.com", "type": "work", "primary": "TRUE"}],
            "active": "True"
        }),
    ];
    for resource in provider_users {
        let (status, created) = send_json(app.clone(), "POST", "/scim/v2/Users", resource).await;
        assert_eq!(status, StatusCode::CREATED, "{created:#}");
        assert_eq!(created["active"], true);
        assert_eq!(created["emails"][0]["primary"], true);
    }

    let (status, group) = send_json(
        app,
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA, ENTRA_GROUP_SCHEMA],
            "externalId": "entra-group-001",
            "displayName": "Entra Group",
            "members": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group:#}");
    assert_eq!(group["schemas"], json!([SCIM_GROUP_SCHEMA]));
    assert!(group.get(ENTRA_GROUP_SCHEMA).is_none());
}

#[tokio::test]
async fn user_crud_normalizes_profile_filters_paginates_and_projects() {
    let (app, _, _, auth_store) = application();
    let (status, created) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        user("luna@example.com"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    assert_eq!(created["displayName"], "Luna Lake");
    assert_eq!(created["emails"][0]["type"], "work");
    assert_eq!(created["emails"][0]["primary"], true);
    assert_eq!(created["meta"]["resourceType"], "User");
    let created_at = created["meta"]["created"].as_str().unwrap();
    assert!(created_at.ends_with('Z'));
    assert_eq!(created_at.rsplit_once('.').unwrap().1.len(), 4);
    let auth_user = auth_store
        .find_user_by_email("luna@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(
        auth_store
            .list_user_accounts(&auth_user.id)
            .await
            .unwrap()
            .is_empty()
    );

    let (_, listed) = response_json(
        app.clone()
            .oneshot(
                request(
                    "GET",
                    "/scim/v2/Users?filter=emails%5Btype%20eq%20%22work%22%5D.value%20eq%20%22luna%40example.com%22&startIndex=1&count=1&attributes=userName,active",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(listed["totalResults"], 1);
    assert_eq!(listed["itemsPerPage"], 1);
    assert_eq!(listed["Resources"][0]["userName"], "luna@example.com");
    assert!(listed["Resources"][0].get("emails").is_none());
    assert!(listed["Resources"][0].get("id").is_some());
    assert!(listed["Resources"][0].get("schemas").is_some());

    let mut replacement = user("luna+new@example.com");
    replacement["active"] = json!(false);
    let (status, replaced) = send_json(
        app.clone(),
        "PUT",
        &format!("/scim/v2/Users/{id}"),
        replacement,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replaced["active"], false);

    let response = app
        .oneshot(
            request("DELETE", &format!("/scim/v2/Users/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], SCIM_MEDIA_TYPE);
    let (status, _) = response_json(response).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        auth_store
            .find_user_by_email("luna+new@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn mutation_responses_apply_attribute_projection_without_losing_location_headers() {
    let (app, _, _, _) = application();
    let response = app
        .clone()
        .oneshot(
            request("POST", "/scim/v2/Users?attributes=userName")
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(user("projected-create@example.com").to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get(header::LOCATION).is_some());
    assert!(response.headers().get(header::CONTENT_LOCATION).is_some());
    let (status, created) = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["userName"], "projected-create@example.com");
    assert!(created.get("schemas").is_some());
    assert!(created.get("id").is_some());
    assert!(created.get("emails").is_none());
    assert!(created.get("meta").is_none());

    let id = created["id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            request(
                "PATCH",
                &format!("/scim/v2/Users/{id}?excludedAttributes=emails,name"),
            )
            .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
            .body(Body::from(
                json!({
                    "schemas": [SCIM_PATCH_SCHEMA],
                    "Operations": [{ "op": "replace", "path": "displayName", "value": "Projected" }]
                })
                .to_string(),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get(header::LOCATION).is_some());
    let (status, patched) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["displayName"], "Projected");
    assert!(patched.get("emails").is_none());
    assert!(patched.get("name").is_none());

    let response = app
        .oneshot(
            request("POST", "/scim/v2/Groups?attributes=displayName")
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(
                    json!({
                        "schemas": [SCIM_GROUP_SCHEMA],
                        "displayName": "Projected Group"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get(header::LOCATION).is_some());
    assert!(response.headers().get(header::CONTENT_LOCATION).is_some());
    let (status, group) = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(group["displayName"], "Projected Group");
    assert!(group.get("schemas").is_some());
    assert!(group.get("id").is_some());
    assert!(group.get("meta").is_none());
}

#[tokio::test]
async fn user_patch_is_ordered_case_insensitive_and_atomic_at_the_store_boundary() {
    let (app, _, _, _) = application();
    let (_, created) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        user("patch@example.com"),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let patch = json!({
        "schemas": [SCIM_PATCH_SCHEMA],
        "Operations": [
            { "op": "REPLACE", "path": "displayName", "value": "First" },
            { "op": "replace", "path": "displayName", "value": [" Second "] },
            { "op": "replace", "path": "Name.GivenName", "value": "Nova" },
            { "op": "add", "path": "emails[type eq \"home\"].value", "value": "home@example.com" },
            { "op": "replace", "path": "emails[PRIMARY eq true].value", "value": "primary@example.com" },
            { "op": "remove", "path": format!("{SCIM_ENTERPRISE_USER_SCHEMA}:department") },
            { "op": "add", "path": format!("{SCIM_ENTERPRISE_USER_SCHEMA}:division"), "value": "Platform" },
            { "op": "replace", "path": "title", "value": "true" },
            { "op": "replace", "path": "userType", "value": "true" },
            { "op": "replace", "path": "active", "value": "false" },
            { "op": "add", "path": "phoneNumbers", "value": { "value": "+44 20 1111 1111", "type": "work", "primary": true } },
            { "op": "add", "path": "phoneNumbers", "value": [
                { "value": "+44 20 2222 2222", "type": "home", "primary": true }
            ] },
            { "op": "add", "path": "roles[type eq \"application\"]", "value": { "value": "engineer" } },
            { "op": "replace", "path": "roles[type eq \"application\"]", "value": [{ "display": "Engineer" }] },
            { "op": "remove", "path": "title" }
        ]
    });
    let (status, changed) =
        send_json(app.clone(), "PATCH", &format!("/scim/v2/Users/{id}"), patch).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed["displayName"], "Second");
    assert_eq!(changed["name"]["givenName"], "Nova");
    assert_eq!(changed["emails"].as_array().unwrap().len(), 2);
    assert_eq!(changed["emails"][0]["value"], "primary@example.com");
    assert_eq!(changed["emails"][0]["primary"], true);
    assert_eq!(changed["active"], false);
    assert_eq!(changed["userType"], "true");
    assert_eq!(changed["phoneNumbers"].as_array().unwrap().len(), 2);
    assert_eq!(changed["phoneNumbers"][0]["primary"], false);
    assert_eq!(changed["phoneNumbers"][1]["primary"], true);
    assert_eq!(changed["roles"][0]["value"], "engineer");
    assert_eq!(changed["roles"][0]["type"], "application");
    assert_eq!(changed["roles"][0]["display"], "Engineer");
    assert_eq!(
        changed[SCIM_ENTERPRISE_USER_SCHEMA],
        json!({ "division": "Platform" })
    );

    let (status, body) = send_json(
        app,
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        json!({ "schemas": [SCIM_PATCH_SCHEMA], "Operations": [{ "op": "remove" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "noTarget");
}

#[tokio::test]
async fn user_email_patch_deduplicates_additions_and_preserves_primary_rules() {
    let (app, _, _, _) = application();
    let mut resource = user("email-patch@example.com");
    resource["emails"] = json!([
        { "value": "personal@example.com", "type": "personal" },
        { "value": "WORK@EXAMPLE.COM", "type": "WORK" }
    ]);
    let (_, created) = send_json(app.clone(), "POST", "/scim/v2/Users", resource).await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["emails"][0]["primary"], false);
    assert_eq!(created["emails"][1]["primary"], true);
    assert_eq!(created["emails"][1]["value"], "work@example.com");

    let patch = json!({
        "schemas": [SCIM_PATCH_SCHEMA],
        "Operations": [
            { "op": "add", "path": "emails", "value": [
                { "value": "PERSONAL@example.com", "type": "PERSONAL" },
                { "value": "new@example.com", "type": "other", "primary": true }
            ] },
            { "op": "replace", "path": "emails[type eq \"other\"].value", "value": "changed@example.com" }
        ]
    });
    let (status, changed) = send_json(app, "PATCH", &format!("/scim/v2/Users/{id}"), patch).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed["emails"].as_array().unwrap().len(), 3);
    assert_eq!(changed["emails"][1]["primary"], false);
    assert_eq!(changed["emails"][2]["value"], "changed@example.com");
    assert_eq!(changed["emails"][2]["primary"], true);
}

#[tokio::test]
async fn group_crud_enforces_same_connection_users_and_member_projection() {
    let (app, _, _, _) = application();
    let (_, created_user) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        user("member@example.com"),
    )
    .await;
    let user_id = created_user["id"].as_str().unwrap();
    let (status, body) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "externalId": " external-group ",
            "displayName": "Whitespace Member",
            "members": [{ "value": format!(" {user_id} "), "type": "User" }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidValue");

    let (status, group) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "externalId": " external-group ",
            "displayName": "Engineering",
            "members": [{ "value": user_id, "type": "user" }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = group["id"].as_str().unwrap();
    assert_eq!(group["externalId"], " external-group ");
    assert_eq!(group["members"][0]["type"], "User");
    assert_eq!(group["members"][0]["display"], "Luna Lake");
    assert!(
        group["members"][0]["$ref"]
            .as_str()
            .unwrap()
            .ends_with(user_id)
    );

    let (status, body) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Invalid",
            "members": [{ "value": "missing-user" }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidValue");

    let (status, changed) = send_json(
        app.clone(),
        "PATCH",
        &format!("/scim/v2/Groups/{group_id}"),
        json!({
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{ "op": "remove", "path": format!("members[value eq \"{user_id}\"]") }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed["members"], json!([]));

    let response = app
        .oneshot(
            request("DELETE", &format!("/scim/v2/Groups/{group_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], SCIM_MEDIA_TYPE);
    let (status, _) = response_json(response).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn managed_credentials_are_one_time_hmac_only_and_authenticate() {
    let options = ScimOptions {
        managed_connections: Some(ScimManagedConnectionOptions::new("secret".repeat(8))),
        ..ScimOptions::default()
    };
    let (app, _, plugin, _) = application_with_options(options);
    let (connection, credential, token) = plugin
        .create_managed_connection(
            "request-id-0000001",
            "tenant-1",
            "actor-1",
            ScimScope::ALL.to_vec(),
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap();
    assert!(connection.connection_id.starts_with("ba_scim_connection_"));
    assert!(credential.credential_id.starts_with("ba_scim_credential_"));
    assert!(token.starts_with(&format!("{}.", credential.credential_id)));
    assert!(!credential.token_digest.contains(&token));
    let persisted = plugin
        .store()
        .find_managed_credential(&credential.credential_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.1.token_digest, credential.token_digest);
    assert_eq!(persisted.1.hash_version, "v1");
    assert!(!persisted.1.token_digest.starts_with("v1:"));
    assert_eq!(
        persisted.1.active_slot_key,
        format!("{}:active:0", connection.id)
    );
    assert_eq!(
        persisted.1.serialized_scopes,
        serde_json::to_string(&ScimScope::ALL).unwrap()
    );

    let response = app
        .oneshot(
            Request::get("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let conflict = plugin
        .create_managed_connection(
            "request-id-0000001",
            "tenant-1",
            "actor-1",
            ScimScope::ALL.to_vec(),
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap_err();
    assert_eq!(conflict.status, 409);
}

#[tokio::test]
async fn managed_catalog_rotates_revokes_isolates_and_decommissions() {
    let mut managed = ScimManagedConnectionOptions::new("catalog-secret".repeat(3));
    managed.max_active_credentials = 2;
    let options = ScimOptions {
        managed_connections: Some(managed),
        ..ScimOptions::default()
    };
    let (app, _, plugin, _) = application_with_options(options);
    let expiry = Utc::now() + Duration::hours(1);
    let (created, first, first_token) = plugin
        .create_managed_connection(
            "managed-request-0001",
            "tenant-a",
            "actor-a",
            ScimScope::ALL.to_vec(),
            expiry,
        )
        .await
        .unwrap();
    let public = serde_json::to_value(&created).unwrap();
    assert_eq!(public["creationRequestId"], "managed-request-0001");
    assert!(public.get("id").is_none());
    let credential_public = serde_json::to_value(&first).unwrap();
    for timestamp in [
        public["createdAt"].as_str().unwrap(),
        credential_public["expiresAt"].as_str().unwrap(),
        credential_public["createdAt"].as_str().unwrap(),
    ] {
        assert!(timestamp.ends_with('Z'));
        assert_eq!(timestamp.rsplit_once('.').unwrap().1.len(), 4);
    }
    assert!(credential_public.get("tokenDigest").is_none());
    assert!(credential_public.get("connectionRecordId").is_none());

    let listed = plugin.list_managed_connections("tenant-a").await.unwrap();
    assert_eq!(listed, vec![created.clone()]);
    assert!(
        plugin
            .get_managed_connection(&created.connection_id, "tenant-b")
            .await
            .is_err_and(|error| error.status == 404)
    );

    let (_, second, second_token) = plugin
        .rotate_managed_credential(
            &created.connection_id,
            "tenant-a",
            "actor-b",
            vec![ScimScope::UsersRead],
            expiry,
        )
        .await
        .unwrap();
    let at_capacity = plugin
        .rotate_managed_credential(
            &created.connection_id,
            "tenant-a",
            "actor-b",
            vec![ScimScope::UsersRead],
            expiry,
        )
        .await
        .unwrap_err();
    assert_eq!(at_capacity.status, 409);

    let (_, revoked) = plugin
        .revoke_managed_credential(
            &created.connection_id,
            "tenant-a",
            &first.credential_id,
            "actor-c",
        )
        .await
        .unwrap();
    assert_eq!(
        revoked
            .iter()
            .find(|item| item.credential_id == first.credential_id)
            .unwrap()
            .status,
        "revoked"
    );
    let (_, third, _) = plugin
        .rotate_managed_credential(
            &created.connection_id,
            "tenant-a",
            "actor-d",
            vec![ScimScope::UsersRead],
            expiry,
        )
        .await
        .unwrap();
    assert_ne!(third.credential_id, second.credential_id);

    let events = plugin
        .list_managed_connection_events(&created.connection_id, "tenant-a")
        .await
        .unwrap();
    assert_eq!(events.first().unwrap().kind, "connection.created");
    assert_eq!(events.last().unwrap().kind, "credential.rotated");
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );

    let (decommissioned, credentials) = plugin
        .decommission_managed_connection(&created.connection_id, "tenant-a", "actor-e")
        .await
        .unwrap();
    assert_eq!(decommissioned.status, "decommissioned");
    assert!(decommissioned.decommission_started_at.is_some());
    assert!(decommissioned.decommissioned_at.is_some());
    assert!(credentials.iter().all(|item| item.status != "active"));
    assert!(
        credentials
            .iter()
            .all(|item| item.status != "decommissioned" || item.decommissioned_at.is_some())
    );
    assert!(
        credentials
            .iter()
            .all(|item| item.active_slot_key.ends_with(":inactive"))
    );

    for token in [first_token, second_token] {
        let response = app
            .clone()
            .oneshot(
                Request::get("/api/auth/scim/v2/Users")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn managed_namespace_tokens_never_fall_through_to_the_custom_verifier() {
    let verifier = Arc::new(CountingVerifier::new("custom"));
    let options = ScimOptions {
        authentication: Some(verifier.clone()),
        managed_connections: Some(ScimManagedConnectionOptions::new(
            "namespace-secret".repeat(3),
        )),
        ..ScimOptions::default()
    };
    let (app, _, _, _) = application_with_options(options);
    let response = app
        .oneshot(
            Request::get("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, "Bearer ba_scim_credential_malformed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn custom_verifiers_cannot_resolve_reserved_connection_ids() {
    let verifier = Arc::new(CountingVerifier::new("ba_scim_connection_injected"));
    let options = ScimOptions {
        authentication: Some(verifier.clone()),
        ..ScimOptions::default()
    };
    let (app, _, _, _) = application_with_options(options);
    let response = app
        .oneshot(
            Request::get("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, "Bearer application-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn configuration_rejects_reserved_duplicate_and_short_managed_secrets() {
    let empty = ScimPlugin::in_memory(ScimOptions::default()).unwrap_err();
    assert!(
        empty
            .to_string()
            .contains("requires a provisioning connection")
    );

    let reserved = ScimOptions {
        connections: vec![ScimConnection::new(
            "ba_scim_connection_reserved",
            vec![ScimBearerCredential::new("credential", "token")],
        )],
        ..ScimOptions::default()
    };
    assert!(ScimPlugin::in_memory(reserved).is_err());

    let short = ScimOptions {
        managed_connections: Some(ScimManagedConnectionOptions::new("short")),
        ..ScimOptions::default()
    };
    assert!(ScimPlugin::in_memory(short).is_err());
}
