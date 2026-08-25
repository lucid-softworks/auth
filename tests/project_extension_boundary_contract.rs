use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdminPlugin, AuditPlugin, AuthConfig, AuthService, GuestCapabilityPlugin, MemoryAuditStore,
    MemoryStepUpStore, MemoryStore, NewPasswordUser, OperatorSecurityConfig,
    OperatorSecurityPlugin, OwnerPolicyPlugin, PluginProvenance, StepUpPolicyPlugin,
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
use tower::ServiceExt;

async fn provision_session(
    service: &AuthService,
    username: &str,
    role: &str,
) -> lucid_auth::SignInResult {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: username.into(),
            email: None,
            password: "password".into(),
            role: role.into(),
        })
        .await
        .unwrap();
    service
        .sign_in_username(username, "password".into(), None, None)
        .await
        .unwrap()
}

async fn get_session_shape(
    service: Arc<AuthService>,
    sign_in: &lucid_auth::SignInResult,
) -> BTreeSet<String> {
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&sign_in.token)
    );
    let response = lucid_auth::axum::router(service)
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let mut paths = BTreeSet::new();
    collect_object_paths("", &value, &mut paths);
    paths
}

fn collect_object_paths(prefix: &str, value: &Value, paths: &mut BTreeSet<String>) {
    if let Value::Object(fields) = value {
        for (key, value) in fields {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            paths.insert(path.clone());
            collect_object_paths(&path, value, paths);
        }
    }
}

#[tokio::test]
async fn default_server_has_no_lucid_extension_surface_or_store_requirement() {
    let mut config = AuthConfig::new([107_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    assert!(service.plugin_metadata().is_empty());
    assert!(service.plugin_migrations().is_empty());
    assert!(service.step_up_policy().is_none());
    assert!(service.operator_security().is_none());

    let sign_in = provision_session(&service, "baseline", "user").await;
    assert_eq!(
        service
            .principal(&sign_in.token)
            .await
            .unwrap()
            .unwrap()
            .role,
        None
    );
    let response_shape = get_session_shape(service.clone(), &sign_in).await;
    for forbidden in [
        "guestGrantId",
        "permissions",
        "resourceScopes",
        "assurance",
        "stepUpRequired",
        "mustChangePassword",
        "audit",
    ] {
        assert!(response_shape.iter().all(|path| !path.contains(forbidden)));
    }

    let app = lucid_auth::axum::router(service);
    for (method, path) in [
        (Method::GET, "/api/auth/guest-grants"),
        (Method::POST, "/api/auth/guest-grants"),
        (Method::POST, "/api/auth/guest-grants/revoke"),
        (Method::POST, "/api/auth/sign-in/guest-grant"),
        (Method::GET, "/api/auth/access/audit"),
        (Method::POST, "/api/auth/operator-security/recover"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

fn enabled_extension_service() -> Arc<AuthService> {
    let auth_store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([109_u8; 32]).unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    config
        .add_plugin(GuestCapabilityPlugin::new(auth_store.clone()))
        .unwrap();
    config
        .add_plugin(StepUpPolicyPlugin::new(
            auth_store.clone(),
            Arc::new(MemoryStepUpStore::default()),
            OwnerPolicyPlugin::step_up_config(),
        ))
        .unwrap();
    config
        .add_plugin(OperatorSecurityPlugin::new(
            auth_store.clone(),
            OperatorSecurityConfig::default(),
        ))
        .unwrap();
    config
        .add_plugin(AuditPlugin::new(Arc::new(MemoryAuditStore::default())))
        .unwrap();
    Arc::new(AuthService::new(auth_store, config))
}

fn assert_descriptor_ownership(service: &AuthService) {
    let extensions: Vec<_> = service
        .plugin_metadata()
        .iter()
        .filter(|descriptor| descriptor.id.starts_with("lucid-"))
        .collect();
    assert_eq!(extensions.len(), 5);
    assert!(extensions.iter().all(|descriptor| {
        descriptor.provenance == PluginProvenance::LucidExtension && descriptor.client.is_none()
    }));
    let ownership: Vec<_> = extensions
        .iter()
        .map(|descriptor| {
            (
                descriptor.id,
                descriptor
                    .endpoints
                    .iter()
                    .map(|endpoint| endpoint.path.as_ref())
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        ownership,
        [
            ("lucid-owner-policy", vec![]),
            (
                "lucid-guest-capability",
                vec![
                    "/guest-grants",
                    "/guest-grants",
                    "/guest-grants/revoke",
                    "/sign-in/guest-grant",
                ],
            ),
            ("lucid-step-up-policy", vec![]),
            ("lucid-operator-security", vec![]),
            ("lucid-security-audit", vec!["/access/audit"]),
        ]
    );
}

fn assert_migration_ownership(service: &AuthService) {
    let migrations: Vec<_> = service
        .plugin_migrations()
        .into_iter()
        .map(|contribution| {
            (
                contribution.plugin_id,
                contribution.migration.id.into_owned(),
            )
        })
        .collect();
    assert_eq!(
        migrations,
        [
            (
                "lucid-guest-capability",
                "lucid-guest-capability-schema".to_owned(),
            ),
            ("lucid-step-up-policy", "extract-step-up-policy".to_owned()),
            (
                "lucid-operator-security",
                "extract-managed-password-policy".to_owned(),
            ),
            (
                "lucid-security-audit",
                "lucid-security-audit-schema".to_owned(),
            ),
        ]
    );
}

#[tokio::test]
async fn enabled_extensions_report_ownership_without_changing_session_shape() {
    let baseline_store = Arc::new(MemoryStore::default());
    let mut baseline_config = AuthConfig::new([108_u8; 32]).unwrap();
    baseline_config.add_plugin(AdminPlugin::default()).unwrap();
    let baseline = Arc::new(AuthService::new(baseline_store, baseline_config));
    let baseline_sign_in = provision_session(&baseline, "baseline_admin", "user").await;
    let baseline_shape = get_session_shape(baseline, &baseline_sign_in).await;

    let service = enabled_extension_service();
    assert_descriptor_ownership(&service);
    assert_migration_ownership(&service);

    let sign_in = provision_session(&service, "extension_member", "member").await;
    assert_eq!(
        get_session_shape(service.clone(), &sign_in).await,
        baseline_shape
    );
    let recovery = lucid_auth::axum::router(service)
        .oneshot(
            Request::post("/api/auth/operator-security/recover")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovery.status(), StatusCode::NOT_FOUND);
}
