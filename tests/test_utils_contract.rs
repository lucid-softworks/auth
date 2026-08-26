#![cfg(feature = "axum")]

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthPlugin, AuthService,
    AuthStore, DatabaseHookContext, DatabaseHooks, DatabaseRecord, MemoryOrganizationStore,
    MemoryStore, OrganizationDataStore, OrganizationMemberStore, OrganizationPlugin,
    TestOrganizationOverrides, TestUserOverrides, TestUtilsOptions, TestUtilsPlugin,
    VerificationValue,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Debug, Default)]
struct HookCounts {
    creates: AtomicUsize,
    deletes: AtomicUsize,
    test_method: AtomicUsize,
}

#[async_trait]
impl DatabaseHooks for HookCounts {
    async fn after_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if matches!(record, DatabaseRecord::User(_)) {
            self.creates.fetch_add(1, Ordering::SeqCst);
            if context.creation_method == Some("test") {
                self.test_method.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    async fn after_delete(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if matches!(record, DatabaseRecord::User(_)) {
            self.deletes.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[tokio::test]
async fn metadata_and_option_gates_match_test_utils_171() {
    let plugin = TestUtilsPlugin::default();
    let descriptor = plugin.descriptor();
    assert_eq!(descriptor.id, "test-utils");
    assert_eq!(descriptor.version, "1.7.1");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.endpoints.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());
    assert!(descriptor.client.is_none());
    assert!(!plugin.options().capture_otp);

    let bare = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([3_u8; 32]).unwrap(),
    );
    assert!(bare.test().is_none());

    let mut config = AuthConfig::new([4_u8; 32]).unwrap();
    config.add_plugin(plugin).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let helpers = service.test().unwrap();
    assert!(helpers.organization().is_none());
    assert!(helpers.otp().is_none());
    assert!(service.plugin_migrations().is_empty());
    let response = lucid_auth::axum::router(Arc::new(service))
        .oneshot(
            Request::get("/api/auth/test-utils")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn user_factories_persistence_and_core_hooks_are_exact() {
    let store = Arc::new(MemoryStore::default());
    let hooks = Arc::new(HookCounts::default());
    let mut config = AuthConfig::new([5_u8; 32]).unwrap();
    config.database_hooks = Some(hooks.clone());
    config.user.additional_fields.insert(
        "tenant".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(store.clone(), config);
    let helpers = service.test().unwrap();
    let defaults = helpers.create_user(TestUserOverrides::default());
    assert!(
        regex::Regex::new(r"^test-[a-z0-9]{8}@example\.com$")
            .unwrap()
            .is_match(&defaults.email)
    );
    assert_eq!(defaults.created_at, defaults.updated_at);
    let mut fields = serde_json::Map::new();
    fields.insert("tenant".into(), json!("fixture"));
    let user = helpers.create_user(TestUserOverrides {
        email: Some("CASE@Test.Example".into()),
        additional_fields: fields,
        ..TestUserOverrides::default()
    });
    assert_ne!(user.id, defaults.id);
    assert_eq!(user.name, "Test User");
    assert!(user.email_verified);
    assert!(user.image.is_none());
    assert_eq!(user.created_at, user.updated_at);
    assert_eq!(user.additional_fields["tenant"], "fixture");
    assert!(store.find_user_by_id(&user.id).await.unwrap().is_none());

    let saved = helpers.save_user(user).await.unwrap();
    let saved_id = Uuid::parse_str(&saved.id).unwrap();
    assert_eq!(saved.email, "case@test.example");
    assert_eq!(hooks.creates.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.test_method.load(Ordering::SeqCst), 1);
    helpers.delete_user(saved_id).await.unwrap();
    helpers.delete_user(saved_id).await.unwrap();
    assert_eq!(hooks.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn login_headers_and_browser_cookies_authenticate_the_normal_router() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([6_u8; 32]).unwrap();
    config.set_base_url("https://auth.example.com").unwrap();
    config.cookies.session_token.name = Some("fixture-session".into());
    config.cookies.session_token.attributes.path = Some("/test".into());
    config.cookies.session_token.attributes.max_age = Some(90.0);
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = Arc::new(AuthService::new(store, config));
    let helpers = service.test().unwrap();
    let user = helpers
        .save_user(helpers.create_user(TestUserOverrides::default()))
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&user.id).unwrap();
    let login = helpers.login(user_id).await.unwrap();
    assert_eq!(login.user.id, user.id);
    assert_eq!(login.session.token, login.token);
    let cookie = &login.cookies[0];
    assert_eq!(cookie.name, "__Secure-fixture-session");
    assert_eq!(cookie.domain, "auth.example.com");
    assert_eq!(cookie.path, "/test");
    assert!(cookie.http_only && cookie.secure);
    assert_eq!(cookie.same_site, "Lax");
    assert!(cookie.value.starts_with(&format!("{}.", login.token)));
    assert!(!cookie.value.contains("66666666666666666666666666666666"));
    assert!(cookie.expires.unwrap() >= chrono::Utc::now().timestamp() + 88);

    let response = lucid_auth::axum::router(service.clone())
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, &login.headers["cookie"])
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"]["id"], user.id.to_string());

    let headers = helpers.get_auth_headers(user_id).await.unwrap();
    let cookies = helpers
        .get_cookies(user_id, Some("localhost"))
        .await
        .unwrap();
    assert_ne!(headers["cookie"], login.headers["cookie"]);
    assert_ne!(cookies[0].value, cookie.value);
    assert_eq!(cookies[0].domain, "localhost");
    let missing = helpers.login(Uuid::new_v4()).await.unwrap_err();
    assert!(missing.to_string().starts_with("User not found: "));
}

#[tokio::test]
async fn organization_helpers_are_conditional_raw_and_non_persisting_factories() {
    let users = Arc::new(MemoryStore::default());
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let mut config = AuthConfig::new([7_u8; 32]).unwrap();
    config
        .add_plugin(OrganizationPlugin::new(organizations.clone()))
        .unwrap();
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(users, config);
    let helpers = service.test().unwrap();
    let organization_helpers = helpers.organization().unwrap();
    let organization =
        organization_helpers.create_organization(TestOrganizationOverrides::default());
    assert_eq!(organization.name, "Test Organization");
    assert!(organization.slug.starts_with("test-organization-"));
    assert_eq!(organization.slug.len(), "test-organization-".len() + 4);
    assert!(
        organizations
            .find_organization_by_id(organization.id)
            .await
            .unwrap()
            .is_none()
    );
    organization_helpers
        .save_organization(organization.clone())
        .await
        .unwrap();
    let member = organization_helpers
        .add_member(Uuid::new_v4(), organization.id, Some(String::new()))
        .await
        .unwrap();
    assert_eq!(member.role, "member");
    let default_member = organization_helpers
        .add_member(Uuid::new_v4(), organization.id, None)
        .await
        .unwrap();
    assert_eq!(default_member.role, "member");
    let custom_member = organization_helpers
        .add_member(Uuid::new_v4(), organization.id, Some("auditor".into()))
        .await
        .unwrap();
    assert_eq!(custom_member.role, "auditor");
    assert_eq!(
        organizations
            .list_members(organization.id)
            .await
            .unwrap()
            .len(),
        3
    );
    organization_helpers
        .delete_organization(organization.id)
        .await
        .unwrap();
    assert!(
        organizations
            .find_organization_by_id(organization.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        organizations
            .list_members(organization.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn otp_capture_is_passive_prefix_aware_last_write_wins_and_instance_scoped() {
    let first = otp_service(8);
    let second = otp_service(9);
    capture_each_prefix(&first).await;
    replace_capture(&first).await;
    assert!(
        second
            .test()
            .unwrap()
            .otp()
            .unwrap()
            .get_otp("user-1")
            .is_none()
    );
    first.test().unwrap().otp().unwrap().clear_otps();
    assert!(
        first
            .test()
            .unwrap()
            .otp()
            .unwrap()
            .get_otp("user-1")
            .is_none()
    );
}

async fn capture_each_prefix(service: &AuthService) {
    for (index, prefix) in [
        "email-verification-otp-",
        "sign-in-otp-",
        "forget-password-otp-",
        "phone-verification-otp-",
    ]
    .into_iter()
    .enumerate()
    {
        let identifier = format!("{prefix}user-{index}");
        let now = chrono::Utc::now();
        service
            .create_verification_value(VerificationValue::new(
                identifier.clone(),
                format!("otp-{index}:stored-tail"),
                now + chrono::Duration::minutes(5),
            ))
            .await
            .unwrap();
        assert_eq!(
            service
                .find_verification_value(&identifier)
                .await
                .unwrap()
                .unwrap()
                .value,
            format!("otp-{index}:stored-tail")
        );
        assert_eq!(
            service
                .test()
                .unwrap()
                .otp()
                .unwrap()
                .get_otp(&format!("user-{index}")),
            Some(format!("otp-{index}"))
        );
    }
}

async fn replace_capture(service: &AuthService) {
    let now = chrono::Utc::now();
    service
        .create_verification_value(VerificationValue::new(
            "sign-in-otp-user-1",
            "replacement:tail",
            now + chrono::Duration::minutes(5),
        ))
        .await
        .unwrap();
    assert_eq!(
        service.test().unwrap().otp().unwrap().get_otp("user-1"),
        Some("replacement".into())
    );
}

fn otp_service(secret_byte: u8) -> AuthService {
    let mut config = AuthConfig::new([secret_byte; 32]).unwrap();
    config
        .add_plugin(TestUtilsPlugin::new(TestUtilsOptions { capture_otp: true }))
        .unwrap();
    AuthService::new(Arc::new(MemoryStore::default()), config)
}
