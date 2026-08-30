#![cfg(feature = "axum")]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, EmailSignUpInput, MemorySsoStore, MemoryStore, NewSsoProvider,
    SsoDnsResolver, SsoOptions, SsoPlugin, SsoStore,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    owner_cookie: String,
    other_cookie: String,
    dns: Arc<FixtureDnsResolver>,
}

#[derive(Default)]
struct FixtureDnsResolver {
    records: RwLock<Vec<String>>,
}

#[async_trait]
impl SsoDnsResolver for FixtureDnsResolver {
    async fn txt_records(&self, _name: &str) -> Result<Vec<String>, String> {
        Ok(self.records.read().await.clone())
    }
}

async fn fixture() -> Fixture {
    fixture_with_options(SsoOptions::default()).await
}

async fn fixture_with_options(options: SsoOptions) -> Fixture {
    let mut config = AuthConfig::new([31_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.set_base_url("https://example.com").unwrap();
    let providers = Arc::new(MemorySsoStore::new());
    let dns = Arc::new(FixtureDnsResolver::default());
    let domain_verification = options.domain_verification;
    config
        .add_plugin(
            SsoPlugin::with_store(options, providers.clone()).with_dns_resolver(dns.clone()),
        )
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let owner = account(&service, "owner@example.com").await;
    let other = account(&service, "other@example.com").await;
    providers
        .create(NewSsoProvider {
            id: "provider-row-1".into(),
            issuer: "https://idp.example.com".into(),
            oidc_config: Some(json!({
                "discoveryEndpoint": "https://idp.example.com/.well-known/openid-configuration",
                "clientId": "client-123456",
                "clientSecret": "never-return-this",
                "pkce": true,
                "scopes": ["openid", "email"]
            })),
            saml_config: None,
            user_id: owner.1.clone(),
            provider_id: "acme-sso!".into(),
            organization_id: None,
            domain: "example.com".into(),
            domain_verified: Some(!domain_verification),
        })
        .await
        .unwrap();
    providers
        .create(NewSsoProvider {
            id: "provider-row-2".into(),
            issuer: "https://other-idp.example.com".into(),
            oidc_config: Some(json!({
                "clientId": "other-client",
                "clientSecret": "other-secret"
            })),
            saml_config: None,
            user_id: other.1.clone(),
            provider_id: "other".into(),
            organization_id: None,
            domain: "other.example.com".into(),
            domain_verified: domain_verification.then_some(false),
        })
        .await
        .unwrap();
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        owner_cookie: cookie(&service, &owner.0),
        other_cookie: cookie(&service, &other.0),
        dns,
    }
}

async fn account(service: &AuthService, email: &str) -> (String, String) {
    let result = service
        .sign_up_email(
            EmailSignUpInput {
                name: email.into(),
                email: email.into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    (result.token.unwrap(), result.user.id)
}

fn cookie(service: &AuthService, token: &str) -> String {
    format!(
        "__Secure-better-auth.session_token={}",
        service.signed_cookie_value(token)
    )
}

async fn get(app: Router, path: &str, cookie: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::get(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
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

async fn post(app: Router, path: &str, cookie: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://example.com");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
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
async fn provider_catalog_requires_a_session_and_returns_only_owned_sanitized_entries() {
    let fixture = fixture().await;
    let (status, _) = get(fixture.app.clone(), "/api/auth/sso/providers", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = get(
        fixture.app,
        "/api/auth/sso/providers",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let providers = body["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    let provider = &providers[0];
    assert_eq!(provider["providerId"], "acme-sso!");
    assert_eq!(provider["type"], "oidc");
    assert_eq!(provider["domainVerified"], true);
    assert_eq!(provider["oidcConfig"]["clientIdLastFour"], "****3456");
    assert_eq!(
        provider["spMetadataUrl"],
        "https://example.com/api/auth/sso/saml2/sp/metadata?providerId=acme-sso!"
    );
    let serialized = provider.to_string();
    assert!(!serialized.contains("never-return-this"));
    assert!(!serialized.contains("clientSecret"));
}

#[tokio::test]
async fn provider_lookup_distinguishes_missing_and_forbidden_records() {
    let fixture = fixture().await;
    let (status, provider) = get(
        fixture.app.clone(),
        "/api/auth/sso/get-provider?providerId=acme-sso%21",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(provider["providerId"], "acme-sso!");

    let (status, forbidden) = get(
        fixture.app.clone(),
        "/api/auth/sso/get-provider?providerId=acme-sso%21",
        Some(&fixture.other_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden["message"],
        "You don't have access to this provider"
    );

    let (status, missing) = get(
        fixture.app,
        "/api/auth/sso/get-provider?providerId=missing",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["message"], "Provider not found");
}

#[tokio::test]
async fn registration_enforces_boundaries_and_returns_the_upstream_creation_shape() {
    let fixture = fixture().await;
    let valid = json!({
        "providerId": "new-provider",
        "issuer": "https://new-idp.example.com",
        "domain": "new.example.com",
        "oidcConfig": {
            "clientId": "new-client",
            "clientSecret": "creation-secret",
            "authorizationEndpoint": "https://new-idp.example.com/authorize",
            "tokenEndpoint": "https://new-idp.example.com/token",
            "jwksEndpoint": "https://new-idp.example.com/jwks",
            "skipDiscovery": true,
            "unknownNestedField": "stripped"
        },
        "overrideUserInfo": true,
        "unknownTopLevelField": "stripped"
    });
    let (status, _) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        None,
        valid.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, reserved) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "credential",
            "issuer": "https://new-idp.example.com",
            "domain": "new.example.com"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reserved["message"],
        "This providerId is reserved and cannot be used for an SSO provider"
    );

    let (status, missing_secret) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "no-secret",
            "issuer": "https://new-idp.example.com",
            "domain": "new.example.com",
            "oidcConfig": {
                "clientId": "new-client",
                "skipDiscovery": true
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_secret["message"],
        "clientSecret is required when using client_secret_basic or client_secret_post authentication"
    );

    let (status, created) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        valid,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["providerId"], "new-provider");
    assert_eq!(created["oidcConfig"]["clientSecret"], "creation-secret");
    assert_eq!(created["oidcConfig"]["pkce"], true);
    assert_eq!(created["oidcConfig"]["overrideUserInfo"], true);
    assert_eq!(
        created["oidcConfig"]["tokenEndpointAuthentication"],
        "client_secret_basic"
    );
    assert_eq!(
        created["redirectURI"],
        "https://example.com/api/auth/sso/callback/new-provider"
    );
    assert!(created.get("domainVerified").is_none());
    assert!(created["oidcConfig"].get("skipDiscovery").is_none());
    assert!(created["oidcConfig"].get("unknownNestedField").is_none());
    assert!(created.get("unknownTopLevelField").is_none());

    let (_, catalog) = get(
        fixture.app,
        "/api/auth/sso/providers",
        Some(&fixture.owner_cookie),
    )
    .await;
    let serialized = catalog.to_string();
    assert!(!serialized.contains("creation-secret"));
}

#[tokio::test]
async fn registration_limit_counts_only_the_callers_providers() {
    let fixture = fixture_with_options(SsoOptions {
        providers_limit: 1,
        ..SsoOptions::default()
    })
    .await;
    let (status, body) = post(
        fixture.app,
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "over-limit",
            "issuer": "https://idp.example.net",
            "domain": "example.net"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["message"],
        "You have reached the maximum number of SSO providers"
    );
}

#[tokio::test]
async fn provider_mutations_enforce_access_merge_configs_reset_domains_and_delete() {
    let fixture = fixture().await;
    let (status, empty) = post(
        fixture.app.clone(),
        "/api/auth/sso/update-provider",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(empty["message"], "No fields provided for update");

    let (status, forbidden) = post(
        fixture.app.clone(),
        "/api/auth/sso/update-provider",
        Some(&fixture.other_cookie),
        json!({"providerId": "acme-sso!", "domain": "login.example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden["message"],
        "You don't have access to this provider"
    );

    let (status, updated) = post(
        fixture.app.clone(),
        "/api/auth/sso/update-provider",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "acme-sso!",
            "domain": "login.example.com",
            "oidcConfig": {
                "clientSecret": "replacement-secret",
                "scopes": ["openid"],
                "unknownNestedField": "stripped"
            },
            "unknownTopLevelField": "stripped"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["domain"], "login.example.com");
    assert_eq!(updated["domainVerified"], false);
    assert_eq!(updated["oidcConfig"]["clientIdLastFour"], "****3456");
    assert_eq!(updated["oidcConfig"]["scopes"], json!(["openid"]));
    let serialized = updated.to_string();
    assert!(!serialized.contains("replacement-secret"));
    assert!(!serialized.contains("unknownNestedField"));

    let (status, forbidden) = post(
        fixture.app.clone(),
        "/api/auth/sso/delete-provider",
        Some(&fixture.other_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden["message"],
        "You don't have access to this provider"
    );

    let (status, deleted) = post(
        fixture.app.clone(),
        "/api/auth/sso/delete-provider",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted, json!({"success": true}));

    let (status, missing) = get(
        fixture.app,
        "/api/auth/sso/get-provider?providerId=acme-sso%21",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["message"], "Provider not found");
}

#[tokio::test]
async fn domain_verification_reuses_tokens_and_requires_matching_txt_records() {
    let disabled = fixture().await;
    let (status, _) = post(
        disabled.app,
        "/api/auth/sso/request-domain-verification",
        Some(&disabled.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let fixture = fixture_with_options(SsoOptions {
        domain_verification: true,
        ..SsoOptions::default()
    })
    .await;
    let (status, first) = post(
        fixture.app.clone(),
        "/api/auth/sso/request-domain-verification",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = first["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(token.len(), 24);

    let (status, second) = post(
        fixture.app.clone(),
        "/api/auth/sso/request-domain-verification",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(second["domainVerificationToken"], token);

    let (status, forbidden) = post(
        fixture.app.clone(),
        "/api/auth/sso/verify-domain",
        Some(&fixture.other_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        forbidden["message"],
        "You don't have access to this provider"
    );

    let (status, failed) = post(
        fixture.app.clone(),
        "/api/auth/sso/verify-domain",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(failed["code"], "DOMAIN_VERIFICATION_FAILED");

    *fixture.dns.records.write().await = vec![format!("_better-auth-token-acme-sso!={token}")];
    let (status, body) = post(
        fixture.app.clone(),
        "/api/auth/sso/verify-domain",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(body, Value::Null);

    let (status, provider) = get(
        fixture.app.clone(),
        "/api/auth/sso/get-provider?providerId=acme-sso%21",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(provider["domainVerified"], true);

    let (status, verified) = post(
        fixture.app,
        "/api/auth/sso/verify-domain",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(verified["code"], "DOMAIN_VERIFIED");
}
