#![cfg(feature = "axum")]

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use josekit::{
    jwk::Jwk,
    jws::{self, JwsHeader, RS256},
};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthService, AuthStore, DatabaseModel,
    DatabaseRecord, EmailSignUpInput, MemorySsoStore, MemoryStore, NewSsoProvider,
    SamlAlgorithmOptions, SignatureAlgorithm, SsoDefaultProvider, SsoDnsResolver, SsoOptions,
    SsoPlugin, SsoPrivateKey, SsoProviderMutationGuard, SsoProviderMutationGuardContext,
    SsoProviderMutationGuardInput, SsoProviderUpdate, SsoProvisioningInput, SsoStore,
    SsoUserProfilePolicy, SsoUserProvisioner, SsoUserResolution, SsoUserResolutionContext,
    SsoUserResolutionInput, SsoUserResolver,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::RwLock;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    auth_store: Arc<MemoryStore>,
    other_user_id: String,
    owner_cookie: String,
    other_cookie: String,
    dns: Arc<FixtureDnsResolver>,
    providers: Arc<MemorySsoStore>,
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
    fixture_with_options_and_trusted_origins(options, &[]).await
}

#[tokio::test]
async fn configured_default_sso_precedes_database_providers_and_matches_subdomains() {
    let fixture = fixture_with_options(SsoOptions {
        default_sso: vec![SsoDefaultProvider {
            domain: "EXAMPLE.com, subsidiary.example".into(),
            provider_id: "acme-sso!".into(),
            oidc_config: Some(json!({
                "issuer": "https://configured-idp.example.com",
                "authorizationEndpoint": "https://configured-idp.example.com/authorize",
                "tokenEndpoint": "https://configured-idp.example.com/token",
                "jwksEndpoint": "https://configured-idp.example.com/jwks",
                "clientId": "configured-client",
                "clientSecret": "configured-secret",
                "skipDiscovery": true,
                "pkce": true
            })),
            saml_config: None,
            private_key: None,
        }],
        ..SsoOptions::default()
    })
    .await;
    let response = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "email": "person@login.staff.example.com",
                        "callbackURL": "/dashboard"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(authorization.host_str(), Some("configured-idp.example.com"));
    assert_eq!(authorization.path(), "/authorize");
    assert_eq!(
        authorization
            .query_pairs()
            .find(|(key, _)| key == "client_id")
            .unwrap()
            .1,
        "configured-client"
    );
}

async fn fixture_with_options_and_trusted_origins(
    options: SsoOptions,
    trusted_origins: &[&str],
) -> Fixture {
    fixture_with_private_key(options, trusted_origins, None).await
}

async fn fixture_with_private_key(
    options: SsoOptions,
    trusted_origins: &[&str],
    private_key: Option<SsoPrivateKey>,
) -> Fixture {
    fixture_with_extensions(options, trusted_origins, private_key, None, None, None).await
}

async fn fixture_with_mutation_guard(guard: Arc<dyn SsoProviderMutationGuard>) -> Fixture {
    fixture_with_extensions(SsoOptions::default(), &[], None, None, None, Some(guard)).await
}

async fn fixture_with_extensions(
    options: SsoOptions,
    trusted_origins: &[&str],
    private_key: Option<SsoPrivateKey>,
    provisioner: Option<Arc<dyn SsoUserProvisioner>>,
    resolver: Option<Arc<dyn SsoUserResolver>>,
    mutation_guard: Option<Arc<dyn SsoProviderMutationGuard>>,
) -> Fixture {
    let mut config = AuthConfig::new([31_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.set_base_url("https://example.com").unwrap();
    for origin in trusted_origins {
        config.trust_origin(origin).unwrap();
    }
    let providers = Arc::new(MemorySsoStore::new());
    let dns = Arc::new(FixtureDnsResolver::default());
    let domain_verification = options.domain_verification;
    let mut plugin =
        SsoPlugin::with_store(options, providers.clone()).with_dns_resolver(dns.clone());
    if let Some(private_key) = private_key {
        plugin = plugin.with_default_private_key("acme-sso!", private_key);
    }
    if let Some(provisioner) = provisioner {
        plugin = plugin.with_user_provisioner(provisioner);
    }
    if let Some(resolver) = resolver {
        plugin = plugin.with_user_resolver(resolver);
    }
    if let Some(mutation_guard) = mutation_guard {
        plugin = plugin.with_provider_mutation_guard(mutation_guard);
    }
    config.add_plugin(plugin).unwrap();
    let auth_store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(auth_store.clone(), config));
    let owner = account(&service, "owner@example.com").await;
    let other = account(&service, "other@example.com").await;
    providers
        .create(NewSsoProvider {
            id: "provider-row-1".into(),
            issuer: "https://idp.example.com".into(),
            oidc_config: Some(json!({
                "discoveryEndpoint": "https://idp.example.com/.well-known/openid-configuration",
                "authorizationEndpoint": "https://idp.example.com/authorize",
                "tokenEndpoint": "https://idp.example.com/token",
                "jwksEndpoint": "https://idp.example.com/jwks",
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
            additional_fields: serde_json::Map::new(),
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
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        auth_store,
        other_user_id: other.1.clone(),
        owner_cookie: cookie(&service, &owner.0),
        other_cookie: cookie(&service, &other.0),
        dns,
        providers,
    }
}

#[derive(Default)]
struct ProvisioningRecorder {
    calls: tokio::sync::Mutex<Vec<SsoProvisioningInput>>,
}

#[async_trait]
impl SsoUserProvisioner for ProvisioningRecorder {
    async fn provision(&self, input: SsoProvisioningInput) -> Result<(), lucid_auth::AuthError> {
        self.calls.lock().await.push(input);
        Ok(())
    }
}

#[derive(Default)]
struct TransactionalResolver {
    target_user_id: RwLock<Option<String>>,
    calls: tokio::sync::Mutex<Vec<SsoUserResolutionInput>>,
}

#[derive(Default)]
struct MutationGuardRecorder {
    target_user_id: RwLock<Option<String>>,
    reject_delete: AtomicBool,
    calls: tokio::sync::Mutex<Vec<SsoProviderMutationGuardInput>>,
}

#[async_trait]
impl SsoProviderMutationGuard for MutationGuardRecorder {
    async fn guard(
        &self,
        input: SsoProviderMutationGuardInput,
        context: SsoProviderMutationGuardContext,
    ) -> Result<(), lucid_auth::AuthError> {
        let reject = matches!(input, SsoProviderMutationGuardInput::Delete { .. })
            && self.reject_delete.load(Ordering::Acquire);
        self.calls.lock().await.push(input);
        if !reject {
            return Ok(());
        }
        let user_id = self.target_user_id.read().await.clone().unwrap();
        let Some(DatabaseRecord::User(mut user)) = context
            .database
            .find_by_id(DatabaseModel::User, &user_id)
            .await?
        else {
            return Err(lucid_auth::AuthError::NotFound);
        };
        user.name = "This mutation must roll back".into();
        context.database.update(DatabaseRecord::User(user)).await?;
        Err(lucid_auth::AuthError::Forbidden)
    }
}

#[async_trait]
impl SsoUserResolver for TransactionalResolver {
    async fn resolve(
        &self,
        input: SsoUserResolutionInput,
        context: SsoUserResolutionContext,
    ) -> Result<SsoUserResolution, lucid_auth::AuthError> {
        let mut calls = self.calls.lock().await;
        let call_index = calls.len();
        calls.push(input);
        drop(calls);
        let user_id = self.target_user_id.read().await.clone().unwrap();
        if call_index == 0 {
            return Ok(SsoUserResolution::Link {
                user_id,
                profile: SsoUserProfilePolicy::Update,
            });
        }
        let Some(DatabaseRecord::User(mut user)) = context
            .database
            .find_by_id(DatabaseModel::User, &user_id)
            .await?
        else {
            return Err(lucid_auth::AuthError::NotFound);
        };
        user.name = "This update must roll back".into();
        context.database.update(DatabaseRecord::User(user)).await?;
        Ok(SsoUserResolution::Reject {
            code: "tenant_denied".into(),
            message: Some("Tenant policy denied this login".into()),
        })
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

async fn begin_oidc_sign_in(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "acme-sso!",
                        "callbackURL": "/dashboard",
                        "requestSignUp": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let state = url::Url::parse(body["url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    (cookie, state)
}

fn signed_sso_id_token(private_key: &Jwk, authorized_party: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": "https://idp.example.com",
        "aud": ["client-123456", "enterprise-api"],
        "azp": authorized_party,
        "sub": "enterprise-user-1",
        "email": "enterprise@example.com",
        "name": "Enterprise User",
        "iat": now,
        "exp": now + 300
    });
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id("sso-contract-key");
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &RS256.signer_from_jwk(private_key).unwrap(),
    )
    .unwrap()
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
async fn provider_additional_fields_enforce_input_transforms_and_returned_policy() {
    let mut options = SsoOptions::default();
    options.schema.sso_provider.additional_fields.insert(
        "tenantCode".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .transform_input(Arc::new(|value: Value| {
                Ok(Value::String(
                    value.as_str().unwrap_or_default().to_ascii_uppercase(),
                ))
            }))
            .transform_output(Arc::new(|value: Value| {
                Ok(Value::String(format!(
                    "tenant:{}",
                    value.as_str().unwrap_or_default()
                )))
            })),
    );
    options.schema.sso_provider.additional_fields.insert(
        "internalNote".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .input(false),
    );
    options.schema.sso_provider.additional_fields.insert(
        "secretTag".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .returned(false),
    );
    let fixture = fixture_with_options(options).await;
    let registration = json!({
        "providerId": "additional-fields",
        "issuer": "https://fields.example.com",
        "domain": "fields.example.com",
        "oidcConfig": {
            "clientId": "fields-client",
            "clientSecret": "fields-secret",
            "authorizationEndpoint": "https://fields.example.com/authorize",
            "tokenEndpoint": "https://fields.example.com/token",
            "jwksEndpoint": "https://fields.example.com/jwks",
            "skipDiscovery": true
        },
        "tenantCode": "blue",
        "secretTag": "classified",
        "unknownField": "stripped"
    });

    let mut blocked = registration.clone();
    blocked["providerId"] = json!("blocked-fields");
    blocked["internalNote"] = Value::Null;
    let (status, body) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        blocked,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "internalNote is not allowed to be set");

    let (status, created) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        registration,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["tenantCode"], "tenant:BLUE");
    assert!(created.get("secretTag").is_none());
    assert!(created.get("unknownField").is_none());
    let stored = fixture
        .providers
        .find_by_provider_id("additional-fields")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.additional_fields["tenantCode"], "BLUE");
    assert_eq!(stored.additional_fields["secretTag"], "classified");
    assert!(!stored.additional_fields.contains_key("unknownField"));

    let (status, updated) = post(
        fixture.app.clone(),
        "/api/auth/sso/update-provider",
        Some(&fixture.owner_cookie),
        json!({"providerId": "additional-fields", "tenantCode": "green"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["tenantCode"], "tenant:GREEN");
    assert!(updated.get("secretTag").is_none());

    let (status, blocked) = post(
        fixture.app,
        "/api/auth/sso/update-provider",
        Some(&fixture.owner_cookie),
        json!({"providerId": "additional-fields", "internalNote": null}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(blocked["message"], "internalNote is not allowed to be set");
}

#[tokio::test]
async fn oidc_sign_in_resolves_domains_and_builds_bound_pkce_authorization_urls() {
    let fixture = fixture().await;
    let (status, body) = post(
        fixture.app.clone(),
        "/api/auth/sign-in/sso",
        None,
        json!({
            "email": "person@staff.example.com",
            "callbackURL": "/dashboard",
            "loginHint": "employee@example.com",
            "additionalParams": {"tenant": "workforce"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["redirect"], true);
    let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        authorization.origin().ascii_serialization(),
        "https://idp.example.com"
    );
    let query = authorization
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "client-123456");
    assert_eq!(query["scope"], "openid email");
    assert_eq!(
        query["redirect_uri"],
        "https://example.com/api/auth/sso/callback/acme-sso!"
    );
    assert_eq!(query["login_hint"], "employee@example.com");
    assert_eq!(query["tenant"], "workforce");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["state"].len(), 32);
    assert_eq!(query["code_challenge"].len(), 43);

    let (status, reserved) = post(
        fixture.app.clone(),
        "/api/auth/sign-in/sso",
        None,
        json!({
            "providerId": "acme-sso!",
            "callbackURL": "/dashboard",
            "additionalParams": {"state": "attacker"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        reserved["message"]
            .as_str()
            .unwrap()
            .contains("additionalParams cannot include reserved OAuth parameters")
    );

    let (status, missing) = post(
        fixture.app,
        "/api/auth/sign-in/sso",
        None,
        json!({"providerId": "missing", "callbackURL": "/dashboard"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["message"], "No provider found for the issuer");
}

#[tokio::test]
async fn oidc_shared_redirect_uri_is_used_for_authorization_and_registration() {
    let fixture = fixture_with_options(SsoOptions {
        redirect_uri: Some("/sso/callback".into()),
        ..SsoOptions::default()
    })
    .await;
    let (status, body) = post(
        fixture.app.clone(),
        "/api/auth/sign-in/sso",
        None,
        json!({"providerId": "acme-sso!", "callbackURL": "/dashboard"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        authorization
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .unwrap()
            .1,
        "https://example.com/api/auth/sso/callback"
    );

    let (status, created) = post(
        fixture.app,
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "shared-redirect",
            "issuer": "https://shared.example.com",
            "domain": "shared.example.com",
            "oidcConfig": {
                "clientId": "shared-client",
                "clientSecret": "shared-secret",
                "authorizationEndpoint": "https://shared.example.com/authorize",
                "tokenEndpoint": "https://shared.example.com/token",
                "jwksEndpoint": "https://shared.example.com/jwks",
                "skipDiscovery": true
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        created["redirectURI"],
        "https://example.com/api/auth/sso/callback"
    );
}

#[tokio::test]
async fn oidc_callback_validates_bound_state_before_token_exchange() {
    let fixture = fixture().await;
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "acme-sso!",
                        "callbackURL": "/dashboard"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let state_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let state = url::Url::parse(body["url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();

    let callback = fixture
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/sso/callback/other?code=authorization-code&state={state}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers()[header::LOCATION],
        "/dashboard?error=invalid_state&error_description=sso_provider_changed_during_authentication"
    );
}

#[tokio::test]
async fn oidc_callback_exchanges_code_and_creates_a_native_session() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_base = format!("http://{}", listener.local_addr().unwrap());
    let mut private_key = Jwk::generate_rsa_key(2_048).unwrap();
    private_key.set_key_id("sso-contract-key");
    private_key.set_algorithm("RS256");
    let mut public_key = private_key.to_public_key().unwrap();
    public_key.set_key_id("sso-contract-key");
    public_key.set_algorithm("RS256");
    let id_token = signed_sso_id_token(&private_key, "client-123456");
    let invalid_id_token = signed_sso_id_token(&private_key, "different-client");
    let assertion_public_key = public_key.clone();
    let private_key_material = SsoPrivateKey {
        private_key_jwk: Some(serde_json::to_value(&private_key).unwrap()),
        kid: Some("sso-contract-key".into()),
        algorithm: Some("RS256".into()),
        ..SsoPrivateKey::default()
    };
    let (assertion_requests, mut assertion_receiver) = tokio::sync::mpsc::unbounded_channel();
    let identity_provider = Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get({
                let base = idp_base.clone();
                move || {
                    let base = base.clone();
                    async move {
                        Json(json!({
                            "issuer": "https://idp.example.com",
                            "authorization_endpoint": format!("{base}/authorize"),
                            "token_endpoint": format!("{base}/token"),
                            "jwks_uri": format!("{base}/jwks"),
                            "userinfo_endpoint": format!("{base}/userinfo"),
                            "token_endpoint_auth_methods_supported": ["client_secret_basic"]
                        }))
                    }
                }
            }),
        )
        .route(
            "/token",
            axum::routing::post({
                let id_token = id_token.clone();
                let invalid_id_token = invalid_id_token.clone();
                let assertion_requests = assertion_requests.clone();
                move |axum::extract::Form(params): axum::extract::Form<
                    std::collections::BTreeMap<String, String>,
                >| {
                    assertion_requests.send(params.clone()).unwrap();
                    let id_token = if params.get("code").is_some_and(|code| code == "invalid-azp") {
                        invalid_id_token.clone()
                    } else {
                        id_token.clone()
                    };
                    async move {
                        Json(json!({
                            "access_token": params.get("code").cloned().unwrap_or_default(),
                            "token_type": "Bearer",
                            "id_token": id_token
                        }))
                    }
                }
            }),
        )
        .route(
            "/jwks",
            axum::routing::get(move || {
                let public_key = public_key.clone();
                async move { Json(json!({"keys": [public_key]})) }
            }),
        )
        .route(
            "/userinfo",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                let subject = if headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.ends_with("mismatched-code"))
                {
                    "different-enterprise-user"
                } else {
                    "enterprise-user-1"
                };
                Json(json!({
                    "sub": subject,
                    "email": "enterprise@example.com",
                    "email_verified": "true",
                    "name": "Enterprise User"
                }))
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, identity_provider).await.unwrap();
    });

    let provisioning = Arc::new(ProvisioningRecorder::default());
    let resolver = Arc::new(TransactionalResolver::default());
    let fixture = fixture_with_extensions(
        SsoOptions {
            trust_email_verified: true,
            disable_implicit_sign_up: true,
            provision_user_on_every_login: true,
            ..SsoOptions::default()
        },
        &[idp_base.as_str()],
        Some(private_key_material),
        Some(provisioning.clone()),
        Some(resolver.clone()),
        None,
    )
    .await;
    *resolver.target_user_id.write().await = Some(fixture.other_user_id.clone());
    fixture
        .providers
        .update(
            "provider-row-1",
            SsoProviderUpdate {
                oidc_config: Some(Some(json!({
                    "discoveryEndpoint": format!("{idp_base}/.well-known/openid-configuration"),
                    "authorizationEndpoint": "https://explicit.example.com/authorize",
                    "clientId": "client-123456",
                    "tokenEndpointAuthentication": "private_key_jwt",
                    "privateKeyId": "sso-contract-key",
                    "privateKeyAlgorithm": "RS256",
                    "pkce": true,
                    "scopes": ["openid", "email"]
                }))),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "acme-sso!",
                        "callbackURL": "/dashboard",
                        "requestSignUp": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let state_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let authorization = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(authorization.host_str(), Some("explicit.example.com"));
    let state = authorization
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = fixture
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/sso/callback/acme-sso%21?code=valid-code&state={state}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(callback.headers()[header::LOCATION], "/dashboard");
    assert!(
        callback
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|cookie| cookie.to_str().unwrap().contains("session_token="))
    );
    let session_cookie = callback
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|cookie| {
            let cookie = cookie.to_str().ok()?;
            cookie
                .contains("session_token=")
                .then(|| cookie.split(';').next().unwrap().to_owned())
        })
        .unwrap();
    let (status, session) = get(
        fixture.app.clone(),
        "/api/auth/get-session",
        Some(&session_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["user"]["emailVerified"], true);
    let calls = provisioning.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].provider.provider_id, "acme-sso!");
    assert_eq!(calls[0].user.email, "enterprise@example.com");
    assert_eq!(calls[0].user_info.account_id, "enterprise-user-1");
    assert_eq!(
        calls[0].tokens.as_ref().unwrap().access_token.as_deref(),
        Some("valid-code")
    );
    drop(calls);
    let resolutions = resolver.calls.lock().await;
    assert_eq!(resolutions.len(), 1);
    let SsoUserResolutionInput::Oidc {
        provider_claims,
        verified_id_token_claims,
        ..
    } = &resolutions[0]
    else {
        panic!("expected OIDC resolution input");
    };
    assert_eq!(provider_claims["sub"], "enterprise-user-1");
    assert_eq!(verified_id_token_claims["iss"], "https://idp.example.com");
    drop(resolutions);
    let token_request = assertion_receiver.recv().await.unwrap();
    assert_eq!(
        token_request["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    assert_eq!(token_request["client_id"], "client-123456");
    assert!(!token_request.contains_key("client_secret"));
    let verifier = RS256.verifier_from_jwk(&assertion_public_key).unwrap();
    let (assertion, _) =
        josekit::jwt::decode_with_verifier(&token_request["client_assertion"], &verifier).unwrap();
    assert_eq!(assertion.issuer(), Some("client-123456"));
    assert_eq!(assertion.subject(), Some("client-123456"));
    let expected_audience = format!("{idp_base}/token");
    assert_eq!(assertion.audience(), Some(vec![expected_audience.as_str()]));

    let (state_cookie, state) = begin_oidc_sign_in(&fixture.app).await;
    let mismatch = fixture
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/sso/callback/acme-sso%21?code=mismatched-code&state={state}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::FOUND);
    assert_eq!(
        mismatch.headers()[header::LOCATION],
        "/dashboard?error=invalid_provider&error_description=id_token_userinfo_subject_mismatch"
    );

    let (state_cookie, state) = begin_oidc_sign_in(&fixture.app).await;
    let invalid_azp = fixture
        .app
        .oneshot(
            Request::get(format!(
                "/api/auth/sso/callback/acme-sso%21?code=invalid-azp&state={state}"
            ))
            .header(header::COOKIE, state_cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_azp.status(), StatusCode::FOUND);
    assert_eq!(
        invalid_azp.headers()[header::LOCATION],
        "/dashboard?error=invalid_provider&error_description=token_not_verified"
    );
    server.abort();
}

#[tokio::test]
async fn oidc_runtime_rejects_private_server_fetches_that_are_not_explicitly_trusted() {
    let fixture = fixture().await;
    fixture
        .providers
        .update(
            "provider-row-1",
            SsoProviderUpdate {
                oidc_config: Some(Some(json!({
                    "authorizationEndpoint": "https://idp.example.com/authorize",
                    "tokenEndpoint": "http://127.0.0.1/token",
                    "jwksEndpoint": "https://idp.example.com/jwks",
                    "clientId": "client-123456",
                    "clientSecret": "secret"
                }))),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();

    let (status, body) = post(
        fixture.app,
        "/api/auth/sign-in/sso",
        None,
        json!({"providerId": "acme-sso!", "callbackURL": "/dashboard"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "discovery_private_host");
    assert!(body["message"].as_str().unwrap().contains("127.0.0.1"));
}

#[tokio::test]
async fn saml_provider_catalog_returns_safe_certificate_summaries() {
    let fixture = fixture().await;
    let owner = fixture
        .providers
        .find_by_provider_id("acme-sso!")
        .await
        .unwrap()
        .unwrap()
        .user_id;
    fixture
        .providers
        .create(NewSsoProvider {
            id: "saml-certificate-row".into(),
            issuer: "https://saml.example.com".into(),
            oidc_config: None,
            saml_config: Some(json!({
                "entryPoint": "https://saml.example.com/sso",
                "cert": "raw fallback must not be returned",
                "idpMetadata": { "cert": ["invalid certificate"] }
            })),
            user_id: owner,
            provider_id: "saml-certificate".into(),
            organization_id: None,
            domain: "saml.example.com".into(),
            domain_verified: None,
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();

    let (status, body) = get(
        fixture.app,
        "/api/auth/sso/get-provider?providerId=saml-certificate",
        Some(&fixture.owner_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["samlConfig"]["certificate"],
        json!([{ "error": "Failed to parse certificate" }])
    );
    assert!(!body.to_string().contains("raw fallback"));
    assert!(!body.to_string().contains("invalid certificate"));
}

#[tokio::test]
async fn saml_sign_in_builds_a_bound_redirect_authn_request() {
    use base64::Engine as _;
    use std::io::Read as _;

    let fixture = fixture().await;
    let owner = fixture
        .providers
        .find_by_provider_id("acme-sso!")
        .await
        .unwrap()
        .unwrap()
        .user_id;
    fixture
        .providers
        .create(NewSsoProvider {
            id: "saml-runtime-row".into(),
            issuer: "https://sp.example.com/metadata".into(),
            oidc_config: None,
            saml_config: Some(json!({
                "issuer": "https://sp.example.com/metadata",
                "entryPoint": "https://idp.example.com/sso",
                "identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "wantAssertionsSigned": true,
                "authnRequestsSigned": false
            })),
            user_id: owner,
            provider_id: "saml-runtime".into(),
            organization_id: None,
            domain: "saml-runtime.example.com".into(),
            domain_verified: None,
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();
    let response = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "saml-runtime",
                        "providerType": "saml",
                        "callbackURL": "/dashboard"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::SET_COOKIE));
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let redirect = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        redirect.as_str().split('?').next().unwrap(),
        "https://idp.example.com/sso"
    );
    let query = redirect
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query["RelayState"].len(), 32);
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&query["SAMLRequest"])
        .unwrap();
    let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
    let mut request = String::new();
    decoder.read_to_string(&mut request).unwrap();
    assert!(request.contains("<samlp:AuthnRequest"));
    assert!(request.contains("ID=\"_"));
    assert!(request.contains("Destination=\"https://idp.example.com/sso\""));
    assert!(request.contains(
        "AssertionConsumerServiceURL=\"https://example.com/api/auth/sso/saml2/sp/acs/saml-runtime\""
    ));
    assert!(request.contains("<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>"));
}

#[tokio::test]
async fn saml_acs_is_cross_origin_public_bounded_and_does_not_burn_invalid_requests() {
    use base64::Engine as _;

    let fixture = fixture().await;
    fixture
        .providers
        .update(
            "provider-row-1",
            SsoProviderUpdate {
                oidc_config: Some(None),
                saml_config: Some(Some(json!({
                    "issuer": "https://sp.example.com/metadata",
                    "entryPoint": "https://idp.example.com/sso",
                    "cert": "certificate",
                    "idpMetadata": {"entityID": "https://idp.example.com"},
                    "wantAssertionsSigned": true
                }))),
                issuer: Some("https://sp.example.com/metadata".into()),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "acme-sso!",
                        "providerType": "saml",
                        "callbackURL": "/dashboard",
                        "requestSignUp": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let relay_state = url::Url::parse(body["url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "RelayState")
        .unwrap()
        .1
        .into_owned();
    let malformed = base64::engine::general_purpose::STANDARD.encode("not SAML XML");

    for _ in 0..2 {
        let form = serde_urlencoded::to_string([
            ("SAMLResponse", malformed.as_str()),
            ("RelayState", relay_state.as_str()),
        ])
        .unwrap();
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::post("/api/auth/sso/saml2/sp/acs/acme-sso!")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("sec-fetch-site", "cross-site")
                    .header("sec-fetch-mode", "navigate")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/dashboard?error=invalid_saml_response&error_description=Invalid+SAML+response"
        );
    }

    let oversized = "a".repeat(lucid_auth::DEFAULT_MAX_SAML_RESPONSE_SIZE + 1);
    let form = serde_urlencoded::to_string([
        ("SAMLResponse", oversized.as_str()),
        ("RelayState", relay_state.as_str()),
    ])
    .unwrap();
    let response = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sso/saml2/sp/acs/acme-sso!")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "navigate")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body["message"],
        "SAML response exceeds maximum allowed size (262144 bytes)"
    );
}

#[tokio::test]
async fn saml_acs_verifies_a_signed_assertion_creates_a_session_and_rejects_replay() {
    use base64::Engine as _;
    use samlet::{
        raw::{
            Binding, EntitySetting, IdentityProvider, LoginResponseOptions, ServiceProvider, User,
            metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig},
        },
        template::{LoginResponseAttribute, LoginResponseTemplate},
    };
    use std::io::Read as _;

    const PRIVATE_KEY: &str = include_str!("fixtures/saml_private_key.pem");
    const CERTIFICATE: &str = include_str!("fixtures/saml_signing_cert.pem");

    let provisioning = Arc::new(ProvisioningRecorder::default());
    let resolver = Arc::new(TransactionalResolver::default());
    let fixture = fixture_with_extensions(
        SsoOptions {
            saml_algorithms: SamlAlgorithmOptions {
                allowed_signature_algorithms: Some(vec![SignatureAlgorithm::RSA_SHA256.into()]),
                ..SamlAlgorithmOptions::default()
            },
            saml_allow_idp_initiated: true,
            saml_idp_initiated_callback_url: Some("/idp-home".into()),
            provision_user_on_every_login: true,
            ..SsoOptions::default()
        },
        &[],
        None,
        Some(provisioning.clone()),
        Some(resolver.clone()),
        None,
    )
    .await;
    *resolver.target_user_id.write().await = Some(fixture.other_user_id.clone());
    fixture
        .providers
        .update(
            "provider-row-1",
            SsoProviderUpdate {
                oidc_config: Some(None),
                saml_config: Some(Some(json!({
                    "issuer": "https://sp.example.com/metadata",
                    "entryPoint": "https://idp.example.com/sso",
                    "cert": CERTIFICATE,
                    "idpMetadata": {"entityID": "https://idp.example.com/metadata"},
                    "idpInitiatedCallbackUrl": "https://example.com/api/auth/sso/saml2/sp/acs/acme-sso!",
                    "wantAssertionsSigned": true,
                    "mapping": {
                        "email": "mail",
                        "firstName": "givenName",
                        "lastName": "surname"
                    }
                }))),
                issuer: Some("https://sp.example.com/metadata".into()),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/sso")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "providerId": "acme-sso!",
                        "providerType": "saml",
                        "callbackURL": "/dashboard",
                        "requestSignUp": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let redirect = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let parameters = redirect
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&parameters["SAMLRequest"])
        .unwrap();
    let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
    let mut request_xml = String::new();
    decoder.read_to_string(&mut request_xml).unwrap();
    let request_id = request_xml
        .split(" ID=\"")
        .nth(1)
        .and_then(|value| value.split('"').next())
        .unwrap();
    let acs = "https://example.com/api/auth/sso/saml2/sp/acs/acme-sso!";
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: true,
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, acs)],
            ..Default::default()
        },
        EntitySetting::default(),
    )
    .unwrap();
    let mut idp_setting = EntitySetting::default();
    idp_setting.private_key = Some(PRIVATE_KEY.into());
    idp_setting.signing_cert = Some(CERTIFICATE.into());
    idp_setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: [
            ("mail", "email"),
            ("givenName", "first_name"),
            ("surname", "last_name"),
        ]
        .into_iter()
        .map(|(name, value_tag)| LoginResponseAttribute {
            name: name.into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: value_tag.into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        })
        .collect(),
    });
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERTIFICATE.into()],
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        },
        idp_setting,
    )
    .unwrap();
    let response = idp
        .create_login_response(
            &sp,
            Binding::Post,
            &User {
                name_id: "saml-user-1".into(),
                attributes: vec![
                    ("email".into(), "employee@example.com".into()),
                    ("first_name".into(), "Enterprise".into()),
                    ("last_name".into(), "User".into()),
                ],
                session_index: Some("session-1".into()),
            },
            &LoginResponseOptions {
                in_response_to: Some(request_id),
                relay_state: Some(&parameters["RelayState"]),
                ..Default::default()
            },
        )
        .unwrap();
    let form = serde_urlencoded::to_string([
        ("SAMLResponse", response.context.as_str()),
        ("RelayState", parameters["RelayState"].as_str()),
    ])
    .unwrap();
    let assertion = || {
        Request::post("/api/auth/sso/saml2/sp/acs/acme-sso!")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "cross-site")
            .header("sec-fetch-mode", "navigate")
            .body(Body::from(form.clone()))
            .unwrap()
    };
    let authenticated = fixture.app.clone().oneshot(assertion()).await.unwrap();
    assert_eq!(authenticated.status(), StatusCode::FOUND);
    assert_eq!(authenticated.headers()[header::LOCATION], "/dashboard");
    let session_cookie = authenticated
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.contains("session_token"))
        .and_then(|value| value.split(';').next())
        .unwrap()
        .to_owned();
    let session = fixture
        .app
        .clone()
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let session: Value =
        serde_json::from_slice(&session.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        session["user"]["email"], "employee@example.com",
        "{session}"
    );
    assert_eq!(session["user"]["name"], "Enterprise User");
    let calls = provisioning.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].provider.provider_id, "acme-sso!");
    assert_eq!(calls[0].user.email, "employee@example.com");
    assert_eq!(calls[0].user_info.account_id, "saml-user-1");
    assert!(calls[0].tokens.is_none());
    drop(calls);
    let resolutions = resolver.calls.lock().await;
    assert_eq!(resolutions.len(), 1);
    let SsoUserResolutionInput::Saml {
        provider_id,
        account_issuer,
        account_id,
        provider_attributes,
        ..
    } = &resolutions[0]
    else {
        panic!("expected SAML resolution input");
    };
    assert_eq!(provider_id, "acme-sso!");
    assert_eq!(account_issuer, "https://idp.example.com/metadata");
    assert_eq!(account_id, "saml-user-1");
    assert_eq!(provider_attributes["mail"], "employee@example.com");
    drop(resolutions);

    let replay = fixture.app.clone().oneshot(assertion()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&replay.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body["message"],
        "State error: failed to validate relay state"
    );

    let unsolicited = idp
        .create_login_response(
            &sp,
            Binding::Post,
            &User {
                name_id: "idp-user-2".into(),
                attributes: vec![
                    ("email".into(), "idp-user@example.com".into()),
                    ("first_name".into(), "IdP".into()),
                    ("last_name".into(), "User".into()),
                ],
                session_index: Some("session-2".into()),
            },
            &LoginResponseOptions::default(),
        )
        .unwrap();
    let form =
        serde_urlencoded::to_string([("SAMLResponse", unsolicited.context.as_str())]).unwrap();
    let response = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sso/saml2/sp/acs/acme-sso!")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/idp-home?error=tenant_denied&error_description=Tenant+policy+denied+this+login"
    );
    let selected = fixture
        .auth_store
        .find_user_by_id(&fixture.other_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.name, "Enterprise User");
    assert_eq!(resolver.calls.lock().await.len(), 2);
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
async fn saml_registration_enforces_the_configured_algorithm_allow_list() {
    let fixture = fixture_with_options(SsoOptions {
        saml_algorithms: SamlAlgorithmOptions {
            allowed_signature_algorithms: Some(vec![SignatureAlgorithm::RSA_SHA512.into()]),
            ..SamlAlgorithmOptions::default()
        },
        ..SsoOptions::default()
    })
    .await;
    let (status, body) = post(
        fixture.app,
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "algorithm-policy",
            "issuer": "https://sp.example.com",
            "domain": "example.com",
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "cert": "certificate",
                "signatureAlgorithm": "sha256"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "SAML_ALGORITHM_NOT_ALLOWED");
    assert_eq!(
        body["message"],
        "SAML signature algorithm not in allow-list: sha256"
    );
}

#[tokio::test]
async fn saml_registration_enforces_authority_certificates_redirects_and_sp_policy() {
    let fixture = fixture().await;
    let base = json!({
        "issuer": "https://sp.example.com",
        "domain": "example.com"
    });
    let (status, missing_idp) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "missing-idp",
            "issuer": base["issuer"],
            "domain": base["domain"],
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "cert": "certificate"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_idp["code"], "VALIDATION_ERROR");
    assert_eq!(
        missing_idp["message"],
        "[body.samlConfig.idpMetadata] idpMetadata.entityID is required when IdP metadata XML is not provided"
    );

    let (status, missing_cert) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "missing-cert",
            "issuer": base["issuer"],
            "domain": base["domain"],
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"}
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_cert["code"], "CERT_SOURCE_MISSING");
    assert_eq!(
        missing_cert["message"],
        "samlConfig requires either a signing certificate (cert or idpMetadata.cert) or an idpMetadata.metadata XML document."
    );

    let (status, fragment) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "fragment",
            "issuer": base["issuer"],
            "domain": base["domain"],
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "cert": "certificate",
                "callbackUrl": "https://app.example.com/#fragment"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        fragment["message"],
        "[body.samlConfig.callbackUrl] callbackUrl must not contain a fragment"
    );

    let (status, policy) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "weak-sp-policy",
            "issuer": base["issuer"],
            "domain": base["domain"],
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "cert": "certificate",
                "wantAssertionsSigned": true,
                "spMetadata": {
                    "metadata": "<EntityDescriptor><SPSSODescriptor WantAssertionsSigned=\"false\"><AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com/acs\"/></SPSSODescriptor></EntityDescriptor>"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        policy["code"],
        "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH"
    );

    let (status, created) = post(
        fixture.app.clone(),
        "/api/auth/sso/register",
        Some(&fixture.owner_cookie),
        json!({
            "providerId": "workforce-saml",
            "issuer": base["issuer"],
            "domain": base["domain"],
            "samlConfig": {
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "cert": "certificate",
                "privateKey": "plaintext-upstream-private-key",
                "wantAssertionsSigned": true
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        created["samlConfig"]["privateKey"],
        "plaintext-upstream-private-key"
    );

    let metadata = fixture
        .app
        .oneshot(
            Request::get("/api/auth/sso/saml2/sp/metadata?providerId=workforce-saml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
}

#[tokio::test]
async fn provider_mutations_enforce_access_merge_configs_reset_domains_and_delete() {
    let guard = Arc::new(MutationGuardRecorder::default());
    let fixture = fixture_with_mutation_guard(guard.clone()).await;
    *guard.target_user_id.write().await = Some(fixture.other_user_id.clone());
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
    let calls = guard.calls.lock().await;
    let SsoProviderMutationGuardInput::Update {
        provider,
        is_authentication_boundary_change,
        ..
    } = &calls[0]
    else {
        panic!("expected update mutation guard input");
    };
    assert_eq!(provider.id, "provider-row-1");
    assert!(!is_authentication_boundary_change);
    drop(calls);

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

    guard.reject_delete.store(true, Ordering::Release);
    let (status, rejected) = post(
        fixture.app.clone(),
        "/api/auth/sso/delete-provider",
        Some(&fixture.owner_cookie),
        json!({"providerId": "acme-sso!"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rejected["code"], "SSO_PROVIDER_MUTATION_REJECTED");
    let rolled_back = fixture
        .auth_store
        .find_user_by_id(&fixture.other_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rolled_back.name, "other@example.com");
    assert!(
        fixture
            .providers
            .find_by_provider_id("acme-sso!")
            .await
            .unwrap()
            .is_some()
    );
    guard.reject_delete.store(false, Ordering::Release);

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

#[tokio::test]
async fn saml_metadata_is_public_and_supports_generated_and_custom_documents() {
    let fixture = fixture_with_options(SsoOptions {
        saml_enable_single_logout: true,
        ..SsoOptions::default()
    })
    .await;
    let missing = fixture
        .app
        .clone()
        .oneshot(
            Request::get("/api/auth/sso/saml2/sp/metadata?providerId=missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let invalid = fixture
        .app
        .clone()
        .oneshot(
            Request::get("/api/auth/sso/saml2/sp/metadata?providerId=acme-sso%21")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    fixture
        .providers
        .create(NewSsoProvider {
            id: "saml-row".into(),
            issuer: "https://sp.example.com/entity".into(),
            oidc_config: None,
            saml_config: Some(json!({
                "issuer": "https://sp.example.com/entity",
                "entryPoint": "https://idp.example.com/sso",
                "idpMetadata": {"entityID": "https://idp.example.com"},
                "cert": "certificate",
                "spMetadata": {"entityID": "https://sp.example.com/entity?a=1&b=2"},
                "wantAssertionsSigned": true,
                "authnRequestsSigned": true,
                "identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            })),
            user_id: "public-metadata-owner".into(),
            provider_id: "saml-provider".into(),
            organization_id: None,
            domain: "example.com".into(),
            domain_verified: None,
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();
    let generated = fixture
        .app
        .clone()
        .oneshot(
            Request::get("/api/auth/sso/saml2/sp/metadata?providerId=saml-provider")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(generated.status(), StatusCode::OK);
    assert_eq!(generated.headers()[header::CONTENT_TYPE], "application/xml");
    let xml = String::from_utf8(
        generated
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        xml,
        concat!(
            "<EntityDescriptor entityID=\"https://sp.example.com/entity?a=1&amp;b=2\" ",
            "xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" ",
            "xmlns:assertion=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
            "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" ",
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">",
            "<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>",
            "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ",
            "Location=\"https://example.com/api/auth/sso/saml2/sp/slo/saml-provider\">",
            "</SingleLogoutService>",
            "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" ",
            "Location=\"https://example.com/api/auth/sso/saml2/sp/slo/saml-provider\">",
            "</SingleLogoutService>",
            "<AssertionConsumerService index=\"0\" ",
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ",
            "Location=\"https://example.com/api/auth/sso/saml2/sp/acs/saml-provider\">",
            "</AssertionConsumerService></SPSSODescriptor></EntityDescriptor>",
        )
    );

    let custom = "<EntityDescriptor entityID=\"custom\"/>";
    fixture
        .providers
        .create(NewSsoProvider {
            id: "custom-saml-row".into(),
            issuer: "https://sp.example.com/custom".into(),
            oidc_config: None,
            saml_config: Some(json!({
                "issuer": "https://sp.example.com/custom",
                "spMetadata": {"metadata": custom}
            })),
            user_id: "public-metadata-owner".into(),
            provider_id: "custom-saml".into(),
            organization_id: None,
            domain: "custom.example.com".into(),
            domain_verified: None,
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();
    let response = fixture
        .app
        .oneshot(
            Request::get("/api/auth/sso/saml2/sp/metadata?providerId=custom-saml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(body, custom);
}

#[tokio::test]
async fn saml_single_logout_is_opt_in_and_initiates_a_bound_redirect_request() {
    let disabled = fixture().await;
    let (status, body) = post(
        disabled.app,
        "/api/auth/sso/saml2/logout/acme-sso%21",
        Some(&disabled.owner_cookie),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "SINGLE_LOGOUT_NOT_ENABLED");

    const CERTIFICATE: &str = include_str!("fixtures/saml_signing_cert.pem");
    let fixture = fixture_with_options(SsoOptions {
        saml_enable_single_logout: true,
        ..SsoOptions::default()
    })
    .await;
    fixture
        .providers
        .create(NewSsoProvider {
            id: "slo-row".into(),
            issuer: "https://sp.example.com/entity".into(),
            oidc_config: None,
            saml_config: Some(json!({
                "issuer": "https://sp.example.com/entity",
                "entryPoint": "https://idp.example.com/sso",
                "cert": CERTIFICATE,
                "idpMetadata": {
                    "entityID": "https://idp.example.com/entity",
                    "singleLogoutService": [{
                        "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                        "Location": "https://idp.example.com/logout"
                    }]
                }
            })),
            user_id: "slo-owner".into(),
            provider_id: "saml-slo".into(),
            organization_id: None,
            domain: "slo.example.com".into(),
            domain_verified: None,
            additional_fields: serde_json::Map::new(),
        })
        .await
        .unwrap();
    let response = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sso/saml2/logout/saml-slo")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .header(header::COOKIE, &fixture.owner_cookie)
                .body(Body::from(
                    json!({"callbackURL": "/signed-out"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://idp.example.com"
    );
    assert_eq!(location.path(), "/logout");
    assert!(location.query_pairs().any(|(key, _)| key == "SAMLRequest"));
    assert_eq!(
        location
            .query_pairs()
            .find(|(key, _)| key == "RelayState")
            .unwrap()
            .1,
        "/signed-out"
    );
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .unwrap()
                    .contains("better-auth.session_token=;")
            })
    );
}
