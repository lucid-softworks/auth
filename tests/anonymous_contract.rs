use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use lucid_auth::{
    AnonymousEmailGenerator, AnonymousLinkAccount, AnonymousLinkAccountCallback,
    AnonymousNameGenerator, AnonymousPlugin, AnonymousPluginConfig, AnonymousSignInContext,
    AuthConfig, AuthError, AuthService, AuthStore, AuthorizationRequest, MemoryStore, OAuthTokens,
    OAuthUserInfo, SocialProvider,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[path = "anonymous_contract/guest.rs"]
mod guest;

#[derive(Default)]
struct LinkRecorder(Mutex<Vec<AnonymousLinkAccount>>);

#[async_trait]
impl AnonymousLinkAccountCallback for LinkRecorder {
    async fn call(&self, account: AnonymousLinkAccount) -> Result<(), AuthError> {
        self.0.lock().unwrap().push(account);
        Ok(())
    }
}

struct Fixture {
    app: Router,
    store: Arc<MemoryStore>,
    links: Arc<LinkRecorder>,
}

struct SocialFixture;

struct FixtureName;

#[async_trait]
impl AnonymousNameGenerator for FixtureName {
    async fn generate(&self, _: &AnonymousSignInContext) -> Result<String, AuthError> {
        Ok("Generated Guest".into())
    }
}

struct InvalidEmail;

#[async_trait]
impl AnonymousEmailGenerator for InvalidEmail {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok("not-an-email".into())
    }
}

#[async_trait]
impl SocialProvider for SocialFixture {
    fn id(&self) -> &str {
        "anonymous-social"
    }
    fn issuer(&self) -> Option<&str> {
        Some("https://anonymous-social.example")
    }
    fn requires_id_token_nonce(&self) -> bool {
        false
    }
    fn disable_implicit_sign_up(&self) -> bool {
        false
    }
    fn disable_sign_up(&self) -> bool {
        false
    }
    fn require_email_verification(&self) -> bool {
        false
    }
    fn supports_id_token_sign_in(&self) -> bool {
        true
    }
    fn create_authorization_url(&self, _: &AuthorizationRequest) -> Result<url::Url, AuthError> {
        url::Url::parse("https://anonymous-social.example/authorize").map_err(|_| AuthError::Worker)
    }
    async fn exchange_code(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        Err(AuthError::OAuthInvalidCode)
    }
    async fn get_user_info(
        &self,
        _: &OAuthTokens,
        _: Option<&str>,
        _: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        Ok(OAuthUserInfo {
            account_id: "anonymous-upgrade-subject".into(),
            issuer: "https://anonymous-social.example".into(),
            name: "Social Upgrade".into(),
            email: "social-upgrade@example.com".into(),
            email_verified: true,
            image: None,
            profile: serde_json::Map::new(),
        })
    }
}

fn fixture() -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let links = Arc::new(LinkRecorder::default());
    let mut config = AuthConfig::new([37_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("http://localhost").unwrap();
    config
        .add_plugin(AnonymousPlugin::new(AnonymousPluginConfig {
            on_link_account: Some(links.clone()),
            ..AnonymousPluginConfig::default()
        }))
        .unwrap();
    config.add_social_provider(SocialFixture).unwrap();
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service),
        store,
        links,
    }
}

#[tokio::test]
async fn plugin_owns_sign_in_replay_and_deletion_routes() {
    let mut core_config = AuthConfig::new([38_u8; 32]).unwrap();
    core_config.email_and_password.enabled = true;
    core_config.trust_origin("http://localhost").unwrap();
    let core = AuthService::new(Arc::new(MemoryStore::default()), core_config);
    assert!(
        core.plugin_metadata()
            .iter()
            .all(|plugin| plugin.id != "anonymous")
    );
    let core = lucid_auth::axum::router(Arc::new(core));
    let response = core
        .clone()
        .oneshot(post("/api/auth/sign-in/anonymous", None, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let permanent = core
        .oneshot(email_signup(
            "",
            "without-anonymous@example.com",
            "No Anonymous Plugin",
        ))
        .await
        .unwrap();
    assert_eq!(permanent.status(), StatusCode::OK);
    assert!(
        json_body(permanent).await["user"]
            .get("isAnonymous")
            .is_none()
    );

    let fixture = fixture();
    let (body, cookie) = anonymous_sign_in(&fixture.app, None).await;
    let user_id = body["user"]["id"].as_str().unwrap();
    assert_eq!(body["user"]["name"], "Anonymous");
    assert!(body["user"]["email"].as_str().unwrap().starts_with("temp@"));
    let repeated = fixture
        .app
        .clone()
        .oneshot(post("/api/auth/sign-in/anonymous", Some(&cookie), None))
        .await
        .unwrap();
    assert_error(
        repeated,
        StatusCode::BAD_REQUEST,
        "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    )
    .await;

    let deleted = fixture
        .app
        .clone()
        .oneshot(post("/api/auth/delete-anonymous-user", Some(&cookie), None))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(json_body(deleted).await, json!({ "success": true }));
    let id = uuid::Uuid::parse_str(user_id).unwrap();
    assert!(fixture.store.find_user_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn email_upgrade_calls_once_cleans_up_and_is_concurrency_safe() {
    let fixture = fixture();
    let (anonymous, cookie) = anonymous_sign_in(&fixture.app, None).await;
    let anonymous_id = anonymous["user"]["id"].as_str().unwrap().to_owned();

    let (left, right) = tokio::join!(
        fixture.app.clone().oneshot(email_signup(
            &cookie,
            "concurrent-upgrade@example.com",
            "First Upgrade"
        )),
        fixture.app.clone().oneshot(email_signup(
            &cookie,
            "concurrent-upgrade@example.com",
            "Second Upgrade"
        )),
    );
    let statuses = [left.unwrap().status(), right.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::UNPROCESSABLE_ENTITY)
            .count(),
        1
    );
    {
        let links = fixture.links.0.lock().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].anonymous_user.user.id.to_string(), anonymous_id);
        assert!(!links[0].new_user.user.is_anonymous);
    }
    assert!(
        fixture
            .store
            .find_user_by_id(uuid::Uuid::parse_str(&anonymous_id).unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn social_upgrade_replaces_the_anonymous_identity_without_orphaning_it() {
    let fixture = fixture();
    let (anonymous, cookie) = anonymous_sign_in(&fixture.app, None).await;
    let anonymous_id = uuid::Uuid::parse_str(anonymous["user"]["id"].as_str().unwrap()).unwrap();
    let response = fixture
        .app
        .clone()
        .oneshot(post(
            "/api/auth/sign-in/social",
            Some(&cookie),
            Some(json!({
                "provider": "anonymous-social",
                "idToken": { "token": "fixture-id-token" }
            })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["user"]["email"], "social-upgrade@example.com");
    assert_eq!(body["user"]["isAnonymous"], false);
    assert!(
        fixture
            .store
            .find_user_by_id(anonymous_id)
            .await
            .unwrap()
            .is_none()
    );
    let links = fixture.links.0.lock().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].anonymous_user.user.id, anonymous_id);
    assert_eq!(links[0].new_user.user.email, "social-upgrade@example.com");
}

#[tokio::test]
async fn generators_domain_and_disabled_deletion_match_plugin_options() {
    let mut config = AuthConfig::new([39_u8; 32]).unwrap();
    config
        .add_plugin(AnonymousPlugin::new(AnonymousPluginConfig {
            email_domain_name: Some("guests.example.com".into()),
            disable_delete_anonymous_user: true,
            generate_name: Some(Arc::new(FixtureName)),
            ..AnonymousPluginConfig::default()
        }))
        .unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let result = service.sign_in_anonymous(None, None).await.unwrap();
    assert_eq!(result.session.user.name, "Generated Guest");
    assert!(result.session.user.email.ends_with("@guests.example.com"));
    assert!(matches!(
        service.delete_anonymous_user(&result.session).await,
        Err(AuthError::AnonymousUserDeletionDisabled)
    ));

    let mut invalid = AuthConfig::new([40_u8; 32]).unwrap();
    invalid
        .add_plugin(AnonymousPlugin::new(AnonymousPluginConfig {
            generate_random_email: Some(Arc::new(InvalidEmail)),
            ..AnonymousPluginConfig::default()
        }))
        .unwrap();
    let invalid = AuthService::new(Arc::new(MemoryStore::default()), invalid);
    assert!(matches!(
        invalid.sign_in_anonymous(None, None).await,
        Err(AuthError::AnonymousInvalidEmail)
    ));
}

async fn anonymous_sign_in(app: &Router, cookie: Option<&str>) -> (Value, String) {
    let response = app
        .clone()
        .oneshot(post("/api/auth/sign-in/anonymous", cookie, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (json_body(response).await, cookie)
}

fn email_signup(cookie: &str, email: &str, name: &str) -> Request<Body> {
    post(
        "/api/auth/sign-up/email",
        Some(cookie),
        Some(json!({
            "name": name,
            "email": email,
            "password": "correct horse battery staple"
        })),
    )
}

fn post(path: &str, cookie: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut request = Request::post(path).header(header::ORIGIN, "http://localhost");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    }
}

async fn assert_error(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(json_body(response).await["code"], code);
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
