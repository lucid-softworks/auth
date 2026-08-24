use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use lucid_auth::{
    AuthError, AuthorizationRequest, GenericOAuthConfig, GenericOAuthPlugin,
    GenericOAuthRefreshContext, GenericOAuthRefreshParams, OAuthClientAssertion,
    OAuthClientAssertionContext, OAuthGrantType, OAuthRefreshContext, OAuthStateStrategy,
    OAuthTokens, TokenEndpointAuth, VerificationStore,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

#[path = "generic_oauth_contract/presets.rs"]
mod presets;
#[path = "generic_oauth_contract/support.rs"]
mod support;
use support::{
    application, assert_cookie_state_mismatch, assert_generic_logout, begin_generic_flow,
    finish_generic_flow, fixture, oidc_fixture, signed_id_token,
};

#[tokio::test]
async fn discovery_fills_missing_metadata_and_explicit_endpoints_win() {
    async fn discovery(axum::extract::State(base): axum::extract::State<String>) -> Json<Value> {
        Json(json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/discovered-authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/userinfo"),
            "jwks_uri": "/jwks",
            "id_token_signing_alg_values_supported": ["HS256"]
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn({
        let base = base.clone();
        async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/discovery", get(discovery))
                    .with_state(base),
            )
            .await
            .unwrap()
        }
    });
    let mut config = GenericOAuthConfig::new("oidc", "oidc-client");
    config.discovery_url = Some(format!("{base}/discovery"));
    config.authorization_url = Some(format!("{base}/explicit-authorize"));
    let plugin = GenericOAuthPlugin::initialize(vec![config]).await.unwrap();
    let provider = plugin.providers().next().unwrap();
    assert_eq!(provider.issuer(), Some(base.as_str()));
    assert!(provider.requires_id_token_nonce());
    assert!(provider.supports_id_token_sign_in());
    let url = provider
        .create_authorization_url(&AuthorizationRequest {
            state: "state".into(),
            code_verifier: "verifier".into(),
            id_token_nonce: Some("nonce".into()),
            redirect_uri: "http://localhost/api/auth/callback/oidc".into(),
            scopes: Some(vec!["email".into()]),
            login_hint: None,
            additional_params: Default::default(),
        })
        .unwrap();
    assert_eq!(url.path(), "/explicit-authorize");
    assert_eq!(
        url.query_pairs()
            .find(|(name, _)| name == "scope")
            .unwrap()
            .1,
        "openid email"
    );
    server.abort();

    let mut unavailable = GenericOAuthConfig::new("broken", "client");
    unavailable.discovery_url = Some("http://127.0.0.1:1/discovery".into());
    assert!(
        GenericOAuthPlugin::initialize(vec![unavailable])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn discovered_oidc_verifies_signature_audience_and_nonce() {
    let (base, server) = oidc_fixture().await;
    let mut config = GenericOAuthConfig::new("oidc-flow", "oidc-client");
    config.discovery_url = Some(format!("{base}/discovery"));
    config.require_id_token_verification = true;
    let plugin = GenericOAuthPlugin::initialize(vec![config]).await.unwrap();
    let provider = plugin.providers().next().unwrap();
    let tokens = OAuthTokens {
        id_token: Some(signed_id_token(&base, "oidc-client", "bound-nonce")),
        ..OAuthTokens::default()
    };
    let info = provider
        .get_user_info(&tokens, Some("bound-nonce"), None)
        .await
        .unwrap();
    assert_eq!(info.account_id, "oidc-subject");
    assert_eq!(info.email, "oidc@example.com");
    assert!(
        provider
            .get_user_info(&tokens, Some("wrong-nonce"), None)
            .await
            .is_err()
    );
    let wrong_audience = OAuthTokens {
        id_token: Some(signed_id_token(&base, "wrong-client", "bound-nonce")),
        ..OAuthTokens::default()
    };
    assert!(
        provider
            .get_user_info(&wrong_audience, Some("bound-nonce"), None)
            .await
            .is_err()
    );
    server.abort();
}

#[derive(Clone, Default)]
struct Assertions(Arc<Mutex<Vec<OAuthClientAssertionContext>>>);

#[async_trait]
impl OAuthClientAssertion for Assertions {
    async fn client_assertion(
        &self,
        context: OAuthClientAssertionContext,
    ) -> Result<String, AuthError> {
        self.0.lock().unwrap().push(context);
        Ok("signed-client-assertion".into())
    }
}

struct RefreshAudience;

#[async_trait]
impl GenericOAuthRefreshParams for RefreshAudience {
    async fn refresh_params(
        &self,
        context: &GenericOAuthRefreshContext,
    ) -> Result<std::collections::BTreeMap<String, String>, AuthError> {
        Ok(std::collections::BTreeMap::from([(
            "audience".into(),
            context
                .request
                .as_ref()
                .and_then(|request| request.headers.get("x-workspace"))
                .cloned()
                .unwrap_or_default(),
        )]))
    }
}

#[tokio::test]
async fn private_key_jwt_refresh_context_and_configuration_failures_match() {
    let (base, evidence, server) = fixture().await;
    let assertions = Assertions::default();
    let mut config = GenericOAuthConfig::new("private", "private-client");
    config.account_issuer = Some("https://private.example".into());
    config.authorization_url = Some(format!("{base}/authorize"));
    config.token_url = Some(format!("{base}/token"));
    config.user_info_url = Some(format!("{base}/userinfo"));
    config.token_endpoint_auth = Some(TokenEndpointAuth::PrivateKeyJwt(Arc::new(
        assertions.clone(),
    )));
    config.refresh_token_params_resolver = Some(Arc::new(RefreshAudience));
    let plugin = GenericOAuthPlugin::initialize(vec![config]).await.unwrap();
    let provider = plugin.providers().next().unwrap();
    provider
        .exchange_code(
            "code",
            &"v".repeat(128),
            "http://localhost/api/auth/callback/private",
            None,
        )
        .await
        .unwrap();
    provider
        .refresh_access_token_with_context(
            "refresh",
            &OAuthRefreshContext {
                request: Some(lucid_auth::OAuthRequestContext {
                    method: "POST".into(),
                    uri: "/api/auth/refresh-token".into(),
                    headers: std::collections::BTreeMap::from([(
                        "x-workspace".into(),
                        "workspace-api".into(),
                    )]),
                }),
            },
        )
        .await
        .unwrap();
    {
        let forms = evidence.token_forms.lock().unwrap();
        assert!(forms[0].contains("client_assertion=signed-client-assertion"));
        assert!(forms[0].contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth"));
        assert!(forms[1].contains("audience=workspace-api"));
        assert!(!forms[1].contains("grant_type=overridden"));
        let assertions = assertions.0.lock().unwrap();
        assert_eq!(assertions[0].grant_type, OAuthGrantType::AuthorizationCode);
        assert_eq!(assertions[1].grant_type, OAuthGrantType::RefreshToken);
    }

    assert_manual_client_assertion(&base, &evidence).await;
    server.abort();

    let mut contradictory = GenericOAuthConfig::new("broken", "client");
    contradictory.client_secret = Some("secret".into());
    contradictory.token_endpoint_auth = Some(TokenEndpointAuth::None);
    assert!(
        GenericOAuthPlugin::initialize(vec![contradictory])
            .await
            .is_err()
    );
}

async fn assert_manual_client_assertion(base: &str, evidence: &support::Evidence) {
    let mut config = GenericOAuthConfig::new("manual", "manual-client");
    config.account_issuer = Some("https://manual.example".into());
    config.authorization_url = Some(format!("{base}/authorize"));
    config.token_url = Some(format!("{base}/token"));
    config.token_url_params.extend([
        ("client_assertion".into(), "manual-assertion".into()),
        (
            "client_assertion_type".into(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ),
    ]);
    let plugin = GenericOAuthPlugin::initialize(vec![config]).await.unwrap();
    plugin
        .providers()
        .next()
        .unwrap()
        .exchange_code("code", &"v".repeat(128), "http://localhost/callback", None)
        .await
        .unwrap();
    let forms = evidence.token_forms.lock().unwrap();
    assert!(forms[2].contains("client_assertion=manual-assertion"));
    assert!(forms[2].contains("client_id=manual-client"));
}

#[tokio::test]
async fn secret_post_basic_and_none_token_auth_match() {
    let (base, evidence, server) = fixture().await;
    let cases = [
        ("post", Some("secret"), TokenEndpointAuth::ClientSecretPost),
        (
            "basic",
            Some("secret"),
            TokenEndpointAuth::ClientSecretBasic,
        ),
        ("none", None, TokenEndpointAuth::None),
    ];
    for (id, secret, auth) in cases {
        let client_id = if id == "basic" { "client id" } else { "client" };
        let mut config = GenericOAuthConfig::new(id, client_id);
        config.account_issuer = Some(format!("https://{id}.example"));
        config.authorization_url = Some(format!("{base}/authorize"));
        config.token_url = Some(format!("{base}/token"));
        config.client_secret = secret
            .map(|value| if id == "basic" { "secret value" } else { value })
            .map(str::to_owned);
        config.token_endpoint_auth = Some(auth);
        GenericOAuthPlugin::initialize(vec![config])
            .await
            .unwrap()
            .providers()
            .next()
            .unwrap()
            .exchange_code("code", &"v".repeat(128), "http://localhost/callback", None)
            .await
            .unwrap();
    }
    let forms = evidence.token_forms.lock().unwrap();
    assert!(forms[0].contains("client_id=client"));
    assert!(forms[0].contains("client_secret=secret"));
    assert!(!forms[1].contains("client_secret="));
    assert!(forms[2].contains("client_id=client"));
    drop(forms);
    let authorizations = evidence.token_authorizations.lock().unwrap();
    assert_eq!(authorizations[0], None);
    assert_eq!(
        authorizations[1].as_deref(),
        Some("Basic Y2xpZW50K2lkOnNlY3JldCt2YWx1ZQ==")
    );
    assert_eq!(authorizations[2], None);
    server.abort();
}

#[tokio::test]
async fn duplicate_ids_keep_first_lookup_and_idp_callbacks_restart_the_flow() {
    let mut first = GenericOAuthConfig::new("duplicate", "first");
    first.account_issuer = Some("https://duplicate.example".into());
    first.authorization_url = Some("https://first.example/authorize".into());
    first.pkce = Some(false);
    let mut second = first.clone();
    second.client_id = "second".into();
    second.authorization_url = Some("https://second.example/authorize".into());
    let plugin = GenericOAuthPlugin::initialize(vec![first, second])
        .await
        .unwrap();
    let provider = plugin.providers().next().unwrap();
    let url = provider
        .create_authorization_url(&AuthorizationRequest {
            state: "state".into(),
            code_verifier: "verifier".into(),
            id_token_nonce: None,
            redirect_uri: "http://localhost/callback".into(),
            scopes: None,
            login_hint: None,
            additional_params: Default::default(),
        })
        .unwrap();
    assert_eq!(url.host_str(), Some("first.example"));
    assert!(!url.query_pairs().any(|(name, _)| name == "code_challenge"));

    let (app, _, _, server) = application(OAuthStateStrategy::Database).await;
    let response = app
        .oneshot(
            Request::get("/api/auth/callback/acme?code=idp-code")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(location.path(), "/authorize");
    assert!(location.query_pairs().any(|(name, _)| name == "state"));
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .starts_with("better-auth.state=")
    );
    server.abort();
}

#[tokio::test]
async fn ordinary_social_flow_uses_generic_provider_for_database_and_cookie_state() {
    let (corrupt_app, corrupt_store, _, corrupt_server) =
        application(OAuthStateStrategy::Database).await;
    let (corrupt_cookie, corrupt_state) =
        begin_generic_flow(&corrupt_app, OAuthStateStrategy::Database).await;
    let mut verification = corrupt_store
        .find_verification("oauth-state", &format!("oauth-state:{corrupt_state}"))
        .await
        .unwrap()
        .unwrap();
    verification.payload = json!({ "callbackURL": 42 });
    corrupt_store
        .update_verification(verification)
        .await
        .unwrap();
    let corrupt_callback = corrupt_app
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/acme?code=valid-code&state={corrupt_state}"
            ))
            .header(header::COOKIE, corrupt_cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(corrupt_callback.status(), StatusCode::FOUND);
    assert_eq!(
        corrupt_callback.headers()[header::LOCATION],
        "http://localhost/api/auth/error?error=internal_server_error"
    );
    corrupt_server.abort();

    for strategy in [OAuthStateStrategy::Database, OAuthStateStrategy::Cookie] {
        let (app, store, evidence, server) = application(strategy).await;
        let (state_cookie, state) = begin_generic_flow(&app, strategy).await;
        if strategy == OAuthStateStrategy::Cookie {
            assert_cookie_state_mismatch(&app, &state_cookie).await;
        }
        let session_cookie =
            finish_generic_flow(&app, &store, &evidence, &state_cookie, &state).await;
        assert_generic_logout(&app, &session_cookie).await;
        server.abort();
    }
}
