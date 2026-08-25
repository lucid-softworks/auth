use super::support::{
    APP_ORIGIN, PREVIEW_ORIGIN, PRODUCTION_ORIGIN, PROXY_SECRET, cookie_header, decrypt_json,
    fixture, fixture_with, query_value, response_json, send, set_cookies,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{
    AccessStore, AuthStore, OAuthAccountStore, OAuthProxyConfig, OAuthProxySecret,
    OAuthStateStrategy,
};
use serde_json::{Value, json};
use url::Url;

fn proxy_config(current: &str, production: &str) -> OAuthProxyConfig {
    OAuthProxyConfig {
        current_url: Some(Url::parse(current).unwrap()),
        production_url: Some(Url::parse(production).unwrap()),
        secret: Some(OAuthProxySecret::from(PROXY_SECRET.to_vec())),
        ..OAuthProxyConfig::default()
    }
}

pub(super) async fn begin_proxy_flow(app: &axum::Router) -> (Value, Vec<String>) {
    let response = send(
        app,
        Request::post("/api/auth/sign-in/social")
            .header(header::ORIGIN, APP_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "provider": "fixture",
                    "callbackURL": format!("{APP_ORIGIN}/complete"),
                    "newUserCallbackURL": format!("{APP_ORIGIN}/welcome"),
                    "errorCallbackURL": format!("{APP_ORIGIN}/oauth-error"),
                    "disableRedirect": true
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookies(response.headers());
    (response_json(response).await, cookies)
}

struct StartedFlow {
    encrypted_state: String,
    original_state: String,
    state_cookies: Vec<String>,
}

async fn start_and_assert_preview(preview: &super::support::Fixture) -> StartedFlow {
    let (sign_in, preview_state_cookies) = begin_proxy_flow(&preview.app).await;
    assert_eq!(sign_in["redirect"], false);
    let provider_url = sign_in["url"].as_str().unwrap();
    assert_eq!(
        query_value(provider_url, "redirect_uri"),
        format!("{PRODUCTION_ORIGIN}/api/auth/callback/fixture")
    );
    let encrypted_state = query_value(provider_url, "state");
    let state_package = decrypt_json(PROXY_SECRET, &encrypted_state);
    assert_eq!(
        state_package
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["state", "stateCookie", "isOAuthProxy"]
    );
    assert_eq!(state_package["isOAuthProxy"], true);
    let original_state = state_package["state"].as_str().unwrap();
    assert_eq!(original_state.len(), 32);
    let state_data = decrypt_json(PROXY_SECRET, state_package["stateCookie"].as_str().unwrap());
    assert_eq!(state_data["oauthState"], original_state);
    let state_callback = Url::parse(state_data["callbackURL"].as_str().unwrap()).unwrap();
    assert_eq!(
        state_callback.origin().ascii_serialization(),
        PREVIEW_ORIGIN
    );
    assert_eq!(state_callback.path(), "/api/auth/oauth-proxy-callback");
    assert_eq!(
        state_callback
            .query_pairs()
            .find(|(name, _)| name == "callbackURL")
            .unwrap()
            .1,
        format!("{APP_ORIGIN}/complete")
    );
    StartedFlow {
        encrypted_state,
        original_state: original_state.into(),
        state_cookies: preview_state_cookies,
    }
}

async fn complete_and_assert_production(
    production: &super::support::Fixture,
    started: &StartedFlow,
) -> String {
    let callback = send(
        &production.app,
        Request::get(format!(
            "/api/auth/callback/fixture?code=valid-code&state={}&iss={}&device_id=ignored-device&user={}",
            percent_encoding::utf8_percent_encode(
                &started.encrypted_state,
                percent_encoding::NON_ALPHANUMERIC
            ),
            percent_encoding::utf8_percent_encode(
                "https://attacker.example.test",
                percent_encoding::NON_ALPHANUMERIC
            ),
            percent_encoding::utf8_percent_encode(
                r#"{"name":{"firstName":"Proxy","lastName":"User"}}"#,
                percent_encoding::NON_ALPHANUMERIC
            )
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::FOUND);
    let proxy_location = callback.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(proxy_location.starts_with(&format!(
        "{PREVIEW_ORIGIN}/api/auth/oauth-proxy-callback?callbackURL="
    )));
    let encrypted_profile = query_value(&proxy_location, "profile");
    let profile = decrypt_json(PROXY_SECRET, &encrypted_profile);
    assert_eq!(profile["state"], started.original_state);
    assert_eq!(profile["account"]["providerId"], "fixture");
    assert_eq!(profile["account"]["accountId"], "proxy-subject");
    assert_eq!(profile["account"]["scope"], "openid,email");
    assert_eq!(profile["profile"]["rawClaim"], "preserved");
    proxy_location
}

async fn assert_production_is_only_a_relay(production: &super::support::Fixture) {
    let exchanges = production.evidence.exchanges();
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].code, "valid-code");
    assert_eq!(exchanges[0].code_verifier.len(), 128);
    assert_eq!(
        exchanges[0].redirect_uri,
        format!("{PRODUCTION_ORIGIN}/api/auth/callback/fixture")
    );
    assert_eq!(exchanges[0].device_id, None);
    let user_info = production.evidence.user_info();
    assert_eq!(user_info.len(), 1);
    assert_eq!(user_info[0].expected_nonce, None);
    assert_eq!(
        user_info[0].provider_user.as_ref().unwrap()["name"]["firstName"],
        "Proxy"
    );
    assert!(
        production
            .store
            .find_user_by_email("proxy@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

async fn finish_and_assert_preview(
    preview: &super::support::Fixture,
    started: &StartedFlow,
    proxy_location: &str,
) {
    let receiver = send(
        &preview.app,
        Request::get(proxy_path(proxy_location))
            .header(header::COOKIE, cookie_header(&started.state_cookies))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(receiver.status(), StatusCode::FOUND);
    assert_eq!(
        receiver.headers()[header::LOCATION],
        format!("{APP_ORIGIN}/welcome")
    );
    assert!(
        set_cookies(receiver.headers())
            .iter()
            .any(|cookie| cookie.contains("better-auth.session_token="))
    );
    let user = preview
        .store
        .find_user_by_email("proxy@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(
        preview
            .store
            .find_oauth_account_owner("https://issuer.fixture", "proxy-subject")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(preview.store.list_sessions(user.id).await.unwrap().len(), 1);
}

fn proxy_path(proxy_location: &str) -> String {
    let proxy_url = Url::parse(proxy_location).unwrap();
    match proxy_url.query() {
        Some(query) => format!("{}?{query}", proxy_url.path()),
        None => proxy_url.path().to_owned(),
    }
}

async fn assert_replay_rejected(
    preview: &super::support::Fixture,
    started: &StartedFlow,
    proxy_location: &str,
) {
    let replay = send(
        &preview.app,
        Request::get(proxy_path(proxy_location))
            .header(header::COOKIE, cookie_header(&started.state_cookies))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::FOUND);
    assert_eq!(
        replay.headers()[header::LOCATION],
        format!("{APP_ORIGIN}/oauth-error?error=state_mismatch")
    );
}

#[tokio::test]
async fn separate_environments_exchange_only_profile_data_and_create_preview_session() {
    let preview = fixture(
        PREVIEW_ORIGIN,
        b'V',
        proxy_config(PREVIEW_ORIGIN, PRODUCTION_ORIGIN),
    );
    let production = fixture(
        PRODUCTION_ORIGIN,
        b'D',
        proxy_config(PRODUCTION_ORIGIN, PRODUCTION_ORIGIN),
    );
    let started = start_and_assert_preview(&preview).await;
    let proxy_location = complete_and_assert_production(&production, &started).await;
    assert_production_is_only_a_relay(&production).await;
    finish_and_assert_preview(&preview, &started, &proxy_location).await;
    assert_replay_rejected(&preview, &started, &proxy_location).await;
}

#[tokio::test]
async fn cookie_state_requires_the_preview_cookie_on_the_final_proxy_hop() {
    let preview = fixture_with(
        PREVIEW_ORIGIN,
        b'C',
        proxy_config(PREVIEW_ORIGIN, PRODUCTION_ORIGIN),
        |config| config.account.store_state_strategy = OAuthStateStrategy::Cookie,
    );
    let production = fixture(
        PRODUCTION_ORIGIN,
        b'R',
        proxy_config(PRODUCTION_ORIGIN, PRODUCTION_ORIGIN),
    );
    let started = start_and_assert_preview(&preview).await;
    let proxy_location = complete_and_assert_production(&production, &started).await;
    let without_cookie = send(
        &preview.app,
        Request::get(proxy_path(&proxy_location))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(without_cookie.status(), StatusCode::FOUND);
    assert_eq!(
        without_cookie.headers()[header::LOCATION],
        format!("{APP_ORIGIN}/oauth-error?error=state_mismatch")
    );
    finish_and_assert_preview(&preview, &started, &proxy_location).await;
}

#[tokio::test]
async fn same_origin_and_nonempty_skip_header_use_the_ordinary_social_flow() {
    let same_origin = fixture(
        PREVIEW_ORIGIN,
        b'S',
        proxy_config(PREVIEW_ORIGIN, PREVIEW_ORIGIN),
    );
    let (ordinary, _) = begin_proxy_flow(&same_origin.app).await;
    let ordinary_url = ordinary["url"].as_str().unwrap();
    assert_eq!(query_value(ordinary_url, "state").len(), 32);
    assert_eq!(
        query_value(ordinary_url, "redirect_uri"),
        format!("{PREVIEW_ORIGIN}/api/auth/callback/fixture")
    );

    let cross_origin = fixture(
        PREVIEW_ORIGIN,
        b'X',
        proxy_config(PREVIEW_ORIGIN, PRODUCTION_ORIGIN),
    );
    let skipped = send(
        &cross_origin.app,
        Request::post("/api/auth/sign-in/social")
            .header(header::ORIGIN, APP_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-skip-oauth-proxy", "false")
            .body(Body::from(
                json!({
                    "provider": "fixture",
                    "callbackURL": format!("{APP_ORIGIN}/complete"),
                    "disableRedirect": true
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(skipped.status(), StatusCode::OK);
    let skipped = response_json(skipped).await;
    let skipped_url = skipped["url"].as_str().unwrap();
    assert_eq!(query_value(skipped_url, "state").len(), 32);
    assert_eq!(
        query_value(skipped_url, "redirect_uri"),
        format!("{PREVIEW_ORIGIN}/api/auth/callback/fixture")
    );
}
