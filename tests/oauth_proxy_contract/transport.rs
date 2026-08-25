use super::{
    flow::begin_proxy_flow,
    support::{
        APP_ORIGIN, PREVIEW_ORIGIN, PRODUCTION_ORIGIN, PROXY_SECRET, cookie_header, decrypt_json,
        fixture, fixture_with, query_value, response_json, send,
    },
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{AuthStore, OAuthProxyConfig, OAuthProxySecret, OAuthProxyVersionedSecret};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use url::Url;

const REQUEST_ORIGIN: &str = "https://request-preview.example.test";
const RETIRED_PROXY_SECRET: &[u8] = b"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";

fn versioned_proxy_config(
    current: &str,
    production: &str,
    current_version: u32,
) -> OAuthProxyConfig {
    OAuthProxyConfig {
        current_url: Some(Url::parse(current).unwrap()),
        production_url: Some(Url::parse(production).unwrap()),
        secret: Some(OAuthProxySecret::Versioned(OAuthProxyVersionedSecret {
            current_version,
            keys: BTreeMap::from([
                (1, RETIRED_PROXY_SECRET.to_vec()),
                (2, PROXY_SECRET.to_vec()),
            ]),
            legacy_secret: None,
        })),
        ..OAuthProxyConfig::default()
    }
}

fn decrypt_versioned_json(secret: &[u8], version: u32, encoded: &str) -> Value {
    let prefix = format!("$ba${version}$");
    decrypt_json(secret, encoded.strip_prefix(&prefix).unwrap())
}

fn proxy_path(proxy_location: &str) -> String {
    let proxy_url = Url::parse(proxy_location).unwrap();
    match proxy_url.query() {
        Some(query) => format!("{}?{query}", proxy_url.path()),
        None => proxy_url.path().to_owned(),
    }
}

#[tokio::test]
async fn form_post_callback_and_versioned_shared_secrets_work_across_key_rotation() {
    let preview = fixture(
        PREVIEW_ORIGIN,
        b'V',
        versioned_proxy_config(PREVIEW_ORIGIN, PRODUCTION_ORIGIN, 2),
    );
    let production = fixture(
        PRODUCTION_ORIGIN,
        b'D',
        versioned_proxy_config(PRODUCTION_ORIGIN, PRODUCTION_ORIGIN, 1),
    );
    let (sign_in, state_cookies) = begin_proxy_flow(&preview.app).await;
    let provider_url = sign_in["url"].as_str().unwrap();
    let encrypted_state = query_value(provider_url, "state");
    let package = decrypt_versioned_json(PROXY_SECRET, 2, &encrypted_state);
    let original_state = package["state"].as_str().unwrap().to_owned();
    let state_cookie = package["stateCookie"].as_str().unwrap();
    let state_data = decrypt_versioned_json(PROXY_SECRET, 2, state_cookie);
    assert_eq!(state_data["oauthState"], original_state);

    let form = serde_urlencoded::to_string([
        ("code", "valid-code"),
        ("state", encrypted_state.as_str()),
        ("iss", "https://attacker.example.test"),
        ("device_id", "ignored-device"),
        (
            "user",
            r#"{"name":{"firstName":"Posted","lastName":"User"}}"#,
        ),
    ])
    .unwrap();
    let callback = send(
        &production.app,
        Request::post("/api/auth/callback/fixture")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::FOUND);
    let proxy_location = callback.headers()[header::LOCATION].to_str().unwrap();
    let encrypted_profile = query_value(proxy_location, "profile");
    let profile = decrypt_versioned_json(RETIRED_PROXY_SECRET, 1, &encrypted_profile);
    assert_eq!(profile["state"], original_state);
    assert_eq!(profile["userInfo"]["email"], "proxy@example.com");
    assert_eq!(
        production.evidence.user_info()[0]
            .provider_user
            .as_ref()
            .unwrap()["name"]["firstName"],
        "Posted"
    );
    assert_eq!(production.evidence.user_info()[0].expected_nonce, None);
    assert_eq!(production.evidence.exchanges()[0].device_id, None);

    let receiver = send(
        &preview.app,
        Request::get(proxy_path(proxy_location))
            .header(header::COOKIE, cookie_header(&state_cookies))
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
        preview
            .store
            .find_user_by_email("proxy@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn missing_current_url_uses_a_trusted_request_origin() {
    let preview = fixture_with(
        PREVIEW_ORIGIN,
        b'O',
        OAuthProxyConfig {
            current_url: None,
            production_url: Some(Url::parse(PRODUCTION_ORIGIN).unwrap()),
            secret: Some(OAuthProxySecret::from(PROXY_SECRET.to_vec())),
            ..OAuthProxyConfig::default()
        },
        |config| config.trust_origin(REQUEST_ORIGIN).unwrap(),
    );
    let response = send(
        &preview.app,
        Request::post("/api/auth/sign-in/social")
            .header(header::HOST, "request-preview.example.test")
            .header(header::ORIGIN, APP_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
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
    assert_eq!(response.status(), StatusCode::OK);
    let sign_in = response_json(response).await;
    let provider_url = sign_in["url"].as_str().unwrap();
    assert_eq!(
        query_value(provider_url, "redirect_uri"),
        format!("{PRODUCTION_ORIGIN}/api/auth/callback/fixture")
    );
    let package = decrypt_json(PROXY_SECRET, &query_value(provider_url, "state"));
    let state_data = decrypt_json(PROXY_SECRET, package["stateCookie"].as_str().unwrap());
    let callback = Url::parse(state_data["callbackURL"].as_str().unwrap()).unwrap();
    assert_eq!(callback.origin().ascii_serialization(), REQUEST_ORIGIN);
    assert_eq!(callback.path(), "/api/auth/oauth-proxy-callback");
}
