use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewPasswordUser};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

async fn application(configure: impl FnOnce(&mut AuthConfig)) -> Router {
    let mut config = AuthConfig::new([73_u8; 32]).unwrap();
    configure(&mut config);
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    lucid_auth::axum::router(service)
}

fn sign_in(peer: &str, forwarded_for: &str, password: &str) -> Request<Body> {
    Request::post("/api/auth/sign-in/username")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", forwarded_for)
        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
        .body(Body::from(
            json!({ "username": "luna", "password": password }).to_string(),
        ))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn trusted_chain_drives_session_metadata() {
    let app = application(|config| {
        config.ip_address.trust_proxy("10.0.0.0/8").unwrap();
    })
    .await;
    let response = app
        .clone()
        .oneshot(sign_in(
            "10.0.0.3:443",
            "198.51.100.7, 10.0.0.2",
            "password",
        ))
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
        .unwrap();
    let response = app
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response_json(response).await["session"]["ipAddress"],
        "198.51.100.7"
    );
}

#[tokio::test]
async fn untrusted_peer_cannot_rotate_spoofed_rate_limit_addresses() {
    let app = application(|config| {
        config.max_attempts = 10;
        config.max_ip_attempts = 1;
    })
    .await;
    let response = app
        .clone()
        .oneshot(sign_in("192.0.2.4:443", "198.51.100.1", "wrong"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(sign_in("192.0.2.4:8443", "198.51.100.2", "password"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(response).await["code"], "TOO_MANY_REQUESTS");
}
