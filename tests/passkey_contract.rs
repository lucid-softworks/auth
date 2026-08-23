use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lucid_auth::{
    Assurance, AuthConfig, AuthService, AuthSession, AuthStore, MemoryStore, NewPasswordUser,
    PasskeyConfig, PasskeyPlugin, StoredPasskey, UsernamePlugin,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "passkey_contract/management.rs"]
mod management;

async fn application() -> (Router, Arc<AuthService>, Arc<MemoryStore>) {
    let mut config = AuthConfig::new([30_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig {
            rp_id: Some("localhost".into()),
            rp_name: Some("Example App".into()),
            origins: Some(vec!["http://localhost:5173".into()]),
            ..PasskeyConfig::default()
        }))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let now = Utc::now();
    store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: user.id,
            name: Some("Security key".into()),
            credential_id: "credential".into(),
            public_key: "cHVibGljLWtleQ==".into(),
            counter: 7,
            device_type: "multiDevice".into(),
            backed_up: true,
            transports: Some("internal,hybrid".into()),
            aaguid: Some("00000000-0000-0000-0000-000000000000".into()),
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    (lucid_auth::axum::router(service.clone()), service, store)
}

#[tokio::test]
async fn registration_options_match_the_official_query_and_defaults() {
    let (app, _, store) = application().await;
    let user = store.find_user_by_username("luna").await.unwrap().unwrap();
    store.delete_user_passkeys(user.id).await.unwrap();
    let cookie = sign_in_cookie(&app).await;
    let response = app
        .oneshot(
            Request::get(
                "/api/auth/passkey/generate-register-options?name=Browser%20Key&authenticatorAttachment=platform&context=enrollment",
            )
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .starts_with("better-auth.better-auth-passkey=")
    );
    let body = response_json(response).await;
    assert_eq!(body["rp"]["id"], "localhost");
    assert_eq!(body["user"]["name"], "Browser Key");
    assert_eq!(body["user"]["displayName"], "luna@users.localhost");
    assert_eq!(
        body["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );
    assert_eq!(body["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(
        body["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    let handle = body["user"]["id"].as_str().unwrap();
    assert_eq!(handle.len(), 43);
}

#[tokio::test]
async fn management_schema_and_ordinary_session_policy_match() {
    let (app, service, store) = application().await;
    let user = store.find_user_by_username("luna").await.unwrap().unwrap();
    let cookie = persisted_session_cookie(&service, &store, user.id).await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/passkey/list-user-passkeys")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = response_json(response).await;
    let passkey = &listed.as_array().unwrap()[0];
    let mut fields = passkey
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    fields.sort();
    assert_eq!(
        fields,
        [
            "aaguid",
            "backedUp",
            "counter",
            "createdAt",
            "credentialID",
            "deviceType",
            "id",
            "name",
            "publicKey",
            "transports",
            "userId",
        ]
    );
    assert_eq!(passkey["counter"], 7);
    assert!(passkey.get("updatedAt").is_none());
    let id = passkey["id"].as_str().unwrap();

    let updated = app
        .clone()
        .oneshot(passkey_request(
            "/api/auth/passkey/update-passkey",
            &cookie,
            json!({ "id": id, "name": "Laptop" }),
        ))
        .await
        .unwrap();
    assert_eq!(response_json(updated).await["passkey"]["name"], "Laptop");
    let deleted = app
        .oneshot(passkey_request(
            "/api/auth/passkey/delete-passkey",
            &cookie,
            json!({ "id": id }),
        ))
        .await
        .unwrap();
    assert_eq!(response_json(deleted).await, json!({ "status": true }));
}

#[tokio::test]
async fn request_origin_fallback_matches_official_verification_errors() {
    let mut config = AuthConfig::new([31_u8; 32]).unwrap();
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let response = lucid_auth::axum::router(service)
        .oneshot(passkey_request_without_origin(
            "/api/auth/passkey/verify-authentication",
            json!({
                "response": {
                    "id": "eA",
                    "rawId": "eA",
                    "response": {
                        "authenticatorData": "",
                        "clientDataJSON": "",
                        "signature": "",
                        "userHandle": null
                    },
                    "type": "public-key"
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        json!({ "code": "BAD_REQUEST", "message": "origin missing" })
    );
}

#[tokio::test]
async fn stale_registration_does_not_consume_the_challenge() {
    let (app, service, store) = application().await;
    let user = store.find_user_by_username("luna").await.unwrap().unwrap();
    store.delete_user_passkeys(user.id).await.unwrap();
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let fresh_session = AuthSession {
        id: Uuid::new_v4(),
        user_id: user.id,
        token_hash: hex::encode(Sha256::digest(token.as_bytes())),
        actor_user_id: None,
        assurance: Assurance::Password,
        expires_at: now + Duration::hours(1),
        created_at: now,
        updated_at: now,
        ip_address: None,
        user_agent: None,
    };
    store.create_session(fresh_session.clone()).await.unwrap();
    let session_cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&token)
    );
    let options = app
        .clone()
        .oneshot(
            Request::get("/api/auth/passkey/generate-register-options")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(options.status(), StatusCode::OK);
    let challenge_cookie = options.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let cookies = format!("{session_cookie}; {challenge_cookie}");
    let mut stale_session = fresh_session.clone();
    stale_session.created_at = now - Duration::days(2);
    store.create_session(stale_session).await.unwrap();

    let response = app
        .clone()
        .oneshot(passkey_request(
            "/api/auth/passkey/verify-registration",
            &cookies,
            malformed_registration(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["code"], "SESSION_NOT_FRESH");

    store.create_session(fresh_session).await.unwrap();
    let response = app
        .oneshot(passkey_request(
            "/api/auth/passkey/verify-registration",
            &cookies,
            malformed_registration(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["code"],
        "FAILED_TO_VERIFY_REGISTRATION"
    );
}

async fn sign_in_cookie(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"luna","password":"password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn persisted_session_cookie(
    service: &AuthService,
    store: &MemoryStore,
    user_id: Uuid,
) -> String {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id,
            token_hash: hex::encode(Sha256::digest(token.as_bytes())),
            actor_user_id: None,
            assurance: Assurance::Password,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&token)
    )
}

fn passkey_request(path: &str, cookie: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn passkey_request_without_origin(path: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn malformed_registration() -> Value {
    json!({
        "response": {
            "id": "eA",
            "rawId": "eA",
            "response": {
                "attestationObject": "",
                "clientDataJSON": "",
                "transports": []
            },
            "type": "public-key"
        }
    })
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
