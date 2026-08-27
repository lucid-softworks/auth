use super::*;
use crate::infra::dash::InfraConnectionOptions;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use josekit::{
    jwk::Jwk,
    jws::{self, JwsHeader, RS256},
};
use serde_json::json;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::mpsc;

#[derive(Clone)]
struct FixtureState {
    requests: mpsc::UnboundedSender<(&'static str, Option<Value>)>,
    public_key: Value,
}

async fn jwks(State(state): State<FixtureState>) -> Json<Value> {
    state.requests.send(("jwks", None)).unwrap();
    Json(json!({ "keys": [state.public_key] }))
}

async fn check_jti(State(state): State<FixtureState>, Json(body): Json<Value>) -> Json<Value> {
    state.requests.send(("jti", Some(body))).unwrap();
    Json(json!({ "valid": true }))
}

async fn fixture() -> (
    DashJwtVerifier,
    Jwk,
    mpsc::UnboundedReceiver<(&'static str, Option<Value>)>,
    tokio::task::JoinHandle<()>,
) {
    let mut private = Jwk::generate_rsa_key(2_048).unwrap();
    private.set_key_id("dash-key");
    private.set_algorithm("RS256");
    let mut public = private.to_public_key().unwrap();
    public.set_key_id("dash-key");
    public.set_algorithm("RS256");
    let (requests, receiver) = mpsc::unbounded_channel();
    let app = Router::new()
        .route("/api/auth/jwks", get(jwks))
        .route("/api/auth/check-jti", post(check_jti))
        .with_state(FixtureState {
            requests,
            public_key: serde_json::to_value(public).unwrap(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let resolved = InfraConnectionOptions {
        api_url: Some(format!("http://{address}")),
        api_key: Some("managed-key".into()),
        ..InfraConnectionOptions::default()
    }
    .resolve();
    let verifier =
        DashJwtVerifier::with_clock(&resolved, || UNIX_EPOCH + Duration::from_secs(1_000));
    (verifier, private, receiver, server)
}

fn token(private: &Jwk, issued_at: i64, hash: &str) -> String {
    let claims = json!({
        "iat": issued_at,
        "exp": 2_000,
        "jti": "managed-jti",
        "apiKeyHash": hash,
        "organizationId": "organization"
    });
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id("dash-key");
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &RS256.signer_from_jwk(private).unwrap(),
    )
    .unwrap()
}

fn api_key_hash() -> String {
    hex::encode(Sha256::digest(b"managed-key"))
}

#[tokio::test]
async fn old_tokens_fetch_jwks_check_jti_and_apply_route_claims() {
    let (verifier, private, mut requests, server) = fixture().await;
    let token = token(&private, 900, &api_key_hash());
    let claims = verifier
        .verify_authorization_with(Some(&format!("Bearer {token}")), |claims| {
            claims
                .get("organizationId")
                .and_then(Value::as_str)
                .map(|value| json!({ "organizationId": value }))
        })
        .await
        .unwrap();

    assert_eq!(claims.0, json!({ "organizationId": "organization" }));
    assert_eq!(requests.recv().await.unwrap(), ("jwks", None));
    assert_eq!(
        requests.recv().await.unwrap(),
        (
            "jti",
            Some(json!({ "jti": "managed-jti", "expiresAt": 2_000 }))
        )
    );
    server.abort();
}

#[tokio::test]
async fn fresh_and_validate_policies_skip_jti() {
    let (verifier, private, mut requests, server) = fixture().await;
    let fresh = token(&private, 971, &api_key_hash());
    verifier
        .verify_authorization(Some(&format!("literal {fresh}")))
        .await
        .unwrap();
    assert_eq!(requests.recv().await.unwrap(), ("jwks", None));
    assert!(requests.try_recv().is_err());

    let old = token(&private, 900, &api_key_hash());
    verifier
        .validate_authorization(Some(&format!("anything {old}")))
        .await
        .unwrap();
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[tokio::test]
async fn cold_jwks_requests_coalesce_and_the_thirty_second_boundary_checks_jti() {
    let (verifier, private, mut requests, server) = fixture().await;
    let fresh = token(&private, 971, &api_key_hash());
    let authorization = format!("Bearer {fresh}");
    let (first, second) = tokio::join!(
        verifier.verify_authorization(Some(&authorization)),
        verifier.verify_authorization(Some(&authorization))
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(requests.recv().await.unwrap(), ("jwks", None));
    assert!(requests.try_recv().is_err());

    let boundary = token(&private, 970, &api_key_hash());
    verifier
        .verify_authorization(Some(&format!("Bearer {boundary}")))
        .await
        .unwrap();
    assert_eq!(
        requests.recv().await.unwrap(),
        (
            "jti",
            Some(json!({ "jti": "managed-jti", "expiresAt": 2_000 }))
        )
    );
    server.abort();
}

#[tokio::test]
async fn expired_jwks_returns_stale_while_refreshing_in_the_background() {
    let (verifier, private, mut requests, server) = fixture().await;
    let stale = json!({ "keys": [] });
    cache::seed(
        &verifier.api_url,
        stale.clone(),
        Instant::now() - Duration::from_secs(1),
    )
    .await;

    assert_eq!(
        cache::get(&verifier.api_url, &verifier.api).await.unwrap(),
        stale
    );
    assert_eq!(requests.recv().await.unwrap(), ("jwks", None));
    let mut refreshed = stale.clone();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        refreshed = cache::get(&verifier.api_url, &verifier.api).await.unwrap();
        if refreshed != stale {
            break;
        }
    }
    let public = serde_json::to_value(private.to_public_key().unwrap()).unwrap();
    assert_eq!(refreshed["keys"][0]["n"], public["n"]);
    assert_eq!(refreshed["keys"][0]["kid"], "dash-key");
    assert_eq!(refreshed["keys"][0]["alg"], "RS256");
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[tokio::test]
async fn header_split_hash_age_signature_and_route_failures_are_unauthorized() {
    let (verifier, private, _requests, server) = fixture().await;
    let valid = token(&private, 971, &api_key_hash());
    assert_eq!(
        verifier.verify_authorization(Some(&valid)).await,
        Err(DashAuthorizationError)
    );
    assert_eq!(
        verifier
            .verify_authorization(Some(&format!("Bearer  {valid}")))
            .await,
        Err(DashAuthorizationError)
    );
    let wrong_hash = token(&private, 971, "wrong");
    assert_eq!(
        verifier
            .verify_authorization(Some(&format!("Bearer {wrong_hash}")))
            .await,
        Err(DashAuthorizationError)
    );
    let expired_age = token(&private, 699, &api_key_hash());
    assert_eq!(
        verifier
            .verify_authorization(Some(&format!("Bearer {expired_age}")))
            .await,
        Err(DashAuthorizationError)
    );
    assert_eq!(
        verifier
            .verify_authorization_with(Some(&format!("Bearer {valid}")), |_| None)
            .await,
        Err(DashAuthorizationError)
    );
    server.abort();
}

#[test]
fn constant_time_comparison_requires_exact_lowercase_hex() {
    assert!(constant_time_equal(b"same", b"same"));
    assert!(!constant_time_equal(b"same", b"Same"));
    assert!(!constant_time_equal(b"same", b"same-longer"));
}
