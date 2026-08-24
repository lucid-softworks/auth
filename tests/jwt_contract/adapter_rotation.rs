use super::support::{RecordingAdapter, fixture, get, json_body, payload, token_header};
use chrono::{Duration, Utc};
use lucid_auth::{JwkAlgorithm, JwtAdapterContext, JwtConfig, JwtSigningOverrides};
use serde_json::json;
use std::sync::Arc;

async fn sign(
    fixture: &super::support::Fixture,
    signing: JwtSigningOverrides,
) -> Result<String, lucid_auth::AuthError> {
    fixture
        .service
        .jwt()
        .unwrap()
        .sign_jwt(
            &JwtAdapterContext::default(),
            payload([("sub", json!("adapter-subject"))]),
            None,
            signing,
        )
        .await
}

#[tokio::test]
async fn custom_adapter_receives_data_first_and_endpoint_context() {
    let adapter = Arc::new(RecordingAdapter::default());
    let mut config = JwtConfig::default();
    config.adapter = adapter.config();
    let fixture = fixture(config);
    let response = get(&fixture.app, "/api/auth/jwks", None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        json_body(response).await["keys"].as_array().unwrap().len(),
        1
    );

    assert_eq!(adapter.keys.lock().await.len(), 1);
    let creates = adapter.creates.lock().await;
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0].method.as_deref(), Some("GET"));
    assert_eq!(creates[0].path.as_deref(), Some("/jwks"));
    drop(creates);
    let reads = adapter.reads.lock().await;
    assert_eq!(
        reads.len(),
        2,
        "empty lookup must be refetched after create"
    );
    assert_eq!(reads[0].path.as_deref(), Some("/jwks"));
}

#[tokio::test]
async fn jwks_read_does_not_rotate_but_signing_does_and_grace_is_strict() {
    let adapter = Arc::new(RecordingAdapter::default());
    let mut config = JwtConfig::default();
    config.adapter = adapter.config();
    config.jwks.rotation_interval = Some(Duration::hours(1));
    config.jwks.grace_period = Some(Duration::days(1));
    let rotating = fixture(config);
    let old_token = sign(&rotating, JwtSigningOverrides::default())
        .await
        .unwrap();
    assert_eq!(adapter.keys.lock().await.len(), 1);
    adapter.keys.lock().await[0].expires_at = Some(Utc::now() - Duration::seconds(1));

    let response = get(&rotating.app, "/api/auth/jwks", None).await;
    assert_eq!(
        json_body(response).await["keys"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        adapter.keys.lock().await.len(),
        1,
        "JWKS reads do not rotate"
    );
    assert!(
        rotating
            .service
            .jwt()
            .unwrap()
            .verify_jwt(&JwtAdapterContext::default(), &old_token, None)
            .await
            .unwrap()
            .is_some(),
        "internal verification reads retired stored rows"
    );

    let replacement = sign(&rotating, JwtSigningOverrides::default())
        .await
        .unwrap();
    assert_eq!(adapter.keys.lock().await.len(), 2);
    assert_ne!(
        token_header(&old_token)["kid"],
        token_header(&replacement)["kid"]
    );

    let no_grace = JwtConfig {
        adapter: adapter.config(),
        jwks: lucid_auth::JwtJwksConfig {
            grace_period: Some(Duration::zero()),
            ..lucid_auth::JwtJwksConfig::default()
        },
        ..JwtConfig::default()
    };
    let no_grace_fixture = fixture(no_grace);
    let response = get(&no_grace_fixture.app, "/api/auth/jwks", None).await;
    let keys = json_body(response).await["keys"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], token_header(&replacement)["kid"]);
}

#[tokio::test]
async fn primary_extra_and_explicit_key_selection_follow_pinned_rules() {
    let adapter = Arc::new(RecordingAdapter::default());
    let mut config = JwtConfig::default();
    config.adapter = adapter.config();
    config.jwks.key_pair_config = Some(JwkAlgorithm::EdDsa);
    config.jwks.key_pair_configs = vec![JwkAlgorithm::Es256];
    let fixture = fixture(config);

    let extra = sign(
        &fixture,
        JwtSigningOverrides {
            signing_algorithm: Some(JwkAlgorithm::Es256),
            ..JwtSigningOverrides::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(token_header(&extra)["alg"], "ES256");
    let primary = sign(&fixture, JwtSigningOverrides::default())
        .await
        .unwrap();
    assert_eq!(token_header(&primary)["alg"], "EdDSA");

    let error = sign(
        &fixture,
        JwtSigningOverrides {
            signing_algorithm: Some(JwkAlgorithm::Rs256 {
                modulus_length: None,
            }),
            ..JwtSigningOverrides::default()
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("additional algorithms"));

    let primary_id = token_header(&primary)["kid"].as_str().unwrap().to_owned();
    let mut keys = adapter.keys.lock().await;
    keys.iter_mut()
        .find(|key| key.id == primary_id)
        .unwrap()
        .expires_at = Some(Utc::now() - Duration::seconds(1));
    drop(keys);
    let error = sign(
        &fixture,
        JwtSigningOverrides {
            signing_key_id: Some(primary_id),
            ..JwtSigningOverrides::default()
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("expired"));
}
