use super::support::{fixture, payload};
use chrono::Utc;
use lucid_auth::{JwtAdapterContext, JwtConfig, JwtSigningOverrides};
use serde_json::json;

async fn sign(
    config: &JwtConfig,
    claims: serde_json::Map<String, serde_json::Value>,
) -> (super::support::Fixture, String) {
    let fixture = fixture(config.clone());
    let token = fixture
        .service
        .jwt()
        .unwrap()
        .sign_jwt(
            &JwtAdapterContext::default(),
            claims,
            None,
            JwtSigningOverrides::default(),
        )
        .await
        .unwrap();
    (fixture, token)
}

#[tokio::test]
async fn verifier_rejects_malformed_tampered_claim_and_context_mismatches() {
    let now = Utc::now().timestamp();
    let (fixture, valid) = sign(
        &JwtConfig::default(),
        payload([("sub", json!("subject")), ("scope", json!("read"))]),
    )
    .await;
    let jwt = fixture.service.jwt().unwrap();
    let context = JwtAdapterContext::default();
    assert_eq!(
        jwt.verify_jwt(&context, &valid, None)
            .await
            .unwrap()
            .unwrap()["scope"],
        "read"
    );
    for malformed in ["", "one.two", "one.two.three.four", "%%%.two.three"] {
        assert!(
            jwt.verify_jwt(&context, malformed, None)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut tampered = valid.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert!(
        jwt.verify_jwt(&context, std::str::from_utf8(&tampered).unwrap(), None)
            .await
            .unwrap()
            .is_none()
    );

    for claims in [
        payload([("scope", json!("missing-sub"))]),
        payload([("sub", json!("subject")), ("exp", json!(now - 1))]),
        payload([("sub", json!("subject")), ("nbf", json!(now + 600))]),
        payload([("sub", json!("subject")), ("aud", json!([]))]),
    ] {
        let (fixture, token) = sign(&JwtConfig::default(), claims).await;
        assert!(
            fixture
                .service
                .jwt()
                .unwrap()
                .verify_jwt(&context, &token, None)
                .await
                .unwrap()
                .is_none()
        );
    }

    let (fixture, token) = sign(&JwtConfig::default(), payload([("sub", json!("subject"))])).await;
    assert!(
        fixture
            .service
            .jwt()
            .unwrap()
            .verify_jwt(&context, &token, Some("https://wrong-issuer.example"))
            .await
            .unwrap()
            .is_none()
    );
}
