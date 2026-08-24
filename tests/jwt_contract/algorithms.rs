use super::support::{algorithm_config, fixture, get, json_body, signup, token, token_header};
use lucid_auth::{JwkAlgorithm, JwkStore, JwtAdapterContext, JwtSchema};

#[tokio::test]
async fn every_supported_algorithm_issues_verifies_and_publishes_only_public_material() {
    for (algorithm, expected_kty, expected_curve) in [
        (JwkAlgorithm::EdDsa, "OKP", Some("Ed25519")),
        (JwkAlgorithm::Es256, "EC", Some("P-256")),
        (JwkAlgorithm::Es512, "EC", Some("P-521")),
        (
            JwkAlgorithm::Ps256 {
                modulus_length: Some(2_048),
            },
            "RSA",
            None,
        ),
        (
            JwkAlgorithm::Rs256 {
                modulus_length: Some(2_048),
            },
            "RSA",
            None,
        ),
    ] {
        let fixture = fixture(algorithm_config(algorithm));
        let credential = signup(&fixture, algorithm.name()).await;
        let token = token(&fixture, &credential.cookie).await;
        let protected = token_header(&token);
        assert_eq!(protected["alg"], algorithm.name());
        assert!(protected["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
        assert!(protected.get("typ").is_none());

        let payload = fixture
            .service
            .jwt()
            .unwrap()
            .verify_jwt(&JwtAdapterContext::default(), &token, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload["sub"], credential.user_id);

        let response = get(&fixture.app, "/api/auth/jwks", None).await;
        assert_eq!(response.status(), 200);
        let body = json_body(response).await;
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key["kid"], protected["kid"]);
        assert_eq!(key["alg"], algorithm.name());
        assert_eq!(key["kty"], expected_kty);
        assert_eq!(
            key.get("crv").and_then(|value| value.as_str()),
            expected_curve
        );
        let stored = fixture
            .store
            .list_jwks(&JwtSchema::default())
            .await
            .unwrap();
        let stored_public: serde_json::Value = serde_json::from_str(&stored[0].public_key).unwrap();
        assert_eq!(key.get("use"), stored_public.get("use"));
        assert!(key.get("d").is_none());
        assert!(key.get("privateKey").is_none());
        if expected_kty == "RSA" {
            assert!(key["n"].as_str().is_some() && key["e"].as_str().is_some());
        } else {
            assert!(key["x"].as_str().is_some());
        }
    }
}
