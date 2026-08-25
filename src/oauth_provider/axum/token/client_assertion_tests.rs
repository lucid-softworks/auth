#[cfg(test)]
mod client_assertion_tests {
    use super::*;
    use josekit::jwk::{Jwk, alg::ec::EcCurve, alg::ed::EdCurve};

    #[test]
    fn every_pinned_private_key_jwt_algorithm_builds_a_verifier() {
        let rsa = Jwk::generate_rsa_key(2048).unwrap().to_public_key().unwrap();
        for algorithm in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            assert!(
                client_assertion_verifier(algorithm, &rsa).is_some(),
                "{algorithm}"
            );
        }
        for (algorithm, curve) in [
            ("ES256", EcCurve::P256),
            ("ES384", EcCurve::P384),
            ("ES512", EcCurve::P521),
        ] {
            let key = Jwk::generate_ec_key(curve)
                .unwrap()
                .to_public_key()
                .unwrap();
            assert!(
                client_assertion_verifier(algorithm, &key).is_some(),
                "{algorithm}"
            );
        }
        let ed = Jwk::generate_ed_key(EdCurve::Ed25519)
            .unwrap()
            .to_public_key()
            .unwrap();
        assert!(client_assertion_verifier("EdDSA", &ed).is_some());
    }

    #[test]
    fn assertion_lifetime_boundaries_match_the_upstream_maximum() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.assertion_max_lifetime = 300;
        let now = 1_000;
        assert!(
            validate_client_assertion_lifetime(&config, &Map::new(), now, (now + 300) as f64)
                .is_ok()
        );
        let claims = Map::from_iter([("iat".into(), Value::from(now - 300))]);
        assert!(
            validate_client_assertion_lifetime(&config, &claims, now, (now + 1) as f64).is_ok()
        );
        assert!(
            validate_client_assertion_lifetime(&config, &Map::new(), now, (now + 301) as f64)
                .is_err()
        );
        let stale = Map::from_iter([("iat".into(), Value::from(now - 301))]);
        assert!(
            validate_client_assertion_lifetime(&config, &stale, now, (now + 1) as f64).is_err()
        );
        assert!(
            validate_client_assertion_lifetime(&config, &Map::new(), now, now as f64).is_err()
        );
    }

    #[test]
    fn assertion_audience_accepts_endpoint_or_provider_issuer() {
        let endpoint = "https://issuer.example/auth/oauth2/introspect";
        let provider_issuer = "https://semantic-issuer.example";
        for audience in [endpoint, provider_issuer] {
            let claims = Map::from_iter([("aud".into(), Value::String(audience.into()))]);
            assert!(
                validate_client_assertion_audience(&claims, endpoint, provider_issuer).is_ok()
            );
        }
        let claims = Map::from_iter([("aud".into(), Value::String("https://other".into()))]);
        assert!(validate_client_assertion_audience(&claims, endpoint, provider_issuer).is_err());
    }

    #[test]
    fn assertion_subject_derives_client_id_and_must_match_a_body_hint() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"client","sub":"client"}"#);
        let assertion = format!("{header}.{payload}.signature");
        assert_eq!(
            client_assertion_client_id(&assertion, None).unwrap(),
            "client"
        );
        assert!(client_assertion_client_id(&assertion, Some("different")).is_err());
    }

    #[test]
    fn jwks_hardening_rejects_private_keys_and_reserved_networks() {
        let private = Jwk::generate_rsa_key(2048).unwrap();
        let body = serde_json::to_vec(&json!({"keys":[private]})).unwrap();
        assert!(parse_public_jwks(&body).is_err());
        for host in [
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.1",
            "192.88.99.1",
            "::1",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:2::1",
            "2002:7f00:1::",
            "3fff::1",
            "5f00::1",
            "fec0::1",
            "metadata.google.internal",
            "metadata.goog",
        ] {
            assert!(!is_public_routable_host(host), "{host}");
        }
        for host in ["8.8.8.8", "2001:4860:4860::8888", "example.com", "host.local"] {
            assert!(is_public_routable_host(host), "{host}");
        }
        assert!(is_public_routable_host("2002:0808:0808::"));
    }

    #[test]
    fn registration_jwks_validation_matches_supported_public_signing_keys() {
        let mut rsa = Jwk::generate_rsa_key(2048).unwrap().to_public_key().unwrap();
        rsa.set_algorithm("RS256");
        assert!(validate_registration_jwks(&json!({"keys":[rsa]})).is_ok());

        let mut wrong_curve = Jwk::generate_ec_key(EcCurve::P256)
            .unwrap()
            .to_public_key()
            .unwrap();
        wrong_curve.set_algorithm("ES384");
        assert!(validate_registration_jwks(&json!({"keys":[wrong_curve]})).is_err());
        assert!(
            validate_registration_jwks(&json!({"keys":[{
                "kty":"OKP", "crv":"X25519", "x":"value"
            }]}))
            .is_err()
        );
    }
}
