use super::support::{fixture, jwt_session, payload, token_payload};
use async_trait::async_trait;
use lucid_auth::{
    AuthError, JwkAlgorithm, JwtAdapterContext, JwtAudience, JwtClaimsConfig, JwtConfig,
    JwtExpiration, JwtOverrideOptions, JwtPayloadDefinition, JwtProtectedHeader, JwtRemoteSigner,
    JwtSession, JwtSigningOverrides, JwtSubjectResolver,
};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

struct DefinedPayload;

#[async_trait]
impl JwtPayloadDefinition for DefinedPayload {
    async fn define_payload(&self, _session: &JwtSession) -> Result<Map<String, Value>, AuthError> {
        Ok(payload([
            ("iat", json!(1_700_000_000)),
            ("exp", json!(1_900_000_000)),
            ("iss", json!("payload-issuer")),
            ("aud", json!(["payload-a", "payload-b"])),
            ("sub", json!("payload-cannot-win")),
            ("role", json!("resource-reader")),
        ]))
    }
}

struct FixedSubject;

#[async_trait]
impl JwtSubjectResolver for FixedSubject {
    async fn get_subject(&self, _session: &JwtSession) -> Result<Option<String>, AuthError> {
        Ok(Some("resolved-subject".into()))
    }
}

type SignerCall = (
    Map<String, Value>,
    Option<JwtProtectedHeader>,
    JwtSigningOverrides,
);

#[derive(Default)]
struct RecordingSigner {
    calls: Mutex<Vec<SignerCall>>,
}

#[async_trait]
impl JwtRemoteSigner for RecordingSigner {
    async fn sign(
        &self,
        payload: Map<String, Value>,
        header: Option<JwtProtectedHeader>,
        signing: Option<JwtSigningOverrides>,
    ) -> Result<String, AuthError> {
        self.calls
            .lock()
            .await
            .push((payload, header, signing.unwrap_or_default()));
        Ok("kms.header.signature".into())
    }
}

#[tokio::test]
async fn default_and_custom_session_claim_precedence_match_the_service_profile() {
    let defaults = fixture(JwtConfig::default());
    let token = defaults
        .service
        .jwt()
        .unwrap()
        .get_jwt_token(
            &JwtAdapterContext::default(),
            &jwt_session("018f0000-0000-7000-8000-000000000021"),
        )
        .await
        .unwrap();
    let claims = token_payload(&token);
    assert_eq!(claims["sub"], "018f0000-0000-7000-8000-000000000021");
    assert_eq!(claims["iss"], "http://localhost");
    assert_eq!(claims["aud"], "http://localhost");
    assert_eq!(claims["custom"], "user-claim");
    let iat = claims["iat"].as_f64().unwrap();
    assert_eq!(claims["exp"].as_f64().unwrap(), iat + 900.0);

    let mut config = JwtConfig::default();
    config.jwt.issuer = Some("configured-issuer".into());
    config.jwt.audience = Some(JwtAudience::One("configured-audience".into()));
    config.jwt.expiration_time = JwtExpiration::Duration("1 minute".into());
    config.jwt.define_payload = Some(Arc::new(DefinedPayload));
    config.jwt.get_subject = Some(Arc::new(FixedSubject));
    let customized = fixture(config);
    let token = customized
        .service
        .jwt()
        .unwrap()
        .get_jwt_token(
            &JwtAdapterContext::default(),
            &jwt_session("ignored-user-id"),
        )
        .await
        .unwrap();
    let claims = token_payload(&token);
    assert_eq!(claims["iat"], 1_700_000_000_i64);
    assert_eq!(claims["exp"], 1_900_000_000_i64);
    assert_eq!(claims["iss"], "payload-issuer");
    assert_eq!(claims["aud"], json!(["payload-a", "payload-b"]));
    assert_eq!(claims["sub"], "resolved-subject");
    assert_eq!(claims["role"], "resource-reader");
}

#[tokio::test]
async fn remote_signer_receives_resolved_claims_headers_and_key_overrides() {
    let signer = Arc::new(RecordingSigner::default());
    let mut config = JwtConfig::default();
    config.jwks.remote_url = Some("opaque-kms-jwks".into());
    config.jwks.key_pair_config = Some(JwkAlgorithm::Es256);
    config.jwt.issuer = Some("https://issuer.example".into());
    config.jwt.audience = Some(JwtAudience::Many(vec!["api-a".into(), "api-b".into()]));
    config.jwt.expiration_time = JwtExpiration::NumericDate(1_900_000_123.0);
    config.jwt.sign = Some(signer.clone());
    let fixture = fixture(config);
    let signing = JwtSigningOverrides {
        signing_key_id: Some("kms-key".into()),
        signing_algorithm: Some(JwkAlgorithm::Es256),
    };
    let token = fixture
        .service
        .jwt()
        .unwrap()
        .sign_jwt(
            &JwtAdapterContext::default(),
            payload([("sub", json!("remote-subject"))]),
            Some(JwtProtectedHeader {
                typ: Some("logout+jwt".into()),
                cty: Some("application/example".into()),
            }),
            signing.clone(),
        )
        .await
        .unwrap();
    assert_eq!(token, "kms.header.signature");
    let calls = signer.calls.lock().await;
    let (payload, header, actual_signing) = &calls[0];
    assert_eq!(payload["exp"], 1_900_000_123.0);
    assert_eq!(payload["iss"], "https://issuer.example");
    assert_eq!(payload["aud"], json!(["api-a", "api-b"]));
    assert_eq!(header.as_ref().unwrap().typ.as_deref(), Some("logout+jwt"));
    assert_eq!(actual_signing, &signing);
}

#[tokio::test]
async fn server_only_override_options_replace_top_level_groups_shallowly() {
    let mut config = JwtConfig::default();
    config.jwt.issuer = Some("original-issuer".into());
    config.jwt.audience = Some("original-audience".into());
    config.jwt.expiration_time = JwtExpiration::Duration("1 hour".into());
    let fixture = fixture(config);
    let token = fixture
        .service
        .jwt()
        .unwrap()
        .sign_jwt_with_override_options(
            &JwtAdapterContext::default(),
            payload([("sub", json!("override-subject"))]),
            Some(&JwtOverrideOptions {
                jwt: Some(JwtClaimsConfig {
                    issuer: Some("override-issuer".into()),
                    audience: Some("override-audience".into()),
                    expiration_time: JwtExpiration::NumericDate(1_900_000_456.0),
                    ..JwtClaimsConfig::default()
                }),
                ..JwtOverrideOptions::default()
            }),
        )
        .await
        .unwrap();
    let claims = token_payload(&token);
    assert_eq!(claims["iss"], "override-issuer");
    assert_eq!(claims["aud"], "override-audience");
    assert_eq!(claims["exp"], 1_900_000_456.0);
}

#[test]
fn expiration_numbers_dates_and_duration_grammar_match_better_auth() {
    use chrono::{TimeZone as _, Utc};
    use lucid_auth::to_exp_jwt;

    assert_eq!(
        to_exp_jwt(&JwtExpiration::NumericDate(1234.75), 50.0).unwrap(),
        1234.75
    );
    let date = Utc.timestamp_millis_opt(1_700_000_000_999).unwrap();
    assert_eq!(
        to_exp_jwt(&JwtExpiration::Date(date), 0.0).unwrap(),
        1_700_000_000.0
    );
    for (duration, expected) in [
        ("1.5 seconds", 102.0),
        ("2 minutes ago", -20.0),
        ("1 day from now", 86_500.0),
        ("-2 hours", -7_100.0),
        ("1 month", 2_592_100.0),
    ] {
        assert_eq!(
            to_exp_jwt(&JwtExpiration::Duration(duration.into()), 100.0).unwrap(),
            expected,
            "{duration}"
        );
    }
    for invalid in ["", "1 fortnight", "NaN seconds"] {
        assert!(
            to_exp_jwt(&JwtExpiration::Duration(invalid.into()), 100.0).is_err(),
            "{invalid}"
        );
    }
}
