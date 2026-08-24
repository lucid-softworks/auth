use super::{fixture::*, *};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};

const NOW: i64 = 1_700_000_000;

fn token(kid: Option<&str>, overrides: Value) -> String {
    token_at(kid, overrides, NOW)
}

async fn verify(
    verifier: &GoogleIdTokenVerifier,
    token: &str,
    domain: Option<&str>,
) -> Result<GoogleIdTokenClaims, GoogleIdTokenError> {
    verifier
        .verify_at(token, &[AUDIENCE.into()], domain, NOW)
        .await
}

#[tokio::test]
async fn maps_verified_google_claims_without_nonce_validation() {
    let (verifier, token) = verifier_and_token(
        json!({"email_verified":"true", "hd":"example.com", "picture":"avatar.png"}),
    );
    let claims = verifier
        .verify(&token, &[AUDIENCE.into()], Some("example.com"))
        .await
        .unwrap();
    assert_eq!(claims.subject, "subject-1");
    assert_eq!(claims.issuer, GOOGLE_ISSUERS[0]);
    assert_eq!(claims.email, "casey@example.com");
    assert!(claims.email_verified);
    assert_eq!(claims.name, "");
    assert_eq!(claims.picture.as_deref(), Some("avatar.png"));
    assert_eq!(claims.hosted_domain.as_deref(), Some("example.com"));
    assert_eq!(claims.profile["nonce"], "ignored-by-one-tap");

    let future = chrono::Utc::now().timestamp() + 3600;
    let (verifier, token) = verifier_and_token(json!({"nbf":future}));
    assert_eq!(
        verifier.verify(&token, &[AUDIENCE.into()], None).await,
        Err(GoogleIdTokenError::InvalidToken)
    );
}

#[tokio::test]
async fn selects_kid_or_tries_every_key_when_kid_is_absent() {
    let verifier = verifier(vec![jwk("old", false), jwk("current", true)]);
    assert!(
        verify(&verifier, &token(Some("current"), json!({})), None)
            .await
            .is_ok()
    );
    assert!(
        verify(&verifier, &token(None, json!({})), None)
            .await
            .is_ok()
    );
    assert_eq!(
        verify(&verifier, &token(Some("missing"), json!({})), None).await,
        Err(GoogleIdTokenError::KeyNotFound)
    );

    let mut forged = token(Some("current"), json!({}));
    let signature = forged.rfind('.').unwrap() + 1;
    let replacement = if &forged[signature..signature + 1] == "A" {
        "B"
    } else {
        "A"
    };
    forged.replace_range(signature..signature + 1, replacement);
    assert_eq!(
        verify(&verifier, &forged, None).await,
        Err(GoogleIdTokenError::InvalidToken)
    );

    let token = encode(
        &Header::new(Algorithm::HS256),
        &json!({"sub":"subject"}),
        &EncodingKey::from_secret(b"not-an-rsa-key"),
    )
    .unwrap();
    assert_eq!(
        verify(&verifier, &token, None).await,
        Err(GoogleIdTokenError::UnsupportedAlgorithm)
    );
}

#[tokio::test]
async fn enforces_issuers_audiences_expiry_age_subject_and_email() {
    let verifier = verifier(vec![jwk("current", true)]);
    for accepted in [
        json!({"iss": GOOGLE_ISSUERS[1]}),
        json!({"aud": ["another-client", "web-client"]}),
    ] {
        assert!(
            verify(&verifier, &token(Some("current"), accepted), None)
                .await
                .is_ok()
        );
    }
    for (overrides, error) in [
        (
            json!({"iss":"https://evil.example"}),
            GoogleIdTokenError::InvalidToken,
        ),
        (
            json!({"aud":"other-client"}),
            GoogleIdTokenError::InvalidToken,
        ),
        (json!({"exp":NOW}), GoogleIdTokenError::Expired),
        (json!({"iat":NOW-3601}), GoogleIdTokenError::TooOld),
        (json!({"iat":NOW+1}), GoogleIdTokenError::IssuedInFuture),
        (json!({"sub":""}), GoogleIdTokenError::MissingSubject),
        (json!({"email":""}), GoogleIdTokenError::MissingEmail),
    ] {
        assert_eq!(
            verify(&verifier, &token(Some("current"), overrides), None).await,
            Err(error)
        );
    }
    for accepted in [
        json!({"exp": NOW as f64 + 0.5}),
        json!({"iat": NOW as f64 - 0.5}),
        json!({"nbf": NOW as f64 - 0.5}),
    ] {
        assert!(
            verify(&verifier, &token(Some("current"), accepted), None)
                .await
                .is_ok()
        );
    }
    assert_eq!(
        verify(
            &verifier,
            &token(Some("current"), json!({"nbf": NOW as f64 + 0.5})),
            None,
        )
        .await,
        Err(GoogleIdTokenError::InvalidToken)
    );
}

#[tokio::test]
async fn enforces_hosted_domain_and_exact_email_verified_coercion() {
    let verifier = verifier(vec![jwk("current", true)]);
    let workspace = token(Some("current"), json!({"hd":"example.com"}));
    assert!(verify(&verifier, &workspace, Some("*")).await.is_ok());
    assert_eq!(
        verify(&verifier, &workspace, Some("other.example")).await,
        Err(GoogleIdTokenError::HostedDomainMismatch)
    );
    assert_eq!(
        verify(&verifier, &token(Some("current"), json!({})), Some("*")).await,
        Err(GoogleIdTokenError::HostedDomainMismatch)
    );
    for value in [json!(false), json!("false"), json!(1)] {
        let claims = verify(
            &verifier,
            &token(Some("current"), json!({"email_verified":value})),
            None,
        )
        .await
        .unwrap();
        assert!(!claims.email_verified);
    }
}
