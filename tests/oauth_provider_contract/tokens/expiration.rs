use super::*;

#[tokio::test]
async fn numeric_scope_expiration_is_an_absolute_epoch_timestamp() {
    let expected_expiration = Utc::now().timestamp() + 120;
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.allow_unauthenticated_client_registration = true;
    provider.scopes.push("api.read".into());
    provider.scope_expirations.insert(
        "api.read".into(),
        OAuthExpiration::Timestamp(expected_expiration),
    );
    let fixture = fixture_with_provider(provider).await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;

    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "api.read"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["expires_at"], expected_expiration);
    let expires_in = tokens["expires_in"].as_i64().unwrap();
    assert!((118..=120).contains(&expires_in), "{tokens}");
}
