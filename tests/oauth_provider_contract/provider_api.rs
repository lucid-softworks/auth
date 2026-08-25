use super::support::*;

#[tokio::test]
async fn request_bound_provider_api_exposes_the_pinned_capability_surface() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.scopes.push("api.read".into());
    let fixture = fixture_with_provider(provider.clone()).await;
    let (client_id, client_secret) = super::tokens::create_m2m_client(&fixture).await;
    let plugin = OAuthProviderPlugin::from_arc(provider, fixture.oauth.clone());
    let mut request = OAuthProviderApiRequest::new("http://localhost/api/auth/oauth2/token");
    request
        .parameters
        .insert("client_id".into(), vec![client_id.clone()]);
    request
        .parameters
        .insert("client_secret".into(), vec![client_secret]);
    let api = plugin
        .provider_api(
            fixture.service.clone(),
            request,
            Some("client_credentials".into()),
        )
        .unwrap();

    assert_eq!(api.get_issuer(), "http://localhost/api/auth");

    assert_eq!(
        api.get_client(&client_id).await.unwrap().unwrap().client_id,
        client_id
    );
    let authenticated = api
        .authenticate_client(OAuthProviderApiAuthenticationRequest {
            scopes: vec!["api.read".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(authenticated.method.as_deref(), Some("client_secret_post"));

    let mut issue =
        OAuthProviderApiTokenIssueInput::new(authenticated.client, vec!["api.read".into()]);
    issue
        .token_response
        .insert("companion_field".into(), json!(true));
    issue.token_response.insert("scope".into(), json!("forged"));
    let tokens = api.issue_tokens(issue).await.unwrap();
    assert_eq!(tokens["companion_field"], true);
    assert_eq!(tokens["scope"], "api.read");
    let access = tokens["access_token"].as_str().unwrap();
    assert!(
        !api.hash_token(access, lucid_auth::OAuthStoredTokenType::AccessToken)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        api.validate_access_token(access, None).await.unwrap()["active"],
        true
    );
    assert_eq!(
        api.require_active_access_token(access, None).await.unwrap()["active"],
        true
    );
}

#[tokio::test]
async fn assertion_helper_enforces_audience_lifetime_and_atomic_replay() {
    let provider = OAuthProviderPluginConfig::new("/login", "/consent");
    let fixture = fixture_with_provider(provider.clone()).await;
    let plugin = OAuthProviderPlugin::from_arc(provider, fixture.oauth.clone());
    let api = plugin
        .provider_api(
            fixture.service,
            OAuthProviderApiRequest::new("http://localhost/api/auth/companion"),
            None,
        )
        .unwrap();
    let now = Utc::now().timestamp();
    let valid = OAuthProviderClientAssertionInput {
        namespace: "urn:test:method:client".into(),
        expected_audience: "http://localhost/api/auth/companion".into(),
        payload: json!({
            "aud":"http://localhost/api/auth/companion",
            "exp": now + 60,
            "iat": now,
            "jti":"once"
        })
        .as_object()
        .unwrap()
        .clone(),
    };
    api.consume_client_assertion(valid.clone()).await.unwrap();
    assert!(api.consume_client_assertion(valid).await.is_err());

    let wrong_audience = OAuthProviderClientAssertionInput {
        namespace: "urn:test:method:client".into(),
        expected_audience: "https://wrong.example".into(),
        payload: json!({"aud":"https://right.example","exp":now + 60,"jti":"aud"})
            .as_object()
            .unwrap()
            .clone(),
    };
    assert!(api.consume_client_assertion(wrong_audience).await.is_err());
    let stale = OAuthProviderClientAssertionInput {
        namespace: "urn:test:method:client".into(),
        expected_audience: "https://right.example".into(),
        payload: json!({"aud":"https://right.example","exp":now - 1,"jti":"stale"})
            .as_object()
            .unwrap()
            .clone(),
    };
    assert!(api.consume_client_assertion(stale).await.is_err());
}
