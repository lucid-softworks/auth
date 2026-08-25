use super::support::*;

#[derive(Debug)]
struct RegistrationMetadata;

#[async_trait]
impl OAuthProviderExtension for RegistrationMetadata {
    fn client_registration_metadata_fields(&self) -> Vec<String> {
        vec!["tenant_hint".into()]
    }
}

#[tokio::test]
async fn registration_reports_exact_redirect_and_pairwise_metadata_errors() {
    let fixture = fixture().await;
    for (body, code, description) in [
        (
            json!({"client_name":"No redirect"}),
            "invalid_redirect_uri",
            "Redirect URIs are required for authorization_code and implicit grant types",
        ),
        (
            json!({"redirect_uris":["not a URI"]}),
            "invalid_redirect_uri",
            "redirect URI must be an absolute URI: not a URI",
        ),
        (
            json!({
                "redirect_uris":["https://client.example/callback"],
                "subject_type":"pairwise"
            }),
            "invalid_client_metadata",
            "pairwise subject_type requires server pairwiseSecret configuration",
        ),
    ] {
        let (status, _, error) = json_request(
            &fixture.app,
            "POST",
            "/api/auth/oauth2/register",
            Some(body),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["error"], code);
        assert_eq!(error["error_description"], description);
    }

    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.allow_unauthenticated_client_registration = true;
    provider.pairwise_secret = Some("pairwise-secret-at-least-32-bytes-long".into());
    let fixture = fixture_with_provider(provider).await;
    let (status, _, error) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/register",
        Some(json!({
            "redirect_uris":[
                "https://one.example/callback",
                "https://two.example/callback"
            ],
            "subject_type":"pairwise"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "invalid_client_metadata");
    assert_eq!(
        error["error_description"],
        "pairwise clients with redirect_uris on different hosts require a sector_identifier_uri, which is not yet supported. All redirect_uris must share the same host."
    );
}

#[tokio::test]
async fn each_client_input_source_strips_fields_outside_its_pinned_schema() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.allow_unauthenticated_client_registration = true;
    provider.extensions.push(Arc::new(RegistrationMetadata));
    let fixture = fixture_with_provider(provider).await;

    let (status, _, dynamic) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/register",
        Some(json!({
            "redirect_uris":["https://dynamic.example/callback"],
            "token_endpoint_auth_method":"none",
            "require_pkce":false,
            "tenant_hint":"tenant-a",
            "unknown_extension":"must be stripped"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{dynamic}");
    assert_eq!(dynamic["tenant_hint"], "tenant-a");
    assert!(dynamic.get("unknown_extension").is_none());
    assert!(dynamic.get("require_pkce").is_none());

    let (status, _, owner) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "redirect_uris":["https://owner.example/callback"],
            "client_name":"Owner client",
            "require_pkce":false,
            "subject_type":"pairwise",
            "skip_consent":true,
            "metadata":{"admin":true},
            "tenant_hint":"must be stripped",
            "dpop_bound_access_tokens":true
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{owner}");
    assert!(owner.get("require_pkce").is_none());
    assert!(owner.get("subject_type").is_none());
    assert!(owner.get("skip_consent").is_none());
    assert!(owner.get("metadata").is_none());
    assert!(owner.get("tenant_hint").is_none());
    assert_eq!(owner["dpop_bound_access_tokens"], true);

    let client_id = owner["client_id"].as_str().unwrap();
    let (status, _, updated) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/update-client",
        Some(json!({
            "client_id":client_id,
            "update":{
                "client_name":"Updated owner client",
                "token_endpoint_auth_method":"none",
                "dpop_bound_access_tokens":false,
                "subject_type":"pairwise",
                "tenant_hint":"must be stripped"
            }
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["client_name"], "Updated owner client");
    assert_eq!(updated["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(updated["dpop_bound_access_tokens"], true);
    assert!(updated.get("subject_type").is_none());
    assert!(updated.get("tenant_hint").is_none());
}
