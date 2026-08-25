use super::support::*;

#[test]
fn convenience_verifier_uses_base_url_defaults_and_explicit_resource() {
    let mut config = AuthConfig::new([207_u8; 32]).unwrap();
    config
        .set_base_url("https://issuer.example/api/auth")
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());

    let defaults = require_mcp_auth(service.clone(), RequireMcpAuthOptions::default()).unwrap();
    assert_eq!(defaults.options().issuer, "https://issuer.example/api/auth");
    assert_eq!(
        defaults.options().audience,
        "https://issuer.example/api/auth"
    );
    assert_eq!(
        defaults.options().jwks_url.as_deref(),
        Some("https://issuer.example/api/auth/jwks")
    );
    assert!(defaults.options().dpop.replay_store.is_some());

    let explicit = require_mcp_auth(
        service,
        RequireMcpAuthOptions {
            resource: Some(RESOURCE.into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(explicit.options().audience, RESOURCE);
}

#[test]
fn convenience_verifier_requires_a_resolvable_base_url() {
    let config = AuthConfig::new([208_u8; 32]).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    let error = require_mcp_auth(service, RequireMcpAuthOptions::default()).unwrap_err();
    assert!(matches!(
        error,
        lucid_auth::McpProtectedRequestError::InvalidConfiguration(_)
    ));
    assert!(
        error
            .to_string()
            .contains("requireMcpAuth requires a resolvable base URL")
    );
}

#[tokio::test]
async fn missing_credentials_return_the_exact_mcp_bearer_challenge() {
    let handler = create_mcp_protected_request_handler(handler_options()).unwrap();
    let outcome = handler
        .verify(&McpProtectedRequest {
            authorization_header: None,
            dpop_proof_jwt: None,
            method: "POST".into(),
            url: "https://api.example/mcp".into(),
        })
        .await
        .unwrap();
    let McpProtectedRequestOutcome::Challenge(challenge) = outcome else {
        panic!("missing credentials were authorized");
    };
    assert_eq!(challenge.status_code, 401);
    assert_eq!(challenge.content_type(), "application/json");
    assert_eq!(
        challenge.www_authenticate,
        "Bearer resource_metadata=\"https://api.example/.well-known/oauth-protected-resource/mcp\", scope=\"mcp.read mcp.write\""
    );
    assert_eq!(
        serde_json::from_str::<Value>(&challenge.json_rpc_body()).unwrap(),
        json!({
            "jsonrpc":"2.0",
            "error":{"code":-32000,"message":"missing authorization header"},
            "id":null
        })
    );
}

#[tokio::test]
async fn invalid_resources_fail_at_construction_and_invalid_scopes_at_invocation() {
    let mut invalid_resource = handler_options();
    invalid_resource.audience = "https://api.example/mcp?tenant=one".into();
    assert!(
        create_mcp_protected_request_handler(invalid_resource)
            .unwrap_err()
            .to_string()
            .contains("must not contain a query")
    );

    let mut invalid_scope = handler_options();
    invalid_scope.required_scopes = Some(vec!["bad scope".into()]);
    let handler = create_mcp_protected_request_handler(invalid_scope).unwrap();
    let error = handler
        .verify(&McpProtectedRequest {
            authorization_header: None,
            dpop_proof_jwt: None,
            method: "POST".into(),
            url: "https://api.example/mcp".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        lucid_auth::McpProtectedRequestError::InvalidConfiguration(_)
    ));
    assert!(error.to_string().contains("invalid required scope"));
}

#[test]
fn operation_owned_insufficient_scope_uses_the_same_json_rpc_envelope() {
    let handler = create_mcp_protected_request_handler(handler_options()).unwrap();
    let challenge = handler
        .insufficient_scope_challenge(vec!["tools.call".into()], None)
        .unwrap();
    assert_eq!(challenge.status_code, 403);
    assert!(
        challenge
            .www_authenticate
            .contains("error=\"insufficient_scope\"")
    );
    assert!(challenge.www_authenticate.contains("scope=\"tools.call\""));
    assert_eq!(
        serde_json::from_str::<Value>(&challenge.json_rpc_body()).unwrap()["error"]["message"],
        "access token is missing required scope: tools.call"
    );
}
