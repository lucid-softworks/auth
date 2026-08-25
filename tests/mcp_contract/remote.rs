use super::{support::*, verifier_support::*};
use lucid_auth::McpRemoteVerifyOptions;

#[tokio::test]
async fn remote_introspection_enforces_activity_issuer_and_audience() {
    let server = introspection_server().await;
    let mut options = handler_options();
    options.issuer = server.origin.clone();
    options.audience = format!("{}/mcp", server.origin);
    options.remote_verify = Some(McpRemoteVerifyOptions {
        introspect_url: format!("{}/introspect", server.origin),
        client_id: "resource-server".into(),
        client_secret: "secret".into(),
        force: true,
        allow_missing_audience: false,
    });
    let handler = create_mcp_protected_request_handler(options).unwrap();

    let active = handler
        .verify(&request_with_token("Bearer", "active"))
        .await
        .unwrap();
    let McpProtectedRequestOutcome::Authorized(claims) = active else {
        panic!("active introspection result was rejected");
    };
    assert_eq!(claims["sub"], "remote-user");

    let inactive = handler
        .verify(&request_with_token("Bearer", "inactive"))
        .await
        .unwrap();
    assert_eq!(challenge_message(inactive), "token inactive");

    let error = handler
        .verify(&request_with_token("Bearer", "wrong-audience"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        lucid_auth::McpProtectedRequestError::Infrastructure(_)
    ));
    assert_eq!(error.to_string(), "introspection claims are invalid");

    let mut allow_missing = handler.options().clone();
    allow_missing
        .remote_verify
        .as_mut()
        .unwrap()
        .allow_missing_audience = true;
    let allow_missing = create_mcp_protected_request_handler(allow_missing).unwrap();
    let accepted = allow_missing
        .verify(&request_with_token("Bearer", "missing-audience"))
        .await
        .unwrap();
    let McpProtectedRequestOutcome::Authorized(claims) = accepted else {
        panic!("missing audience was rejected despite explicit opt-in");
    };
    assert!(claims.get("aud").is_none());
    assert!(claims.get("client_id").is_none());
    assert_eq!(claims["azp"], "remote-client");

    let mut typed = handler.options().clone();
    typed.jwt_verify_options.token_type = Some("JWT".into());
    let typed = create_mcp_protected_request_handler(typed).unwrap();
    assert_eq!(
        typed
            .verify(&request_with_token("Bearer", "active"))
            .await
            .unwrap_err()
            .to_string(),
        "introspection claims are invalid"
    );
}
