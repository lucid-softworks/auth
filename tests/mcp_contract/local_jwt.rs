use super::{support::*, verifier_support::*};

#[tokio::test]
async fn local_jwks_accepts_valid_tokens_and_rejects_invalid_signatures() {
    let (private, public) = rsa_key("mcp-local");
    let server = jwks_server(&public).await;
    let mut options = handler_options();
    options.issuer = server.origin.clone();
    options.audience = RESOURCE.into();
    options.jwks_url = Some(format!("{}/jwks", server.origin));
    let handler = create_mcp_protected_request_handler(options).unwrap();

    let mut valid_claims = access_claims(&server.origin, RESOURCE);
    valid_claims["azp"] = json!("local-client");
    let valid = access_token(&private, "mcp-local", valid_claims);
    let accepted = handler
        .verify(&request_with_token("Bearer", &valid))
        .await
        .unwrap();
    let McpProtectedRequestOutcome::Authorized(claims) = accepted else {
        panic!("valid local JWT was rejected");
    };
    assert_eq!(claims["sub"], "local-user");
    assert_eq!(claims["client_id"], "local-client");

    let (wrong_private, _) = rsa_key("mcp-local");
    let invalid = access_token(
        &wrong_private,
        "mcp-local",
        access_claims(&server.origin, RESOURCE),
    );
    let rejected = handler
        .verify(&request_with_token("Bearer", &invalid))
        .await
        .unwrap();
    assert_eq!(challenge_message(rejected), "invalid access token");
}
