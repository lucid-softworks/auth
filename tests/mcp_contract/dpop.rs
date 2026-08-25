use super::{support::*, verifier_support::*};

#[tokio::test]
async fn dpop_enforces_token_binding_and_rejects_replayed_proofs() {
    let (access_private, access_public) = rsa_key("mcp-access");
    let server = jwks_server(&access_public).await;
    let mut options = handler_options();
    options.issuer = server.origin.clone();
    options.audience = RESOURCE.into();
    options.jwks_url = Some(format!("{}/jwks", server.origin));
    let handler = create_mcp_protected_request_handler(options).unwrap();

    let (proof_private, proof_public, thumbprint) = dpop_key();
    let mut bound_claims = access_claims(&server.origin, RESOURCE);
    bound_claims["cnf"] = json!({"jkt": thumbprint});
    let bound = access_token(&access_private, "mcp-access", bound_claims);
    let bearer_rejection = handler
        .verify(&request_with_token("Bearer", &bound))
        .await
        .unwrap();
    assert_eq!(
        challenge_message(bearer_rejection),
        "DPoP-bound access token requires the DPoP authorization scheme"
    );

    let unbound = access_token(
        &access_private,
        "mcp-access",
        access_claims(&server.origin, RESOURCE),
    );
    let unbound_rejection = handler
        .verify(&request_with_token("DPoP", &unbound))
        .await
        .unwrap();
    assert_eq!(
        challenge_message(unbound_rejection),
        "DPoP authorization requires a DPoP-bound access token"
    );

    let proof = dpop_proof(&proof_private, &proof_public, &bound, RESOURCE, "one-proof");
    let mut request = request_with_token("DPoP", &bound);
    request.dpop_proof_jwt = Some(proof);
    assert!(matches!(
        handler.verify(&request).await.unwrap(),
        McpProtectedRequestOutcome::Authorized(_)
    ));
    let replay = handler.verify(&request).await.unwrap();
    assert_eq!(
        challenge_message(replay),
        "DPoP proof jti has already been used"
    );
}

#[tokio::test]
async fn convenience_verifiers_share_durable_replay_reservations() {
    let (access_private, access_public) = rsa_key("mcp-durable-access");
    let server = jwks_server(&access_public).await;
    let mut config = AuthConfig::new([204_u8; 32]).unwrap();
    config.set_base_url(&server.origin).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    let options = RequireMcpAuthOptions {
        resource: Some(RESOURCE.into()),
        issuer: Some(server.origin.clone()),
        jwks_url: Some(format!("{}/jwks", server.origin)),
        required_scopes: Some(vec!["mcp.read".into()]),
        ..Default::default()
    };
    let first = require_mcp_auth(service.clone(), options.clone()).unwrap();
    let second = require_mcp_auth(service, options).unwrap();

    let (proof_private, proof_public, thumbprint) = dpop_key();
    let mut claims = access_claims(&server.origin, RESOURCE);
    claims["cnf"] = json!({"jkt": thumbprint});
    let token = access_token(&access_private, "mcp-durable-access", claims);
    let proof = dpop_proof(
        &proof_private,
        &proof_public,
        &token,
        RESOURCE,
        "durable-proof",
    );
    let mut request = request_with_token("DPoP", &token);
    request.dpop_proof_jwt = Some(proof);

    assert!(matches!(
        first.verify(&request).await.unwrap(),
        McpProtectedRequestOutcome::Authorized(_)
    ));
    assert_eq!(
        challenge_message(second.verify(&request).await.unwrap()),
        "DPoP proof jti has already been used"
    );
}
