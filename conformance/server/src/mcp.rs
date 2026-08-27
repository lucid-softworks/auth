use super::Fixture;
use axum::{
    Extension, Json,
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lucid_auth::{
    DatabaseIdGenerationSize, DatabaseIdValue, McpProtectedRequest, McpProtectedRequestOutcome,
    OAuthClientRegistrationMode, OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite,
    OAuthProviderClient, OAuthProviderStore, PreparedDatabaseId, RequireMcpAuthOptions,
    generate_database_id, require_mcp_auth,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

pub(super) async fn seed_client(store: &dyn OAuthProviderStore, resource: &str) {
    store
        .find_oauth_resource(resource)
        .await
        .expect("seed MCP resource")
        .expect("configured MCP resource");
    let now = chrono::Utc::now();
    let secret = URL_SAFE_NO_PAD.encode(Sha256::digest(b"mcp-conformance-secret"));
    let client = OAuthProviderClient {
        id: String::new(),
        client_id: "mcp-conformance-client".into(),
        client_secret: Some(secret),
        client_discovery_id: None,
        disabled: false,
        skip_consent: None,
        enable_end_session: None,
        subject_type: None,
        scopes: Some(vec!["mcp.read".into()]),
        client_credentials_scopes: vec!["mcp.read".into()],
        user_id: None,
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: None,
        name: Some("Official MCP conformance client".into()),
        uri: None,
        icon: None,
        contacts: None,
        tos: None,
        policy: None,
        software_id: None,
        software_version: None,
        software_statement: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        application_type: Some("web".into()),
        jwks: None,
        jwks_uri: None,
        grant_types: Some(vec!["client_credentials".into()]),
        response_types: Some(Vec::new()),
        require_pkce: Some(false),
        dpop_bound_access_tokens: false,
        reference_id: None,
        metadata: None,
    };
    assert!(matches!(
        store
            .persist_oauth_client_registration(
                &default_database_id,
                &default_database_id,
                OAuthClientRegistrationWrite {
                    client,
                    resource_ids: vec![resource.into()],
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
            .await
            .expect("seed MCP client"),
        OAuthClientRegistrationOutcome::Created(_)
    ));
}

fn default_database_id() -> Result<PreparedDatabaseId, lucid_auth::AuthError> {
    let id = generate_database_id(DatabaseIdGenerationSize::Omitted)
        .map_err(|error| lucid_auth::AuthError::Storage(error.to_string()))?;
    Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(id)))
}

pub(super) async fn handle(
    Extension(fixture): Extension<Fixture>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(resource) = fixture.mcp_resource.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let verifier = require_mcp_auth(
        fixture.service.clone(),
        RequireMcpAuthOptions {
            resource: Some(resource.clone()),
            required_scopes: Some(vec!["mcp.read".into()]),
            ..Default::default()
        },
    )
    .expect("valid native MCP verifier");
    let outcome = verifier
        .verify(&McpProtectedRequest {
            authorization_header: header_value(&headers, header::AUTHORIZATION.as_str()),
            dpop_proof_jwt: header_value(&headers, "dpop"),
            method: "POST".into(),
            url: resource,
        })
        .await;
    match outcome {
        Ok(McpProtectedRequestOutcome::Authorized(_)) => protocol_response(&body),
        Ok(McpProtectedRequestOutcome::Challenge(challenge)) => challenge_response(challenge),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn challenge_response(challenge: lucid_auth::McpAuthorizationChallenge) -> Response {
    let mut response = (
        StatusCode::from_u16(challenge.status_code).expect("MCP challenge status"),
        challenge.json_rpc_body(),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        challenge.content_type().parse().expect("MCP content type"),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        challenge
            .www_authenticate
            .parse()
            .expect("MCP authentication challenge"),
    );
    response
}

fn protocol_response(body: &[u8]) -> Response {
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if message["method"] == "notifications/initialized" {
        return StatusCode::ACCEPTED.into_response();
    }
    if message["method"] != "initialize" {
        return (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": "Method not found"},
            })),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "lucid-auth-conformance", "version": "1.0.0"},
            },
        })),
    )
        .into_response()
}
