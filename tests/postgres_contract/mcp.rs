use axum::{Json, Router, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jwk::{Jwk, P_256},
    jws::{self, ES256, JwsHeader, RS256},
};
use lucid_auth::{
    AuthConfig, AuthService, McpProtectedRequest, McpProtectedRequestOutcome,
    RequireMcpAuthOptions, postgres::PostgresStore, require_mcp_auth,
};
use serde_json::{Map, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const RESOURCE: &str = "http://localhost/mcp";

pub(super) async fn assert_durable_dpop_replay(
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (access_private, access_public) = rsa_key("postgres-mcp-access");
    let server = jwks_server(access_public).await?;
    let options = RequireMcpAuthOptions {
        resource: Some(RESOURCE.into()),
        issuer: Some(server.origin.clone()),
        jwks_url: Some(format!("{}/jwks", server.origin)),
        required_scopes: Some(vec!["mcp.read".into()]),
        ..Default::default()
    };
    let first = require_mcp_auth(service(store, &server.origin)?, options.clone())?;
    let second = require_mcp_auth(service(store, &server.origin)?, options)?;

    let (proof_private, proof_public, thumbprint) = dpop_key();
    let token = access_token(
        &access_private,
        "postgres-mcp-access",
        json!({
            "iss": server.origin,
            "aud": RESOURCE,
            "sub": "postgres-mcp-user",
            "scope": "mcp.read",
            "cnf": {"jkt": thumbprint},
            "iat": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 300,
        }),
    );
    let proof = dpop_proof(&proof_private, &proof_public, &token, "postgres-proof");
    let request = McpProtectedRequest {
        authorization_header: Some(format!("DPoP {token}")),
        dpop_proof_jwt: Some(proof),
        method: "POST".into(),
        url: RESOURCE.into(),
    };
    assert!(matches!(
        first.verify(&request).await?,
        McpProtectedRequestOutcome::Authorized(_)
    ));
    let McpProtectedRequestOutcome::Challenge(replay) = second.verify(&request).await? else {
        panic!("a PostgreSQL-backed DPoP proof replay was authorized");
    };
    assert!(replay.json_rpc_body().contains("jti has already been used"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_verifications \
             WHERE purpose = '' AND identifier LIKE 'dpop-proof:%'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

fn service(
    store: &Arc<PostgresStore>,
    origin: &str,
) -> Result<Arc<AuthService>, lucid_auth::AuthError> {
    let mut config = AuthConfig::new([205_u8; 32])?;
    config.set_base_url(origin)?;
    Ok(Arc::new(AuthService::try_new(store.clone(), config)?))
}

struct JwksServer {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn jwks_server(public_key: Jwk) -> Result<JwksServer, std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let public_key = public_key.clone();
            async move { Json(json!({"keys": [public_key]})) }
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Ok(JwksServer { origin, task })
}

fn rsa_key(kid: &str) -> (Jwk, Jwk) {
    let mut private = Jwk::generate_rsa_key(2_048).unwrap();
    private.set_key_id(kid);
    private.set_algorithm("RS256");
    let mut public = private.to_public_key().unwrap();
    public.set_key_id(kid);
    public.set_algorithm("RS256");
    (private, public)
}

fn access_token(private: &Jwk, kid: &str, claims: serde_json::Value) -> String {
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id(kid);
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &RS256.signer_from_jwk(private).unwrap(),
    )
    .unwrap()
}

fn dpop_key() -> (Jwk, Jwk, String) {
    let private = Jwk::generate_ec_key(P_256).unwrap();
    let public = private.to_public_key().unwrap();
    let key = serde_json::to_value(&public).unwrap();
    let key = key.as_object().unwrap();
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        key["crv"].as_str().unwrap(),
        key["x"].as_str().unwrap(),
        key["y"].as_str().unwrap(),
    );
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    (private, public, thumbprint)
}

fn dpop_proof(private: &Jwk, public: &Jwk, token: &str, jti: &str) -> String {
    let mut header = JwsHeader::new();
    header.set_algorithm("ES256");
    header.set_token_type("dpop+jwt");
    header.set_jwk(public.clone());
    let claims = Map::from_iter([
        ("htm".into(), json!("POST")),
        ("htu".into(), json!(RESOURCE)),
        ("jti".into(), json!(jti)),
        ("iat".into(), json!(chrono::Utc::now().timestamp())),
        (
            "ath".into(),
            json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
        ),
    ]);
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &ES256.signer_from_jwk(private).unwrap(),
    )
    .unwrap()
}
