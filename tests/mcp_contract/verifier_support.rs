use super::support::*;
use axum::{
    extract::State,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jwk::{Jwk, P_256},
    jws::{self, ES256, JwsHeader, RS256},
};
use serde_json::Map;
use sha2::{Digest as _, Sha256};

pub(super) struct TestServer {
    pub(super) origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct IntrospectionState {
    issuer: String,
    audience: String,
}

pub(super) async fn jwks_server(public_key: &Jwk) -> TestServer {
    let jwks = json!({"keys": [public_key]});
    spawn_server(move |_| Router::new().route("/jwks", get(|| async move { axum::Json(jwks) })))
        .await
}

pub(super) async fn introspection_server() -> TestServer {
    spawn_server(|origin| {
        let state = IntrospectionState {
            issuer: origin.clone(),
            audience: format!("{origin}/mcp"),
        };
        Router::new()
            .route("/introspect", post(introspect))
            .with_state(state)
    })
    .await
}

async fn spawn_server(make_app: impl FnOnce(String) -> Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = make_app(origin.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    TestServer { origin, task }
}

async fn introspect(State(state): State<IntrospectionState>, body: String) -> axum::Json<Value> {
    let token = url::form_urlencoded::parse(body.as_bytes())
        .find_map(|(name, value)| (name == "token").then(|| value.into_owned()))
        .unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let value = match token.as_str() {
        "active" => json!({
            "active": true,
            "iss": state.issuer,
            "aud": state.audience,
            "sub": "remote-user",
            "scope": "mcp.read",
            "exp": now + 300,
        }),
        "wrong-audience" => json!({
            "active": true,
            "iss": state.issuer,
            "aud": "https://other.example/mcp",
            "sub": "remote-user",
            "scope": "mcp.read",
            "exp": now + 300,
        }),
        "missing-audience" => json!({
            "active": true,
            "iss": state.issuer,
            "sub": "remote-user",
            "azp": "remote-client",
            "scope": "mcp.read",
            "exp": now + 300,
        }),
        _ => json!({"active": false}),
    };
    axum::Json(value)
}

pub(super) fn rsa_key(kid: &str) -> (Jwk, Jwk) {
    let mut private = Jwk::generate_rsa_key(2_048).unwrap();
    private.set_key_id(kid);
    private.set_algorithm("RS256");
    let mut public = private.to_public_key().unwrap();
    public.set_key_id(kid);
    public.set_algorithm("RS256");
    (private, public)
}

pub(super) fn access_token(private: &Jwk, kid: &str, claims: Value) -> String {
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

pub(super) fn access_claims(issuer: &str, audience: &str) -> Value {
    json!({
        "iss": issuer,
        "aud": audience,
        "sub": "local-user",
        "scope": "mcp.read",
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 300,
    })
}

pub(super) fn dpop_key() -> (Jwk, Jwk, String) {
    let private = Jwk::generate_ec_key(P_256).unwrap();
    let public = private.to_public_key().unwrap();
    let value = serde_json::to_value(&public).unwrap();
    let key = value.as_object().unwrap();
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        key["crv"].as_str().unwrap(),
        key["x"].as_str().unwrap(),
        key["y"].as_str().unwrap(),
    );
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    (private, public, thumbprint)
}

pub(super) fn dpop_proof(
    private: &Jwk,
    public: &Jwk,
    access_token: &str,
    resource: &str,
    jti: &str,
) -> String {
    let mut header = JwsHeader::new();
    header.set_algorithm("ES256");
    header.set_token_type("dpop+jwt");
    header.set_jwk(public.clone());
    let claims = Map::from_iter([
        ("htm".into(), json!("POST")),
        ("htu".into(), json!(resource)),
        ("jti".into(), json!(jti)),
        ("iat".into(), json!(chrono::Utc::now().timestamp())),
        (
            "ath".into(),
            json!(URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))),
        ),
    ]);
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &ES256.signer_from_jwk(private).unwrap(),
    )
    .unwrap()
}

pub(super) fn request_with_token(scheme: &str, token: &str) -> McpProtectedRequest {
    McpProtectedRequest {
        authorization_header: Some(format!("{scheme} {token}")),
        dpop_proof_jwt: None,
        method: "POST".into(),
        url: RESOURCE.into(),
    }
}

pub(super) fn challenge_message(outcome: McpProtectedRequestOutcome) -> String {
    let McpProtectedRequestOutcome::Challenge(challenge) = outcome else {
        panic!("request was unexpectedly authorized");
    };
    serde_json::from_str::<Value>(&challenge.json_rpc_body()).unwrap()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned()
}
