use super::support::*;
use josekit::{
    jwk::Jwk,
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};

#[path = "tokens/authentication.rs"]
mod authentication;
#[path = "tokens/expiration.rs"]
mod expiration;
#[path = "tokens/extensions.rs"]
mod extensions;
#[path = "tokens/refresh_reuse.rs"]
mod refresh_reuse;

#[tokio::test]
async fn m2m_introspection_revocation_and_userinfo_error_match_oauth_semantics() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    assert_m2m_token_lifecycle(&fixture, &client_id, &client_secret).await;
}

#[tokio::test]
async fn token_family_endpoints_reject_json_with_the_better_call_415_shape() {
    let fixture = fixture().await;
    for path in [
        "/api/auth/oauth2/token",
        "/api/auth/oauth2/introspect",
        "/api/auth/oauth2/revoke",
        "/api/auth/oauth2/userinfo",
    ] {
        let (status, _, bytes) = request(
            &fixture.app,
            "POST",
            path,
            Some("application/json"),
            Body::from("{}"),
            None,
        )
        .await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{path}: {body}");
        assert_eq!(body["code"], "UNSUPPORTED_MEDIA_TYPE");
        assert_eq!(
            body["message"],
            "Content-Type \"application/json\" is not allowed. Allowed types: application/x-www-form-urlencoded"
        );
    }

    let (status, _, body) = request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/token",
        Some("Application/X-Www-Form-Urlencoded"),
        Body::from("grant_type=client_credentials"),
        None,
    )
    .await;
    assert_ne!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{:?}", body);
}

#[tokio::test]
async fn private_key_jwt_registration_output_and_derived_client_id_work_end_to_end() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.scopes.push("api.read".into());
    let mut jwt = JwtConfig::default();
    jwt.jwt.issuer = Some("https://semantic-issuer.example".into());
    let fixture = fixture_with_jwt_and_provider(jwt, provider).await;
    let mut private_key = Jwk::generate_rsa_key(2048).unwrap();
    private_key.set_key_id("contract-signing-key");
    private_key.set_algorithm("RS256");
    let mut public_key = private_key.to_public_key().unwrap();
    public_key.set_key_id("contract-signing-key");
    public_key.set_algorithm("RS256");
    let jwks = json!({"keys":[public_key]});
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "scope":"api.read",
            "grant_types":["client_credentials"],
            "token_endpoint_auth_method":"private_key_jwt",
            "jwks":jwks
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["jwks"], jwks);
    assert!(created.get("client_secret").is_none());
    let client_id = created["client_id"].as_str().unwrap().to_owned();
    let mut stored = fixture
        .oauth
        .find_oauth_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    stored.client_credentials_scopes = vec!["api.read".into()];
    fixture.oauth.update_oauth_client(stored).await.unwrap();

    let now = Utc::now().timestamp();
    let mut payload = JwtPayload::new();
    payload.set_issuer(&client_id);
    payload.set_subject(&client_id);
    payload.set_audience(vec!["https://semantic-issuer.example"]);
    payload.set_claim("iat", Some(json!(now))).unwrap();
    payload.set_claim("exp", Some(json!(now + 300))).unwrap();
    payload.set_jwt_id(Uuid::new_v4().to_string());
    let mut header = JwsHeader::new();
    header.set_key_id("contract-signing-key");
    let signer = RS256.signer_from_jwk(&private_key).unwrap();
    let assertion = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", &assertion),
            ("scope", "api.read"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens["access_token"].is_string());
}

#[tokio::test]
async fn resource_policy_issues_audience_jwt_with_ttl_scopes_and_custom_claims() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    let identifier = "https://resource.example";
    fixture
        .oauth
        .create_oauth_resource(OAuthProviderResource {
            id: Uuid::new_v4(),
            identifier: identifier.into(),
            name: "Contract resource".into(),
            access_token_ttl: Some(120),
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: Some(vec!["api.read".into()]),
            custom_claims: Some(json!({"tenant":"contract"})),
            dpop_bound_access_tokens_required: false,
            disabled: false,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            policy_version: 1,
            metadata: None,
        })
        .await
        .unwrap()
        .unwrap();
    fixture
        .oauth
        .link_oauth_client_resource(OAuthProviderClientResource {
            id: Uuid::new_v4(),
            client_id: client_id.clone(),
            resource_id: identifier.into(),
            metadata: None,
            created_at: Some(Utc::now()),
        })
        .await
        .unwrap();
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "api.read"),
            ("resource", identifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens["access_token"].as_str().unwrap().split('.').count() == 3);
    assert_eq!(tokens["expires_in"], 120);
    let access = tokens["access_token"].as_str().unwrap();
    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("token", access),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);
    assert_eq!(active["aud"], identifier);
    assert_eq!(active["tenant"], "contract");
}

#[tokio::test]
async fn custom_jwt_issuer_matches_discovery_and_issued_resource_tokens() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.scopes.push("api.read".into());
    let mut jwt = JwtConfig::default();
    jwt.jwt.issuer = Some("https://issuer.example/oauth".into());
    let fixture = fixture_with_jwt_and_provider(jwt, provider).await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    let resource = "https://resource.example/custom-issuer";
    fixture
        .oauth
        .create_oauth_resource(OAuthProviderResource {
            id: Uuid::new_v4(),
            identifier: resource.into(),
            name: "Custom issuer resource".into(),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: Some(vec!["api.read".into()]),
            custom_claims: None,
            dpop_bound_access_tokens_required: false,
            disabled: false,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            policy_version: 1,
            metadata: None,
        })
        .await
        .unwrap()
        .unwrap();
    fixture
        .oauth
        .link_oauth_client_resource(OAuthProviderClientResource {
            id: Uuid::new_v4(),
            client_id: client_id.clone(),
            resource_id: resource.into(),
            metadata: None,
            created_at: Some(Utc::now()),
        })
        .await
        .unwrap();
    let (_, _, metadata) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://issuer.example/oauth");
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "api.read"),
            ("resource", resource),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("token", tokens["access_token"].as_str().unwrap()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);
    assert_eq!(active["iss"], "https://issuer.example/oauth");
}

pub(super) async fn create_m2m_client(fixture: &Fixture) -> (String, String) {
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "scope": "api.read",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let client_id = created["client_id"].as_str().unwrap().to_owned();
    let client_secret = created["client_secret"].as_str().unwrap().to_owned();
    let mut stored = fixture
        .oauth
        .find_oauth_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    stored.client_credentials_scopes = vec!["api.read".into()];
    fixture.oauth.update_oauth_client(stored).await.unwrap();
    (client_id, client_secret)
}

async fn assert_m2m_token_lifecycle(fixture: &Fixture, client_id: &str, client_secret: &str) {
    let client_auth = [("client_id", client_id), ("client_secret", client_secret)];
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            client_auth[0],
            client_auth[1],
            ("scope", "api.read"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap().to_owned();

    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            client_auth[0],
            client_auth[1],
            ("token", &access),
            ("token_type_hint", "access_token"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);
    assert_eq!(active["client_id"], client_id);

    let (status, _, userinfo) = form_request(
        &fixture.app,
        "/api/auth/oauth2/userinfo",
        &[("access_token", &access)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{userinfo}");
    assert_eq!(userinfo["error"], "invalid_scope");

    let (status, _, body) = form_request(
        &fixture.app,
        "/api/auth/oauth2/revoke",
        &[
            client_auth[0],
            client_auth[1],
            ("token", &access),
            ("token_type_hint", "access_token"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, inactive) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[client_auth[0], client_auth[1], ("token", &access)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{inactive}");
    assert_eq!(inactive, json!({ "active": false }));
}
