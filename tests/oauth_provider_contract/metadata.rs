use super::support::*;
use lucid_auth::{JwkAlgorithm, JwtConfig};

#[test]
fn descriptor_defaults_and_validation_match_the_upstream_plugin() {
    let provider = OAuthProviderPluginConfig::new("/login", "/consent");
    assert_eq!(provider.access_token_expires_in, 3_600);
    assert_eq!(provider.refresh_token_expires_in, 2_592_000);
    assert!(provider.client_registration_require_pkce);
    assert!(provider.validate().is_ok());

    let descriptor = OAuthProviderPlugin::in_memory(provider).descriptor();
    assert_eq!(descriptor.id, "oauth-provider");
    assert_eq!(descriptor.dependencies, &["jwt"]);
    assert_eq!(descriptor.version, "1.7.1");
    assert_eq!(
        descriptor.client.unwrap().package,
        "@better-auth/oauth-provider"
    );
    assert!(descriptor.endpoints.iter().any(|endpoint| {
        endpoint.path == "/oauth2/token" && endpoint.client_method == "oauth2Token"
    }));

    let mut invalid = OAuthProviderPluginConfig::new("/login", "/consent");
    invalid.grant_types = vec!["refresh_token".into()];
    assert_eq!(
        invalid.validate(),
        Err(OAuthProviderConfigError::RefreshRequiresAuthorizationCode)
    );

    let mut missing_dependency = AuthConfig::new([138_u8; 32]).unwrap();
    missing_dependency
        .add_plugin(OAuthProviderPlugin::in_memory(
            OAuthProviderPluginConfig::new("/login", "/consent"),
        ))
        .unwrap();
    assert!(matches!(
        AuthService::try_new(Arc::new(MemoryStore::default()), missing_dependency),
        Err(AuthError::InvalidConfiguration(message)) if message.contains("jwt")
    ));
}

#[tokio::test]
async fn discovery_supports_head_and_server_only_routes_stay_unmounted() {
    let fixture = fixture().await;
    for path in [
        "/api/auth/.well-known/oauth-authorization-server",
        "/api/auth/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server/api/auth",
    ] {
        let (status, headers, body) =
            request(&fixture.app, "HEAD", path, None, Body::empty(), None).await;
        assert_eq!(status, StatusCode::OK, "HEAD {path}");
        assert!(body.is_empty());
        assert!(
            headers[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("max-age=15")
        );

        let (status, _, _) = request(
            &fixture.app,
            "POST",
            path,
            Some("application/json"),
            Body::from("{}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "POST {path}");
    }

    for path in [
        "/api/auth/admin/oauth2/create-client",
        "/api/auth/admin/oauth2/resources",
        "/api/auth/admin/oauth2/resources/urn:contract",
    ] {
        let (status, _, _) = json_request(
            &fixture.app,
            "POST",
            path,
            Some(json!({})),
            Some(&fixture.cookie),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn discovery_reflects_disabled_jwt_grants_and_advertised_scopes() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.disable_jwt_plugin = true;
    provider.grant_types = vec!["client_credentials".into()];
    provider.advertised_metadata.scopes_supported = Some(vec!["profile".into()]);
    let fixture = fixture_with_provider(provider).await;
    let (status, _, metadata) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata["scopes_supported"], json!(["profile"]));
    assert_eq!(metadata["response_types_supported"], json!([]));
    assert_eq!(metadata["backchannel_logout_supported"], false);
    assert_eq!(metadata["backchannel_logout_session_supported"], false);
    assert!(metadata.get("jwks_uri").is_none());
    assert_eq!(
        metadata["id_token_signing_alg_values_supported"],
        json!(["HS256"])
    );
}

#[derive(Debug)]
struct DiscoveryMetadata;

#[async_trait]
impl OAuthProviderExtension for DiscoveryMetadata {
    fn client_discovery_ids(&self) -> Vec<String> {
        vec!["contract-discovery".into()]
    }

    fn client_discovery_metadata(&self) -> Map<String, Value> {
        Map::from_iter([
            ("client_id_metadata_document_supported".into(), json!(true)),
            ("issuer".into(), json!("https://must-not-override.example")),
        ])
    }
}

#[tokio::test]
async fn client_discovery_enables_public_auth_and_core_metadata_wins() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.extensions.push(Arc::new(DiscoveryMetadata));
    let fixture = fixture_with_provider(provider).await;
    let (_, _, metadata) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    assert_eq!(metadata["issuer"], "http://localhost/api/auth");
    assert!(
        metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("none"))
    );
}

#[tokio::test]
async fn jwt_options_drive_issuer_jwks_and_all_id_token_algorithms() {
    let mut jwt = JwtConfig::default();
    jwt.jwt.issuer = Some("https://issuer.example".into());
    jwt.jwks.remote_url = Some("https://keys.example/provider.json".into());
    jwt.jwks.key_pair_config = Some(JwkAlgorithm::Es256);
    jwt.jwks.key_pair_configs = vec![
        JwkAlgorithm::Rs256 {
            modulus_length: None,
        },
        JwkAlgorithm::Es256,
    ];
    let mut auth = AuthConfig::new([139_u8; 32]).unwrap();
    auth.set_base_url("http://localhost/api/auth").unwrap();
    auth.add_plugin(JwtPlugin::new(jwt)).unwrap();
    auth.add_plugin(OAuthProviderPlugin::in_memory(
        OAuthProviderPluginConfig::new("/login", "/consent"),
    ))
    .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), auth).unwrap());
    let app = lucid_auth::axum::router(service);
    let (_, _, metadata) = json_request(
        &app,
        "GET",
        "/api/auth/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://issuer.example");
    assert_eq!(
        metadata["authorization_endpoint"],
        "http://localhost/api/auth/oauth2/authorize"
    );
    assert_eq!(metadata["jwks_uri"], "https://keys.example/provider.json");
    assert_eq!(
        metadata["id_token_signing_alg_values_supported"],
        json!(["ES256", "RS256"])
    );
    assert_eq!(
        metadata["token_endpoint_auth_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
}

#[tokio::test]
async fn dynamic_registration_and_owner_client_management_are_available() {
    let fixture = fixture().await;
    let (status, headers, registered) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/register",
        Some(json!({
            "redirect_uris": ["https://client.example/callback"],
            "client_name": "Dynamic client",
            "token_endpoint_auth_method": "none"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(registered["client_id"].is_string());
    assert!(registered.get("require_pkce").is_none());
    assert!(registered.get("client_secret").is_none());

    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "redirect_uris": ["https://managed.example/callback"],
            "client_name": "Managed client"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let managed_id = created["client_id"].as_str().unwrap();
    assert!(created["client_secret"].is_string());

    let (status, _, listed) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/oauth2/get-clients",
        None,
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["client_id"], managed_id);

    let (status, _, updated) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/update-client",
        Some(json!({
            "client_id": managed_id,
            "update": { "client_name": "Renamed client" }
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["client_name"], "Renamed client");

    let (status, _, _) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/delete-client",
        Some(json!({ "client_id": managed_id })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        fixture
            .oauth
            .find_oauth_client(managed_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn client_key_material_registration_guards_and_wire_output_match_better_auth() {
    let fixture = fixture().await;
    let jwks = json!({"keys":[{
        "kty":"RSA", "kid":"contract-key", "alg":"RS256", "n":"AQAB", "e":"AQAB"
    }]});
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "grant_types":["client_credentials"],
            "token_endpoint_auth_method":"private_key_jwt",
            "jwks":jwks
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["jwks"], jwks);
    let client_id = created["client_id"].as_str().unwrap();
    let path = format!(
        "/api/auth/oauth2/get-client?client_id={}",
        url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
    );
    let (status, _, fetched) =
        json_request(&fixture.app, "GET", &path, None, Some(&fixture.cookie)).await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(fetched["jwks"], jwks);

    for (key_material, expected) in [
        (
            json!({"jwks":{"keys":[]}}),
            "jwks must be an RFC 7517 JWK Set object with a non-empty keys array",
        ),
        (
            json!({"jwks":{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"private"}]}}),
            "jwks must contain only public asymmetric keys",
        ),
        (
            json!({"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","alg":"ES384"}]}}),
            "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve",
        ),
        (
            json!({"jwks_uri":"http://keys.example/jwks.json"}),
            "jwks_uri must use HTTPS",
        ),
        (
            json!({"jwks_uri":"https://127.0.0.1/jwks.json"}),
            "jwks_uri must not point to a private or reserved address",
        ),
        (
            json!({"jwks_uri":"https://keys.example/jwks.json"}),
            "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin",
        ),
    ] {
        let mut body = json!({
            "grant_types":["client_credentials"],
            "token_endpoint_auth_method":"private_key_jwt"
        });
        body.as_object_mut()
            .unwrap()
            .extend(key_material.as_object().unwrap().clone());
        let (status, _, error) = json_request(
            &fixture.app,
            "POST",
            "/api/auth/oauth2/create-client",
            Some(body),
            Some(&fixture.cookie),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["error"], "invalid_client_metadata");
        assert_eq!(error["error_description"], expected);
    }
}
