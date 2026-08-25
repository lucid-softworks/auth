use super::*;

const OPAQUE_CONFIRMED_TOKEN: &str = "opaque-confirmed-access-token";

#[derive(Default)]
struct ContractExtension {
    client_id: std::sync::Mutex<Option<String>>,
}

#[async_trait]
impl OAuthProviderExtension for ContractExtension {
    fn grant_types(&self) -> Vec<String> {
        vec!["urn:contract:grant".into()]
    }

    fn client_authentication_methods(&self) -> Vec<OAuthExtensionClientAuthenticationMethod> {
        vec![OAuthExtensionClientAuthenticationMethod {
            method: "contract_assertion".into(),
            assertion_types: vec!["urn:contract:assertion".into()],
        }]
    }

    fn client_discovery_ids(&self) -> Vec<String> {
        vec!["contract".into()]
    }

    async fn discover_client(
        &self,
        client_id: &str,
        stored_client: Option<&OAuthProviderClient>,
        _context: &OAuthCallbackContext,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        Ok(stored_client
            .filter(|client| client.client_id == client_id)
            .cloned())
    }

    async fn authenticate_client(
        &self,
        input: &OAuthExtensionClientAuthenticationInput,
    ) -> Result<Option<OAuthExtensionClientAuthentication>, AuthError> {
        if input.method != "contract_assertion"
            || input
                .parameters
                .get("client_assertion")
                .and_then(|values| values.first())
                .map(String::as_str)
                != Some("proof")
        {
            return Ok(None);
        }
        Ok(self.client_id.lock().unwrap().clone().map(|client_id| {
            OAuthExtensionClientAuthentication {
                client_id,
                confirmation: Some(json!({"x5t#S256":"contract"})),
            }
        }))
    }

    async fn token_grant(
        &self,
        input: &OAuthExtensionGrantInput,
    ) -> Result<Value, lucid_auth::OAuthProviderError> {
        if input
            .parameters
            .get("force_error")
            .and_then(|values| values.first())
            .is_some_and(|value| value == "true")
        {
            return Err(lucid_auth::OAuthProviderError::InvalidTarget(
                "extension rejected the target".into(),
            ));
        }
        let public = input
            .parameters
            .get("public")
            .and_then(|values| values.first())
            .is_some_and(|value| value == "true");
        let authenticated = input
            .provider
            .authenticate_client(OAuthProviderApiAuthenticationRequest {
                scopes: vec!["api.read".into()],
                require_credentials: !public,
            })
            .await?;
        let mut issue =
            OAuthProviderApiTokenIssueInput::new(authenticated.client, vec!["api.read".into()]);
        issue.confirmation = authenticated.confirmation;
        input.provider.issue_tokens(issue).await
    }

    async fn claims(
        &self,
        target: OAuthClaimTarget,
        _context: &OAuthCallbackContext,
        protocol: &Value,
    ) -> Result<Map<String, Value>, AuthError> {
        Ok(Map::from_iter([
            ("extension_target".into(), json!(format!("{target:?}"))),
            ("first_registered".into(), json!(true)),
            (
                "extension_grant_type".into(),
                protocol.get("grantType").cloned().unwrap_or(Value::Null),
            ),
        ]))
    }

    fn server_metadata(
        &self,
        _document: OAuthProviderMetadataDocument,
        _base: &Map<String, Value>,
    ) -> Map<String, Value> {
        Map::from_iter([("contract_extension".into(), json!(true))])
    }

    fn client_metadata(
        &self,
        _client: &OAuthProviderClient,
        _base: &Map<String, Value>,
    ) -> Map<String, Value> {
        Map::from_iter([("contract_client_extension".into(), json!(true))])
    }
}

struct LaterClaims;

#[async_trait]
impl OAuthProviderExtension for LaterClaims {
    async fn claims(
        &self,
        _target: OAuthClaimTarget,
        _context: &OAuthCallbackContext,
        _protocol: &Value,
    ) -> Result<Map<String, Value>, AuthError> {
        Ok(Map::from_iter([("first_registered".into(), json!(false))]))
    }
}

struct OpaqueClaims;

#[async_trait]
impl OAuthProviderExtension for OpaqueClaims {
    async fn claims(
        &self,
        target: OAuthClaimTarget,
        _context: &OAuthCallbackContext,
        _protocol: &Value,
    ) -> Result<Map<String, Value>, AuthError> {
        if target != OAuthClaimTarget::AccessToken {
            return Ok(Map::new());
        }
        Ok(Map::from_iter([
            ("tenant".into(), json!("extension")),
            ("extension_only".into(), json!(true)),
            ("scope".into(), json!("forged")),
            ("cnf".into(), json!({"jkt":"forged"})),
        ]))
    }
}

#[tokio::test]
async fn extensions_contribute_discovery_client_metadata_claims_and_shared_token_issuance() {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.allow_unauthenticated_client_registration = true;
    provider.scopes.push("api.read".into());
    let extension = Arc::new(ContractExtension::default());
    provider.extensions.push(extension.clone());
    provider.extensions.push(Arc::new(LaterClaims));
    let fixture = fixture_with_provider(provider).await;
    assert_contract_extension_metadata(&fixture).await;
    let client_id = create_contract_extension_client(&fixture).await;
    mark_contract_client_discovered(&fixture, &client_id).await;
    *extension.client_id.lock().unwrap() = Some(client_id);
    assert_contract_extension_token_flow(&fixture).await;
    assert_public_extension_grant_and_error_propagation(&fixture).await;
}

#[tokio::test]
async fn opaque_introspection_rederives_resource_claims_and_preserves_dpop_confirmation() {
    let (fixture, client_id, client_secret) = opaque_fixture().await;
    let resource_id = "https://opaque-resource.example";
    store_opaque_resource_and_token(&fixture, &client_id, resource_id).await;
    let active = introspect_opaque(&fixture, &client_id, &client_secret).await;
    assert_eq!(active["active"], true);
    assert_eq!(active["token_type"], "DPoP");
    assert_eq!(active["cnf"]["jkt"], "bound-key");
    assert_eq!(active["scope"], "api.read");
    assert_eq!(active["tenant"], "resource");
    assert_eq!(active["extension_only"], true);
    assert_eq!(active["resource_only"], true);

    fixture
        .oauth
        .delete_oauth_resource(resource_id)
        .await
        .unwrap();
    let inactive = introspect_opaque(&fixture, &client_id, &client_secret).await;
    assert_eq!(inactive["active"], false);
}

async fn opaque_fixture() -> (Fixture, String, String) {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.disable_jwt_plugin = true;
    provider.allow_dynamic_client_registration = true;
    provider.scopes.push("api.read".into());
    provider.extensions.push(Arc::new(OpaqueClaims));
    let fixture = fixture_with_provider(provider).await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    (fixture, client_id, client_secret)
}

async fn store_opaque_resource_and_token(fixture: &Fixture, client_id: &str, resource_id: &str) {
    fixture
        .oauth
        .create_oauth_resource(OAuthProviderResource {
            id: Uuid::new_v4(),
            identifier: resource_id.into(),
            name: "Opaque resource".into(),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: Some(json!({"tenant":"resource","resource_only":true})),
            dpop_bound_access_tokens_required: false,
            disabled: true,
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
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(OAuthProviderAccessToken {
                id: Uuid::new_v4(),
                token: URL_SAFE_NO_PAD.encode(Sha256::digest(OPAQUE_CONFIRMED_TOKEN.as_bytes())),
                client_id: client_id.into(),
                session_id: None,
                user_id: None,
                reference_id: None,
                authorization_code_id: None,
                resources: Some(vec![resource_id.into()]),
                requested_user_info_claims: None,
                refresh_id: None,
                expires_at: Utc::now() + Duration::minutes(5),
                created_at: Utc::now(),
                revoked: None,
                confirmation: Some(json!({"jkt":"bound-key"})),
                scopes: vec!["api.read".into()],
            }),
            refresh_token: None,
        })
        .await
        .unwrap();
}

async fn introspect_opaque(fixture: &Fixture, client_id: &str, client_secret: &str) -> Value {
    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("token", OPAQUE_CONFIRMED_TOKEN),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    active
}

async fn assert_contract_extension_metadata(fixture: &Fixture) {
    let (status, _, metadata) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert_eq!(metadata["contract_extension"], true);
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("urn:contract:grant"))
    );
}

async fn create_contract_extension_client(fixture: &Fixture) -> String {
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "scope":"api.read", "grant_types":["urn:contract:grant"],
            "token_endpoint_auth_method":"contract_assertion"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["contract_client_extension"], true);
    created["client_id"].as_str().unwrap().into()
}

async fn mark_contract_client_discovered(fixture: &Fixture, client_id: &str) {
    let mut stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    stored.client_discovery_id = Some("contract".into());
    fixture.oauth.update_oauth_client(stored).await.unwrap();
}

async fn assert_contract_extension_token_flow(fixture: &Fixture) {
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "urn:contract:grant"),
            ("client_assertion_type", "urn:contract:assertion"),
            ("client_assertion", "proof"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["extension_target"], "TokenResponse");
    assert_eq!(tokens["extension_grant_type"], "urn:contract:grant");
    assert_eq!(tokens["first_registered"], true);
    let access = tokens["access_token"].as_str().unwrap();
    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            ("client_assertion_type", "urn:contract:assertion"),
            ("client_assertion", "proof"),
            ("token", access),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["extension_target"], "AccessToken");
    assert_eq!(active["cnf"]["x5t#S256"], "contract");

    let (status, _, error) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "urn:contract:grant"),
            ("client_assertion", "proof"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "invalid_client");
}

async fn assert_public_extension_grant_and_error_propagation(fixture: &Fixture) {
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "scope":"api.read",
            "grant_types":["urn:contract:grant"],
            "token_endpoint_auth_method":"none"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let public_client = created["client_id"].as_str().unwrap();
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "urn:contract:grant"),
            ("client_id", public_client),
            ("public", "true"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(tokens["access_token"].is_string());

    let (status, _, error) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "urn:contract:grant"),
            ("force_error", "true"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "invalid_target");
    assert_eq!(error["error_description"], "extension rejected the target");
}
