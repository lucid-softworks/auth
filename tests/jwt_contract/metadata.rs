use super::support::{ORIGIN, fixture, get, json_body, signup};
use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, JwkAlgorithm, JwtConfig, JwtPlugin, JwtProtectedHeader,
    JwtRemoteSigner, JwtSchema, JwtSigningOverrides, MemoryStore,
};
use serde_json::{Map, Value};
use std::sync::Arc;

fn service_result(jwt: JwtConfig) -> Result<AuthService, AuthError> {
    let mut config = AuthConfig::new([162_u8; 32]).unwrap();
    config.set_base_url(ORIGIN).unwrap();
    config.add_plugin(JwtPlugin::new(jwt)).unwrap();
    AuthService::try_new(Arc::new(MemoryStore::default()), config)
}

#[derive(Debug)]
struct StaticSigner;

#[async_trait]
impl JwtRemoteSigner for StaticSigner {
    async fn sign(
        &self,
        _payload: Map<String, Value>,
        _header: Option<JwtProtectedHeader>,
        _signing: Option<JwtSigningOverrides>,
    ) -> Result<String, AuthError> {
        Ok("remote.compact.token".into())
    }
}

#[tokio::test]
async fn descriptor_routes_and_client_metadata_are_optional_and_exact() {
    let baseline = service_result(JwtConfig::default()).unwrap();
    let descriptor = baseline
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "jwt")
        .unwrap();
    assert!(descriptor.cookies.is_empty() && descriptor.rate_limits.is_empty());
    assert!(descriptor.dependencies.is_empty());
    assert_eq!(descriptor.client.unwrap().factory, "jwtClient");
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.path.as_ref(), endpoint.client_method))
            .collect::<Vec<_>>(),
        vec![("/jwks", "jwks"), ("/token", "token")]
    );
    assert!(baseline.plugin_migrations().is_empty());
    assert!(baseline.generic_database_schema().table("jwks").is_some());

    let core = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([163_u8; 32]).unwrap(),
    );
    assert!(
        core.plugin_metadata()
            .iter()
            .all(|plugin| plugin.id != "jwt")
    );
    assert!(core.jwt().is_none());

    let fixture = fixture(JwtConfig::default());
    assert_eq!(
        get(&fixture.app, "/api/auth/jwks", None).await.status(),
        200
    );
    for path in ["/api/auth/sign-jwt", "/api/auth/verify-jwt"] {
        assert_eq!(get(&fixture.app, path, None).await.status(), 404);
    }
}

#[tokio::test]
async fn validation_rejects_only_the_pinned_invalid_combinations() {
    for path in ["", "jwks", "/nested/../jwks"] {
        let mut config = JwtConfig::default();
        config.jwks.jwks_path = path.into();
        assert!(matches!(
            service_result(config),
            Err(AuthError::InvalidConfiguration(message))
                if message.contains("jwksPath")
        ));
    }

    let mut signer_without_remote = JwtConfig::default();
    signer_without_remote.jwt.sign = Some(Arc::new(StaticSigner));
    assert!(matches!(
        service_result(signer_without_remote),
        Err(AuthError::InvalidConfiguration(message)) if message.contains("remoteUrl")
    ));

    let mut remote_without_algorithm = JwtConfig::default();
    remote_without_algorithm.jwks.remote_url = Some("not-even-a-url".into());
    assert!(matches!(
        service_result(remote_without_algorithm),
        Err(AuthError::InvalidConfiguration(message)) if message.contains("keyPairConfig.alg")
    ));
}

#[test]
fn schema_remapping_is_complete_empty_safe_and_instance_local() {
    let custom = JwtPlugin::new(JwtConfig {
        schema: JwtSchema {
            model_name: Some("custom_keys".into()),
            public_key_field_name: Some("public_material".into()),
            private_key_field_name: Some("private_material".into()),
            created_at_field_name: Some("created_on".into()),
            expires_at_field_name: Some("expires_on".into()),
            alg_field_name: Some("algorithm".into()),
            crv_field_name: Some("curve".into()),
        },
        ..JwtConfig::default()
    });
    let mut auth = AuthConfig::new([165_u8; 32]).unwrap();
    auth.add_plugin(custom).unwrap();
    let custom_service = AuthService::new(Arc::new(MemoryStore::default()), auth);
    assert!(custom_service.plugin_migrations().is_empty());
    let custom_schema = custom_service.generic_database_schema();
    let custom_table = custom_schema.table("custom_keys").unwrap();
    for identifier in [
        "public_material",
        "private_material",
        "created_on",
        "expires_on",
        "algorithm",
        "curve",
    ] {
        assert!(custom_table.fields.contains_key(identifier));
    }

    let default = service_result(JwtConfig {
        schema: JwtSchema {
            model_name: Some(String::new()),
            public_key_field_name: Some(String::new()),
            ..JwtSchema::default()
        },
        ..JwtConfig::default()
    })
    .unwrap();
    assert!(default.plugin_migrations().is_empty());
    let default_schema = default.generic_database_schema();
    let default_table = default_schema.table("jwks").unwrap();
    assert!(default_table.fields.contains_key("publicKey"));
    assert!(default_schema.table("custom_keys").is_none());
}

#[tokio::test]
async fn custom_path_replaces_default_and_is_reflected_in_client_metadata() {
    let mut custom = JwtConfig::default();
    custom.jwks.jwks_path = "/.well-known/custom-jwks.json".into();
    let custom_fixture = fixture(custom);
    assert_eq!(
        get(&custom_fixture.app, "/api/auth/jwks", None)
            .await
            .status(),
        404
    );
    let response = get(
        &custom_fixture.app,
        "/api/auth/.well-known/custom-jwks.json",
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        json_body(response).await["keys"].as_array().unwrap().len(),
        1
    );
    let descriptor = custom_fixture
        .service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "jwt")
        .unwrap();
    assert_eq!(
        descriptor.endpoints[0].path,
        "/.well-known/custom-jwks.json"
    );
}

#[tokio::test]
async fn remote_mode_disables_only_jwks_and_passes_through_custom_tokens() {
    let mut remote = JwtConfig::default();
    remote.jwks.remote_url = Some("opaque remote metadata value".into());
    remote.jwks.key_pair_config = Some(JwkAlgorithm::EdDsa);
    remote.jwt.sign = Some(Arc::new(StaticSigner));
    let remote_fixture = fixture(remote);
    assert_eq!(
        get(&remote_fixture.app, "/api/auth/jwks", None)
            .await
            .status(),
        404
    );
    let credential = signup(&remote_fixture, "remote").await;
    let response = get(
        &remote_fixture.app,
        "/api/auth/token",
        Some(&credential.cookie),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(json_body(response).await["token"], "remote.compact.token");
}
