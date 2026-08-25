use super::support::*;
use lucid_auth::{
    DEVICE_CODE_GRANT_TYPE, DeviceAuthorizationConfig, OAuthDeviceAuthorizationPlugin,
};

#[tokio::test]
async fn oauth_device_authorization_composes_with_the_mcp_provider() {
    let mut config = AuthConfig::new([205_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config.add_plugin(plugin()).unwrap();
    config
        .add_plugin(OAuthDeviceAuthorizationPlugin::in_memory(
            DeviceAuthorizationConfig::default(),
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    let app = lucid_auth::axum::router(service);

    let (status, _, body) = request(
        &app,
        "GET",
        "/api/auth/.well-known/oauth-authorization-server",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let metadata: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        metadata["device_authorization_endpoint"],
        "http://localhost/api/auth/device/code"
    );
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(DEVICE_CODE_GRANT_TYPE))
    );
}
