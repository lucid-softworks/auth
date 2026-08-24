use super::support::{RecordingAdapter, payload};
use lucid_auth::{
    AuthConfig, AuthService, JwtAdapterContext, JwtConfig, JwtPlugin, JwtSigningOverrides,
    MemoryStore, VersionedSecret,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn versioned_private_jwk_envelopes_rotate_and_retire_exact_secret_versions() {
    let adapter = Arc::new(RecordingAdapter::default());
    let first = service(adapter.clone(), vec![secret(7, 171)], None, [170_u8; 32]);
    sign(&first).await.unwrap();
    let keys = adapter.keys.lock().await;
    let envelope: String = serde_json::from_str(&keys[0].private_key).unwrap();
    assert!(envelope.starts_with("$ba$7$"));
    assert!(!format!("{:?}", keys[0]).contains(&envelope));
    drop(keys);

    let rotated = service(
        adapter.clone(),
        vec![secret(8, 172), secret(7, 171)],
        None,
        [170_u8; 32],
    );
    assert!(sign(&rotated).await.is_ok());

    let retired = service(adapter, vec![secret(8, 172)], None, [170_u8; 32]);
    assert!(
        sign(&retired)
            .await
            .unwrap_err()
            .to_string()
            .contains("decryption")
    );
}

#[tokio::test]
async fn versioned_configuration_uses_only_the_explicit_legacy_bare_hex_fallback() {
    let adapter = Arc::new(RecordingAdapter::default());
    let legacy = service(adapter.clone(), Vec::new(), None, [173_u8; 32]);
    sign(&legacy).await.unwrap();
    let stored: String = serde_json::from_str(&adapter.keys.lock().await[0].private_key).unwrap();
    assert!(!stored.starts_with("$ba$"));

    let compatible = service(
        adapter.clone(),
        vec![secret(2, 174)],
        Some(vec![173_u8; 32]),
        [175_u8; 32],
    );
    assert!(sign(&compatible).await.is_ok());

    let no_legacy = service(adapter, vec![secret(2, 174)], None, [175_u8; 32]);
    assert!(sign(&no_legacy).await.is_err());
}

fn service(
    adapter: Arc<RecordingAdapter>,
    secrets: Vec<VersionedSecret>,
    legacy: Option<Vec<u8>>,
    initial: [u8; 32],
) -> AuthService {
    let mut auth = AuthConfig::new(initial).unwrap();
    auth.set_base_url("http://localhost").unwrap();
    if !secrets.is_empty() {
        auth.set_versioned_secrets(secrets, legacy).unwrap();
    }
    auth.add_plugin(JwtPlugin::new(JwtConfig {
        adapter: adapter.config(),
        ..JwtConfig::default()
    }))
    .unwrap();
    AuthService::new(Arc::new(MemoryStore::default()), auth)
}

fn secret(version: u32, byte: u8) -> VersionedSecret {
    VersionedSecret {
        version,
        value: vec![byte; 32],
    }
}

async fn sign(service: &AuthService) -> Result<String, lucid_auth::AuthError> {
    service
        .jwt()
        .unwrap()
        .sign_jwt(
            &JwtAdapterContext::default(),
            payload([("sub", json!("secret-rotation-subject"))]),
            None,
            JwtSigningOverrides::default(),
        )
        .await
}
