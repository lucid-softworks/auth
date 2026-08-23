use chrono::{Duration, Utc};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyPlugin, AuthConfig, AuthService, MemoryStore, NewApiKey,
    NewPasswordUser,
};
use std::{collections::BTreeMap, sync::Arc};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_keys = ApiKeyConfiguration {
        config_id: "default".into(),
        ..ApiKeyConfiguration::default()
    };
    let mut auth = AuthConfig::new([42_u8; 32])?;
    auth.add_plugin(ApiKeyPlugin::new(api_keys.clone()))?;
    let service = AuthService::new(Arc::new(MemoryStore::default()), auth);
    service
        .provision_password_user(NewPasswordUser {
            username: "example".into(),
            name: "Example User".into(),
            email: None,
            password: "replace-me".into(),
            role: "owner".into(),
        })
        .await?;
    let session = service
        .sign_in_username("example", "replace-me".into(), None, None)
        .await?;
    let issued = service
        .issue_api_key(
            &session.session,
            &api_keys,
            NewApiKey {
                config_id: "default".into(),
                name: Some("Read-only client".into()),
                prefix: Some("example_".into()),
                expires_at: Some(Utc::now() + Duration::days(30)),
                permissions: Some(BTreeMap::from([("documents".into(), vec!["read".into()])])),
                metadata: None,
                remaining: None,
                refill_amount: None,
                refill_interval: None,
                rate_limit_enabled: true,
                rate_limit_time_window: Some(60_000),
                rate_limit_max: Some(120),
            },
        )
        .await?;

    let verified = service
        .verify_api_key(&issued.key, &[api_keys], Some("default"), None)
        .await?;
    assert!(verified.api_key.permits("documents", "read"));
    println!("verified API key {:?}", verified.api_key.start);
    Ok(())
}
