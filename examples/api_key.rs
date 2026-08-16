use chrono::{Duration, Utc};
use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewApiKey, NewPasswordUser};
use std::{collections::BTreeMap, sync::Arc};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([42_u8; 32])?,
    );
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
            NewApiKey {
                config_id: "example".into(),
                name: "Read-only client".into(),
                prefix: "example_".into(),
                expires_at: Utc::now() + Duration::days(30),
                permissions: BTreeMap::from([("documents".into(), vec!["read".into()])]),
                rate_limit_window_seconds: 60,
                rate_limit_max: 120,
            },
        )
        .await?;

    let verified = service.verify_api_key(&issued.key, "example").await?;
    assert!(verified.api_key.permits("documents", "read"));
    println!("verified API key {}", verified.api_key.start);
    Ok(())
}
