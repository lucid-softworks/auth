use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewPasswordUser};
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new([42_u8; 32])?;
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
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
    println!("signed in {}", session.session.user.name);
    Ok(())
}
