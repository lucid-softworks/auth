use axum::Router;
use lucid_auth::{AuthConfig, AuthService, MemoryStore};
use std::{env, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = env::var("BETTER_AUTH_SECRET")?;
    let public_url =
        env::var("BETTER_AUTH_URL").unwrap_or_else(|_| "http://localhost:3000".to_owned());
    let frontend_origin =
        env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_owned());
    let address = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse::<SocketAddr>()?;

    let mut config = AuthConfig::new(secret.into_bytes())?;
    config.set_base_url(&public_url)?;
    config.trust_origin(&frontend_origin)?;
    config.enable_cors();
    config.email_and_password.enabled = true;

    let service = Arc::new(AuthService::try_new(
        Arc::new(MemoryStore::default()),
        config,
    )?);
    let app: Router = lucid_auth::axum::router(service);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("lucid-auth memory server listening on {public_url}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
