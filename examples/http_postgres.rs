use axum::Router;
use lucid_auth::{AuthConfig, AuthService, postgres::PostgresStore};
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = env::var("BETTER_AUTH_SECRET")?;
    let public_url = env::var("BETTER_AUTH_URL")?;
    let database_url = env::var("DATABASE_URL")?;
    let frontend_origin = env::var("FRONTEND_ORIGIN")?;
    let address = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
        .parse::<SocketAddr>()?;

    let mut config = AuthConfig::new(secret.into_bytes())?;
    config.set_base_url(&public_url)?;
    config.trust_origin(&frontend_origin)?;
    config.enable_cors();
    config.email_and_password.enabled = true;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    let store = Arc::new(PostgresStore::new(pool));
    let service = Arc::new(AuthService::try_new(store.clone(), config)?);

    store.migrate().await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;

    let app: Router = lucid_auth::axum::router(service);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("lucid-auth PostgreSQL server listening on {public_url}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
