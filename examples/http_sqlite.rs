use axum::Router;
use lucid_auth::{
    AuthConfig, AuthService,
    sqlite::{SqliteAdapterConfig, SqliteStore},
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{env, net::SocketAddr, str::FromStr, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = env::var("BETTER_AUTH_SECRET")?;
    let public_url = env::var("BETTER_AUTH_URL")?;
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://lucid-auth.db".into());
    let frontend_origin = env::var("FRONTEND_ORIGIN")?;
    let address = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
        .parse::<SocketAddr>()?;

    let mut config = AuthConfig::new(secret.into_bytes())?;
    config.set_base_url(&public_url)?;
    config.trust_origin(&frontend_origin)?;
    config.enable_cors();
    config.email_and_password.enabled = true;

    let connect_options = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);
    let max_connections = if database_url == "sqlite::memory:" {
        1
    } else {
        5
    };
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(connect_options)
        .await?;
    let store = Arc::new(SqliteStore::new(pool, SqliteAdapterConfig::default()));
    let service = Arc::new(AuthService::try_new(store.clone(), config)?);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await?;

    let app: Router = lucid_auth::axum::router(service);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("lucid-auth SQLite server listening on {public_url}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
