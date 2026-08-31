use axum::Router;
use lucid_auth::{
    AuthConfig, AuthService,
    mssql::{MssqlAdapterConfig, MssqlStore},
};
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

    let store = Arc::new(
        MssqlStore::connect(
            &database_url,
            MssqlAdapterConfig {
                transaction: env::var("MSSQL_TRANSACTIONS").as_deref() == Ok("true"),
                ..Default::default()
            },
        )
        .await?,
    );
    let service = Arc::new(AuthService::try_new(store.clone(), config)?);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await?;

    let app: Router = lucid_auth::axum::router(service);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("lucid-auth Microsoft SQL Server listening on {public_url}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
