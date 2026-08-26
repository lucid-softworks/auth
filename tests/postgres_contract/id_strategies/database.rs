use lucid_auth::{
    AuthConfig, AuthService, DatabaseIdGeneration, UsernamePlugin,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct StrategyDatabase {
    pub(super) pool: sqlx::PgPool,
    pub(super) service: Arc<AuthService>,
    pub(super) store: Arc<PostgresStore>,
    admin: sqlx::PgPool,
    schema: String,
}

impl StrategyDatabase {
    pub(super) async fn start(
        strategy: DatabaseIdGeneration,
        label: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let schema = format!("lucid_id_{label}_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&admin)
            .await?;
        let search_path = format!("SET search_path TO \"{schema}\"");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let search_path = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&search_path).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await?;
        let store = Arc::new(PostgresStore::new(
            pool.clone(),
            PostgresAdapterConfig::default(),
        ));
        let mut config = AuthConfig::new([b'P'; 32])?;
        config.database_id_generation = strategy;
        config.email_and_password.enabled = true;
        config.add_plugin(UsernamePlugin::default())?;
        let service = Arc::new(AuthService::try_new(store.clone(), config)?);
        store.migrate().await?;
        Ok(Self {
            pool,
            service,
            store,
            admin,
            schema,
        })
    }

    pub(super) async fn close(self) -> Result<(), Box<dyn std::error::Error>> {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
