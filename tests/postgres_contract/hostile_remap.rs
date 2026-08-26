use lucid_auth::{
    AuthService,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "hostile_remap/config.rs"]
mod config;
#[path = "hostile_remap/schema.rs"]
mod schema;
#[path = "hostile_remap/workflows.rs"]
mod workflows;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn hostile_core_remaps_work_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let database = IsolatedDatabase::connect().await?;
    let outcome = run_contract(&database.pool).await;
    let cleanup = database.close().await;
    outcome?;
    cleanup
}

async fn run_contract(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(PostgresStore::new(
        pool.clone(),
        PostgresAdapterConfig { use_plural: true },
    ));
    let service = AuthService::try_new(store.clone(), config::hostile_config()?)?;
    store.migrate().await?;
    store.migrate().await?;

    schema::assert_exact_schema(pool).await?;
    workflows::assert_all(&service, &store).await?;
    Ok(())
}

struct IsolatedDatabase {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
}

impl IsolatedDatabase {
    async fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let schema = format!("lucid_hostile_{}", Uuid::new_v4().simple());
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
        Ok(Self {
            admin,
            pool,
            schema,
        })
    }

    async fn close(self) -> Result<(), Box<dyn std::error::Error>> {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
