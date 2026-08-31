use lucid_auth::{
    AuthConfig, AuthPlugin, AuthSchemaCatalog, AuthService, MemoryStore, PluginDescriptor,
    PluginProvenance, PluginSchemaTable,
};
use sqlx::{
    MySqlPool,
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
};
use std::{
    borrow::Cow,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) async fn pool(max_connections: u32) -> MySqlPool {
    let database_url = std::env::var("MYSQL_DATABASE_URL")
        .expect("MYSQL_DATABASE_URL is required for ignored MySQL contracts");
    let admin_url = std::env::var("MYSQL_ADMIN_DATABASE_URL").unwrap_or(database_url);
    let admin = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let database = format!(
        "lucid_auth_{}_{}",
        std::process::id(),
        DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(&format!("create database `{database}`"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let options = MySqlConnectOptions::from_str(&admin_url)
        .unwrap()
        .database(&database);
    MySqlPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .unwrap()
}

struct SchemaPlugin(PluginSchemaTable);

#[async_trait::async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "mysql-test-schema",
            display_name: "MySQL test schema",
            version: "0.0.0",
            provenance: PluginProvenance::LucidExtension,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        vec![self.0.clone()]
    }
}

pub(super) fn catalog(table: PluginSchemaTable, secret: [u8; 32]) -> Arc<AuthSchemaCatalog> {
    let mut config = AuthConfig::new(secret).unwrap();
    config.add_plugin(SchemaPlugin(table)).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    Arc::new(service.database_schema().clone())
}
