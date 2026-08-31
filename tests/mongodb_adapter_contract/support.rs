use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, PluginDescriptor, PluginProvenance, PluginSchemaTable,
    mongodb::{MongoAdapterConfig, MongoStore},
};
use mongodb::Client;
use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) struct SchemaPlugin(pub(super) PluginSchemaTable);

#[async_trait::async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "mongodb-test-schema",
            display_name: "MongoDB test schema",
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

pub(super) async fn standalone_store(table: PluginSchemaTable) -> MongoStore {
    configured_store(
        "MONGODB_STANDALONE_URI",
        MongoAdapterConfig {
            transaction: Some(false),
            ..Default::default()
        },
        config(table, [63; 32]),
    )
    .await
}

pub(super) async fn replica_store(table: PluginSchemaTable) -> MongoStore {
    configured_store(
        "MONGODB_REPLICA_SET_URI",
        MongoAdapterConfig::default(),
        config(table, [64; 32]),
    )
    .await
}

pub(super) async fn configured_store(
    environment: &str,
    adapter: MongoAdapterConfig,
    config: AuthConfig,
) -> MongoStore {
    let uri = std::env::var(environment)
        .unwrap_or_else(|_| panic!("{environment} is required for ignored MongoDB contracts"));
    let client = Client::with_uri_str(&uri).await.unwrap();
    let database = client.database(&format!(
        "lucid_auth_{}_{}",
        std::process::id(),
        DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    database.drop().await.unwrap();
    let store = MongoStore::new(database, Some(client), adapter);
    let _service = AuthService::new(Arc::new(store.clone()), config);
    store
}

pub(super) fn config(table: PluginSchemaTable, secret: [u8; 32]) -> AuthConfig {
    let mut config = AuthConfig::new(secret).unwrap();
    config.add_plugin(SchemaPlugin(table)).unwrap();
    config
}
