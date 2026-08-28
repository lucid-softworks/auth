use lucid_auth::{
    AuthConfig, AuthPlugin, AuthSchemaCatalog, AuthService, MemoryStore, PluginDescriptor,
    PluginProvenance, PluginSchemaTable,
};
use std::{borrow::Cow, sync::Arc};

struct SchemaPlugin(PluginSchemaTable);

#[async_trait::async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "sqlite-test-schema",
            display_name: "SQLite test schema",
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
