use super::{AuthPlugin, PluginDescriptor, PluginMigrationContribution, PluginRateLimit};
use crate::{
    AdditionalFieldSet, AuthConfig, AuthError, AuthSchemaCatalog, DatabaseModel, PluginSchemaTable,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

mod client_metadata;
mod core_endpoints;
mod lifecycle;
mod oauth_provider;
mod provenance;
mod schema;
mod validation;

use core_endpoints::CORE_ENDPOINTS;
use schema::additional_schema_fields;

type DescriptorMap = HashMap<&'static str, (usize, PluginDescriptor)>;

pub(crate) struct PluginRegistry {
    plugins: Vec<Arc<dyn AuthPlugin>>,
    descriptors: Vec<PluginDescriptor>,
    migrations: Vec<PluginMigrationContribution>,
    rate_limits: Vec<PluginRateLimit>,
    schema_fields: BTreeMap<DatabaseModel, AdditionalFieldSet>,
    schema_catalog: Arc<AuthSchemaCatalog>,
}

impl PluginRegistry {
    pub(crate) fn build(
        plugins: &[Arc<dyn AuthPlugin>],
        config: &AuthConfig,
    ) -> Result<Self, AuthError> {
        let mut by_id = HashMap::new();
        let mut migrations_by_plugin = Vec::with_capacity(plugins.len());
        let mut plugin_tables = Vec::<PluginSchemaTable>::new();
        for (index, plugin) in plugins.iter().enumerate() {
            let descriptor = plugin.descriptor();
            validation::validate_descriptor(&descriptor)?;
            plugin.validate(config)?;
            validation::validate_runtime_rate_limits(plugin.as_ref(), &descriptor)?;
            let migrations = if descriptor.provenance == crate::PluginProvenance::LucidExtension {
                plugin.migrations().into_owned()
            } else {
                Vec::new()
            };
            validation::validate_migrations(&migrations, &descriptor)?;
            migrations_by_plugin.push(migrations);
            plugin_tables.extend(plugin.schema());
            let descriptor_id = descriptor.id;
            if by_id.insert(descriptor_id, (index, descriptor)).is_some() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "plugin '{descriptor_id}' is enabled more than once"
                )));
            }
        }
        validation::validate_relationships(&by_id)?;
        oauth_provider::validate_extensions(plugins)?;
        validation::validate_contributions(&by_id, config)?;
        let ordered_ids = validation::dependency_order(&by_id)?;
        let mut ordered_plugins = Vec::with_capacity(plugins.len());
        let mut descriptors = Vec::with_capacity(plugins.len());
        let mut migrations = Vec::new();
        let mut rate_limits = Vec::new();
        let schema_fields = additional_schema_fields(config, &plugin_tables)?;
        let schema_catalog = Arc::new(
            AuthSchemaCatalog::build(config, plugin_tables)
                .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?,
        );
        for id in ordered_ids {
            let (index, descriptor) = &by_id[&id];
            rate_limits.extend(plugins[*index].rate_limits());
            migrations.extend(migrations_by_plugin[*index].drain(..).map(|migration| {
                PluginMigrationContribution {
                    plugin_id: descriptor.id,
                    migration,
                }
            }));
            ordered_plugins.push(plugins[*index].clone());
            descriptors.push(descriptor.clone());
        }
        Ok(Self {
            plugins: ordered_plugins,
            descriptors,
            migrations,
            rate_limits,
            schema_fields,
            schema_catalog,
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) fn plugins(&self) -> &[Arc<dyn AuthPlugin>] {
        &self.plugins
    }

    pub(crate) fn descriptors(&self) -> &[PluginDescriptor] {
        &self.descriptors
    }

    pub(crate) fn rate_limits(&self) -> &[PluginRateLimit] {
        &self.rate_limits
    }

    pub(crate) fn rate_limit(&self, path: &str) -> Option<PluginRateLimit> {
        self.rate_limits
            .iter()
            .copied()
            .find(|rule| rule.path == path)
    }

    pub(crate) fn schema_fields(&self, model: DatabaseModel) -> &AdditionalFieldSet {
        self.schema_fields
            .get(&model)
            .expect("every Better Auth core model has a schema field set")
    }

    pub(crate) fn schema_catalog(&self) -> &Arc<AuthSchemaCatalog> {
        &self.schema_catalog
    }

    pub(crate) fn open_api_endpoints(&self) -> Vec<(&'static str, Vec<crate::OpenApiEndpoint>)> {
        self.plugins
            .iter()
            .zip(&self.descriptors)
            .map(|(plugin, descriptor)| (descriptor.id, plugin.open_api_endpoints()))
            .collect()
    }

    pub(crate) fn open_api_models(&self) -> Vec<crate::OpenApiModel> {
        self.plugins
            .iter()
            .flat_map(|plugin| plugin.open_api_models())
            .collect()
    }

    pub(crate) fn find<P: AuthPlugin + 'static>(&self) -> Option<&P> {
        self.plugins
            .iter()
            .find_map(|plugin| plugin.as_any().downcast_ref())
    }

    pub(crate) fn migrations(&self) -> Vec<PluginMigrationContribution> {
        self.migrations.clone()
    }

    pub(crate) fn social_providers(&self) -> Vec<Arc<dyn crate::SocialProvider>> {
        self.plugins
            .iter()
            .flat_map(|plugin| plugin.social_providers())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PluginMigration, PluginProvenance, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
    };
    use std::borrow::Cow;

    struct MigrationPlugin {
        id: &'static str,
        provenance: PluginProvenance,
    }

    #[async_trait::async_trait]
    impl AuthPlugin for MigrationPlugin {
        fn descriptor(&self) -> PluginDescriptor {
            PluginDescriptor {
                id: self.id,
                display_name: "Migration fixture",
                version: COMPATIBLE_BETTER_AUTH_VERSION,
                provenance: self.provenance,
                dependencies: &[],
                conflicts: &[],
                endpoints: Cow::Borrowed(&[]),
                cookies: &[],
                rate_limits: &[],
                middleware: &[],
                client: None,
            }
        }

        fn migrations(&self) -> Cow<'_, [PluginMigration]> {
            Cow::Owned(vec![PluginMigration::borrowed(
                "fixture-schema",
                "fixture schema",
                "CREATE TABLE fixture (id TEXT)",
            )])
        }
    }

    #[test]
    fn official_schema_sql_is_not_replayed_but_extension_operations_remain() {
        let official: Arc<dyn AuthPlugin> = Arc::new(MigrationPlugin {
            id: "official-fixture",
            provenance: PluginProvenance::better_auth_plugin("fixture"),
        });
        let extension: Arc<dyn AuthPlugin> = Arc::new(MigrationPlugin {
            id: "extension-fixture",
            provenance: PluginProvenance::LucidExtension,
        });
        let config = AuthConfig::new([23; 32]).unwrap();
        let official_registry = PluginRegistry::build(&[official], &config).unwrap();
        assert!(official_registry.migrations().is_empty());
        let extension_registry = PluginRegistry::build(&[extension], &config).unwrap();
        assert_eq!(extension_registry.migrations().len(), 1);
    }
}
