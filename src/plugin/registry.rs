use super::{
    AuthPlugin, PluginDescriptor, PluginHttpMethod, PluginMigration, PluginMigrationContribution,
    PluginRateLimit,
};
use crate::{AdditionalFieldSet, AuthConfig, AuthError, DatabaseModel};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

mod client_metadata;
mod core_endpoints;
mod lifecycle;
mod oauth_provider;
mod schema;

use core_endpoints::CORE_ENDPOINTS;
use schema::{core_schema_fields, merge_schema_fields};

type DescriptorMap = HashMap<&'static str, (usize, PluginDescriptor)>;

pub(crate) struct PluginRegistry {
    plugins: Vec<Arc<dyn AuthPlugin>>,
    descriptors: Vec<PluginDescriptor>,
    migrations: Vec<PluginMigrationContribution>,
    rate_limits: Vec<PluginRateLimit>,
    schema_fields: BTreeMap<DatabaseModel, AdditionalFieldSet>,
}

impl PluginRegistry {
    pub(crate) fn build(
        plugins: &[Arc<dyn AuthPlugin>],
        config: &AuthConfig,
    ) -> Result<Self, AuthError> {
        let mut by_id = HashMap::new();
        let mut migrations_by_plugin = Vec::with_capacity(plugins.len());
        for (index, plugin) in plugins.iter().enumerate() {
            let descriptor = plugin.descriptor();
            validate_descriptor(&descriptor)?;
            plugin.validate(config)?;
            validate_runtime_rate_limits(plugin.as_ref(), &descriptor)?;
            let migrations = plugin.migrations().into_owned();
            validate_migrations(&migrations, &descriptor)?;
            migrations_by_plugin.push(migrations);
            let descriptor_id = descriptor.id;
            if by_id.insert(descriptor_id, (index, descriptor)).is_some() {
                return invalid(format!(
                    "plugin '{descriptor_id}' is enabled more than once"
                ));
            }
        }
        validate_relationships(&by_id)?;
        oauth_provider::validate_extensions(plugins)?;
        validate_contributions(&by_id, config)?;
        let ordered_ids = dependency_order(&by_id)?;
        let mut ordered_plugins = Vec::with_capacity(plugins.len());
        let mut descriptors = Vec::with_capacity(plugins.len());
        let mut migrations = Vec::new();
        let mut rate_limits = Vec::new();
        let mut schema_fields = core_schema_fields(config);
        for id in ordered_ids {
            let (index, descriptor) = &by_id[&id];
            rate_limits.extend(plugins[*index].rate_limits());
            merge_schema_fields(
                &mut schema_fields,
                plugins[*index].schema_fields(),
                descriptor.id,
            )?;
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

fn validate_descriptor(descriptor: &PluginDescriptor) -> Result<(), AuthError> {
    if !valid_id(descriptor.id) {
        return invalid(format!("plugin id '{}' is invalid", descriptor.id));
    }
    if descriptor.display_name.trim().is_empty() || descriptor.version.trim().is_empty() {
        return invalid(format!(
            "plugin '{}' requires a display name and version",
            descriptor.id
        ));
    }
    if let Some(client) = descriptor.client {
        client_metadata::validate(client, descriptor.id)
            .map_err(AuthError::InvalidConfiguration)?;
    }
    Ok(())
}

fn validate_relationships(by_id: &DescriptorMap) -> Result<(), AuthError> {
    for descriptor in by_id.values().map(|(_, descriptor)| descriptor) {
        for dependency in descriptor.dependencies {
            if !by_id.contains_key(dependency) {
                return invalid(format!(
                    "plugin '{}' requires missing plugin '{dependency}'",
                    descriptor.id
                ));
            }
        }
        for conflict in descriptor.conflicts {
            if by_id.contains_key(conflict) {
                return invalid(format!(
                    "plugin '{}' conflicts with plugin '{conflict}'",
                    descriptor.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_contributions(by_id: &DescriptorMap, config: &AuthConfig) -> Result<(), AuthError> {
    let mut endpoint_methods: HashMap<(PluginHttpMethod, String), &'static str> = CORE_ENDPOINTS
        .iter()
        .map(|(method, path)| ((*method, (*path).to_owned()), "core"))
        .collect();
    let mut endpoint_paths: HashMap<String, &'static str> = CORE_ENDPOINTS
        .iter()
        .map(|(_, path)| ((*path).to_owned(), "core"))
        .collect();
    let mut cookies = core_cookie_owners(config);

    for (_, descriptor) in by_id.values() {
        validate_endpoints(descriptor, &mut endpoint_methods, &mut endpoint_paths)?;
        validate_cookies(descriptor, &mut cookies)?;
        validate_policy_metadata(descriptor)?;
    }
    Ok(())
}

fn core_cookie_owners(config: &AuthConfig) -> HashMap<String, &'static str> {
    let session = config
        .cookies
        .session_token
        .name
        .clone()
        .unwrap_or_else(|| format!("{}.session_token", config.cookies.prefix));
    [session]
        .into_iter()
        .flat_map(|name| [name.clone(), format!("__Secure-{name}")])
        .map(|name| (name, "core"))
        .collect()
}

fn validate_endpoints(
    descriptor: &PluginDescriptor,
    methods: &mut HashMap<(PluginHttpMethod, String), &'static str>,
    paths: &mut HashMap<String, &'static str>,
) -> Result<(), AuthError> {
    for endpoint in descriptor.endpoints.iter() {
        validate_path(endpoint.path.as_ref(), descriptor.id)?;
        if endpoint.client_method.trim().is_empty() {
            return invalid(format!(
                "plugin '{}' endpoint '{}' has no client method",
                descriptor.id, endpoint.path
            ));
        }
        if let Some(owner) = methods.insert(
            (endpoint.method, endpoint.path.as_ref().to_owned()),
            descriptor.id,
        ) {
            return invalid(format!(
                "plugin '{}' endpoint {:?} {} conflicts with '{owner}'",
                descriptor.id, endpoint.method, endpoint.path
            ));
        }
        if let Some(owner) = paths.insert(endpoint.path.as_ref().to_owned(), descriptor.id)
            && owner != descriptor.id
        {
            return invalid(format!(
                "plugin '{}' endpoint path '{}' conflicts with '{owner}'",
                descriptor.id, endpoint.path
            ));
        }
    }
    Ok(())
}

fn validate_cookies(
    descriptor: &PluginDescriptor,
    cookies: &mut HashMap<String, &'static str>,
) -> Result<(), AuthError> {
    for cookie in descriptor.cookies {
        if cookie.name.is_empty()
            || cookie.name.contains([';', '='])
            || cookie.name.chars().any(char::is_whitespace)
        {
            return invalid(format!("plugin '{}' cookie name is invalid", descriptor.id));
        }
        if let Some(owner) = cookies.insert(cookie.name.into(), descriptor.id) {
            return invalid(format!(
                "plugin '{}' cookie '{}' conflicts with '{owner}'",
                descriptor.id, cookie.name
            ));
        }
    }
    Ok(())
}

fn validate_policy_metadata(descriptor: &PluginDescriptor) -> Result<(), AuthError> {
    for rate_limit in descriptor.rate_limits {
        validate_path(rate_limit.path, descriptor.id)?;
        if !descriptor
            .endpoints
            .iter()
            .any(|endpoint| endpoint.path == rate_limit.path)
            || rate_limit.window == 0
            || rate_limit.max == 0
        {
            return invalid(format!("plugin '{}' rate limit is invalid", descriptor.id));
        }
    }
    for middleware in descriptor.middleware {
        if !valid_id(middleware.id) {
            return invalid(format!(
                "plugin '{}' middleware id is invalid",
                descriptor.id
            ));
        }
    }
    Ok(())
}

fn validate_runtime_rate_limits(
    plugin: &dyn AuthPlugin,
    descriptor: &PluginDescriptor,
) -> Result<(), AuthError> {
    for rate_limit in plugin.rate_limits() {
        validate_path(rate_limit.path, descriptor.id)?;
        if !descriptor
            .endpoints
            .iter()
            .any(|endpoint| endpoint.path == rate_limit.path)
            || rate_limit.max == 0
        {
            return invalid(format!(
                "plugin '{}' runtime rate limit is invalid",
                descriptor.id
            ));
        }
    }
    Ok(())
}

fn validate_migrations(
    plugin_migrations: &[PluginMigration],
    descriptor: &PluginDescriptor,
) -> Result<(), AuthError> {
    let mut migrations = HashMap::new();
    for migration in plugin_migrations {
        if !valid_id(migration.id.as_ref())
            || migration.description.trim().is_empty()
            || migration.sql.trim().is_empty()
        {
            return invalid(format!("plugin '{}' migration is invalid", descriptor.id));
        }
        if migrations.insert(migration.id.as_ref(), ()).is_some() {
            return invalid(format!(
                "plugin '{}' migration '{}' is duplicated",
                descriptor.id, migration.id
            ));
        }
    }
    Ok(())
}

fn dependency_order(by_id: &DescriptorMap) -> Result<Vec<&'static str>, AuthError> {
    let mut ids: Vec<_> = by_id.keys().copied().collect();
    ids.sort_by_key(|id| by_id[id].0);
    let mut states = HashMap::new();
    let mut ordered = Vec::with_capacity(ids.len());
    for id in ids {
        visit(id, by_id, &mut states, &mut ordered)?;
    }
    Ok(ordered)
}

fn visit(
    id: &'static str,
    by_id: &DescriptorMap,
    states: &mut HashMap<&'static str, VisitState>,
    ordered: &mut Vec<&'static str>,
) -> Result<(), AuthError> {
    match states.get(id) {
        Some(VisitState::Complete) => return Ok(()),
        Some(VisitState::Visiting) => {
            return invalid(format!("plugin dependency cycle includes '{id}'"));
        }
        None => {}
    }
    states.insert(id, VisitState::Visiting);
    for dependency in by_id[id].1.dependencies {
        visit(dependency, by_id, states, ordered)?;
    }
    states.insert(id, VisitState::Complete);
    ordered.push(id);
    Ok(())
}

fn validate_path(path: &str, plugin_id: &str) -> Result<(), AuthError> {
    if !path.starts_with('/')
        || path.len() < 2
        || path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_control)
    {
        return invalid(format!(
            "plugin '{plugin_id}' endpoint path '{path}' is invalid"
        ));
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn invalid<T>(message: String) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message))
}

#[derive(Clone, Copy)]
enum VisitState {
    Visiting,
    Complete,
}
