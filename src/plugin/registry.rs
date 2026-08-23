use super::{AuthPlugin, PluginDescriptor, PluginHttpMethod, PluginMigrationContribution};
use crate::{AuthConfig, AuthError, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION};
use std::{collections::HashMap, sync::Arc};

mod lifecycle;

pub(crate) struct PluginRegistry {
    plugins: Vec<Arc<dyn AuthPlugin>>,
    descriptors: Vec<PluginDescriptor>,
}

impl PluginRegistry {
    pub(crate) fn empty() -> Self {
        Self {
            plugins: Vec::new(),
            descriptors: Vec::new(),
        }
    }

    pub(crate) fn build(
        plugins: &[Arc<dyn AuthPlugin>],
        config: &AuthConfig,
    ) -> Result<Self, AuthError> {
        if plugins.is_empty() {
            return Ok(Self::empty());
        }
        let mut by_id = HashMap::new();
        for (index, plugin) in plugins.iter().enumerate() {
            let descriptor = plugin.descriptor();
            validate_descriptor(descriptor)?;
            plugin.validate(config)?;
            if by_id.insert(descriptor.id, (index, descriptor)).is_some() {
                return invalid(format!(
                    "plugin '{}' is enabled more than once",
                    descriptor.id
                ));
            }
        }
        validate_relationships(&by_id)?;
        validate_contributions(plugins, &by_id, config)?;
        let ordered_ids = dependency_order(&by_id)?;
        let mut ordered_plugins = Vec::with_capacity(plugins.len());
        let mut descriptors = Vec::with_capacity(plugins.len());
        for id in ordered_ids {
            let (index, descriptor) = by_id[&id];
            ordered_plugins.push(plugins[index].clone());
            descriptors.push(descriptor);
        }
        Ok(Self {
            plugins: ordered_plugins,
            descriptors,
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) fn plugins(&self) -> &[Arc<dyn AuthPlugin>] {
        &self.plugins
    }

    pub(crate) fn descriptors(&self) -> &[PluginDescriptor] {
        &self.descriptors
    }

    pub(crate) fn find<P: AuthPlugin + 'static>(&self) -> Option<&P> {
        self.plugins
            .iter()
            .find_map(|plugin| plugin.as_any().downcast_ref())
    }

    pub(crate) fn migrations(&self) -> Vec<PluginMigrationContribution> {
        self.plugins
            .iter()
            .zip(&self.descriptors)
            .flat_map(|(plugin, descriptor)| {
                plugin
                    .migrations()
                    .iter()
                    .copied()
                    .map(|migration| PluginMigrationContribution {
                        plugin_id: descriptor.id,
                        migration,
                    })
            })
            .collect()
    }
}

fn validate_descriptor(descriptor: PluginDescriptor) -> Result<(), AuthError> {
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
        if [client.package, client.import_path, client.factory]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return invalid(format!(
                "plugin '{}' client metadata is incomplete",
                descriptor.id
            ));
        }
        if client.better_auth_version != COMPATIBLE_BETTER_AUTH_VERSION {
            return invalid(format!(
                "plugin '{}' targets Better Auth {}, expected {}",
                descriptor.id, client.better_auth_version, COMPATIBLE_BETTER_AUTH_VERSION
            ));
        }
    }
    Ok(())
}

fn validate_relationships(
    by_id: &HashMap<&'static str, (usize, PluginDescriptor)>,
) -> Result<(), AuthError> {
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

fn validate_contributions(
    plugins: &[Arc<dyn AuthPlugin>],
    by_id: &HashMap<&'static str, (usize, PluginDescriptor)>,
    config: &AuthConfig,
) -> Result<(), AuthError> {
    let mut endpoint_methods: HashMap<(PluginHttpMethod, &'static str), &'static str> =
        CORE_ENDPOINTS
            .iter()
            .map(|(method, path)| ((*method, *path), "core"))
            .collect();
    let mut endpoint_paths: HashMap<&'static str, &'static str> = CORE_ENDPOINTS
        .iter()
        .map(|(_, path)| (*path, "core"))
        .collect();
    let mut cookies = core_cookie_owners(config);

    for (index, descriptor) in by_id.values().copied() {
        validate_endpoints(descriptor, &mut endpoint_methods, &mut endpoint_paths)?;
        validate_cookies(descriptor, &mut cookies)?;
        validate_policy_metadata(descriptor)?;
        validate_migrations(plugins[index].as_ref(), descriptor)?;
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
    descriptor: PluginDescriptor,
    methods: &mut HashMap<(PluginHttpMethod, &'static str), &'static str>,
    paths: &mut HashMap<&'static str, &'static str>,
) -> Result<(), AuthError> {
    for endpoint in descriptor.endpoints {
        validate_path(endpoint.path, descriptor.id)?;
        if endpoint.client_method.trim().is_empty() {
            return invalid(format!(
                "plugin '{}' endpoint '{}' has no client method",
                descriptor.id, endpoint.path
            ));
        }
        if let Some(owner) = methods.insert((endpoint.method, endpoint.path), descriptor.id) {
            return invalid(format!(
                "plugin '{}' endpoint {:?} {} conflicts with '{owner}'",
                descriptor.id, endpoint.method, endpoint.path
            ));
        }
        if let Some(owner) = paths.insert(endpoint.path, descriptor.id)
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
    descriptor: PluginDescriptor,
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

fn validate_policy_metadata(descriptor: PluginDescriptor) -> Result<(), AuthError> {
    for rate_limit in descriptor.rate_limits {
        validate_path(rate_limit.path, descriptor.id)?;
        if !descriptor
            .endpoints
            .iter()
            .any(|endpoint| endpoint.path == rate_limit.path)
            || rate_limit.window_seconds == 0
            || rate_limit.max_requests == 0
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

fn validate_migrations(
    plugin: &dyn AuthPlugin,
    descriptor: PluginDescriptor,
) -> Result<(), AuthError> {
    let mut migrations = HashMap::new();
    for migration in plugin.migrations() {
        if !valid_id(migration.id)
            || migration.description.trim().is_empty()
            || migration.sql.trim().is_empty()
        {
            return invalid(format!("plugin '{}' migration is invalid", descriptor.id));
        }
        if migrations.insert(migration.id, ()).is_some() {
            return invalid(format!(
                "plugin '{}' migration '{}' is duplicated",
                descriptor.id, migration.id
            ));
        }
    }
    Ok(())
}

fn dependency_order(
    by_id: &HashMap<&'static str, (usize, PluginDescriptor)>,
) -> Result<Vec<&'static str>, AuthError> {
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
    by_id: &HashMap<&'static str, (usize, PluginDescriptor)>,
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

const CORE_ENDPOINTS: &[(PluginHttpMethod, &str)] = &[
    (PluginHttpMethod::Get, "/get-session"),
    (PluginHttpMethod::Post, "/sign-up/email"),
    (PluginHttpMethod::Post, "/sign-in/email"),
    (PluginHttpMethod::Post, "/verify-password"),
    (PluginHttpMethod::Post, "/request-password-reset"),
    (PluginHttpMethod::Get, "/reset-password/:token"),
    (PluginHttpMethod::Post, "/reset-password"),
    (PluginHttpMethod::Post, "/send-verification-email"),
    (PluginHttpMethod::Get, "/verify-email"),
    (PluginHttpMethod::Post, "/sign-out"),
    (PluginHttpMethod::Post, "/sign-in/anonymous"),
    (PluginHttpMethod::Post, "/update-user"),
    (PluginHttpMethod::Post, "/delete-user"),
    (PluginHttpMethod::Get, "/delete-user/callback"),
    (PluginHttpMethod::Post, "/change-password"),
    (PluginHttpMethod::Get, "/list-sessions"),
    (PluginHttpMethod::Post, "/revoke-session"),
    (PluginHttpMethod::Post, "/revoke-other-sessions"),
    (PluginHttpMethod::Post, "/revoke-sessions"),
];
