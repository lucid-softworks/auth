use super::{DescriptorMap, client_metadata, provenance};
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginDescriptor, PluginHttpMethod, PluginMigration,
};
use std::collections::HashMap;

use super::CORE_ENDPOINTS;

pub(super) fn validate_descriptor(descriptor: &PluginDescriptor) -> Result<(), AuthError> {
    if !valid_id(descriptor.id) {
        return invalid(format!("plugin id '{}' is invalid", descriptor.id));
    }
    if descriptor.display_name.trim().is_empty() || descriptor.version.trim().is_empty() {
        return invalid(format!(
            "plugin '{}' requires a display name and version",
            descriptor.id
        ));
    }
    provenance::validate(descriptor).map_err(AuthError::InvalidConfiguration)?;
    if let Some(client) = descriptor.client {
        client_metadata::validate(client, descriptor.id)
            .map_err(AuthError::InvalidConfiguration)?;
    }
    Ok(())
}

pub(super) fn validate_relationships(by_id: &DescriptorMap) -> Result<(), AuthError> {
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

pub(super) fn validate_contributions(
    by_id: &DescriptorMap,
    config: &AuthConfig,
) -> Result<(), AuthError> {
    let mut endpoint_methods: HashMap<(PluginHttpMethod, String), &'static str> = CORE_ENDPOINTS
        .iter()
        .map(|(method, path, _)| ((*method, (*path).to_owned()), "core"))
        .collect();
    let mut endpoint_paths: HashMap<String, &'static str> = CORE_ENDPOINTS
        .iter()
        .map(|(_, path, _)| ((*path).to_owned(), "core"))
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

pub(super) fn validate_runtime_rate_limits(
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

pub(super) fn validate_migrations(
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

pub(super) fn dependency_order(by_id: &DescriptorMap) -> Result<Vec<&'static str>, AuthError> {
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
