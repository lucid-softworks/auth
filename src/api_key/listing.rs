use super::{ApiKeyConfiguration, ApiKeyReference, config_ids_match, http_input};
use crate::{ApiKey, ApiKeySortDirection, AuthError, AuthService, SessionWithUser};
use std::collections::HashSet;
use uuid::Uuid;

pub(super) async fn list_records(
    service: &AuthService,
    actor: &SessionWithUser,
    configurations: &[ApiKeyConfiguration],
    requested_config_id: Option<&str>,
    sort_by: Option<&str>,
    direction: ApiKeySortDirection,
    organization_id: Option<Uuid>,
) -> Result<Vec<ApiKey>, AuthError> {
    let mut records = if requested_config_id.is_some_and(|id| !id.is_empty()) {
        let config = http_input::resolve_configuration(configurations, requested_config_id)?;
        list_storage_group(
            service,
            actor,
            config,
            None,
            sort_by,
            direction,
            organization_id,
        )
        .await?
    } else {
        list_all_storage_groups(
            service,
            actor,
            configurations,
            sort_by,
            direction,
            organization_id,
        )
        .await?
    };
    let expected_reference = if organization_id.is_some() {
        ApiKeyReference::Organization
    } else {
        ApiKeyReference::User
    };
    records.retain(|key| {
        configurations
            .iter()
            .find(|config| config_ids_match(&key.config_id, &config.config_id))
            .is_some_and(|config| config.reference == expected_reference)
            && requested_config_id
                .filter(|id| !id.is_empty())
                .is_none_or(|id| config_ids_match(&key.config_id, id))
    });
    service.schedule_api_key_cleanup();
    Ok(records)
}

async fn list_all_storage_groups(
    service: &AuthService,
    actor: &SessionWithUser,
    configurations: &[ApiKeyConfiguration],
    sort_by: Option<&str>,
    direction: ApiKeySortDirection,
    organization_id: Option<Uuid>,
) -> Result<Vec<ApiKey>, AuthError> {
    let mut storage_groups = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut records = Vec::new();
    for config in configurations {
        if !storage_groups.insert(storage_identifier(config)) {
            continue;
        }
        let group = list_storage_group(
            service,
            actor,
            config,
            None,
            sort_by,
            direction,
            organization_id,
        )
        .await?;
        records.extend(
            group
                .into_iter()
                .filter(|key| seen_ids.insert(key.id.clone())),
        );
    }
    Ok(records)
}

async fn list_storage_group(
    service: &AuthService,
    actor: &SessionWithUser,
    config: &ApiKeyConfiguration,
    config_id: Option<&str>,
    sort_by: Option<&str>,
    direction: ApiKeySortDirection,
    organization_id: Option<Uuid>,
) -> Result<Vec<ApiKey>, AuthError> {
    match organization_id {
        Some(organization_id) => {
            service
                .list_organization_api_keys(
                    actor,
                    config,
                    config_id,
                    sort_by,
                    direction,
                    organization_id,
                )
                .await
        }
        None => {
            service
                .list_api_keys(actor, config, config_id, sort_by, direction)
                .await
        }
    }
}

fn storage_identifier(config: &ApiKeyConfiguration) -> String {
    if config.storage == super::ApiKeyStorage::Database {
        return "database".into();
    }
    if config.custom_storage.is_some() {
        return format!("custom:{}", config.config_id);
    }
    if config.fallback_to_database {
        "secondary-storage-with-fallback".into()
    } else {
        "secondary-storage".into()
    }
}
