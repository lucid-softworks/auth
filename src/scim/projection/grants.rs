use super::{
    ScimAuthorizationSource, ScimError, ScimIdentitySource, ScimOptions, ScimProjectedRoleGrant,
    ScimRoleExistenceInput, ScimRoleMappingInput, ScimRoleProjection, ScimTransactionContext,
    query,
};
use crate::DatabaseTransaction;
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::{collections::HashMap, sync::Arc};

pub(super) struct DesiredGrant {
    key: String,
    connection_id: String,
    scim_user_id: String,
    source: ScimAuthorizationSource,
    role: String,
}

pub(super) fn projected(grant: &DesiredGrant) -> ScimProjectedRoleGrant {
    ScimProjectedRoleGrant {
        source: grant.source.clone(),
        role: grant.role.clone(),
    }
}

pub(super) fn sort_key(grant: &ScimProjectedRoleGrant) -> (&str, &str) {
    let ScimAuthorizationSource::Group { id, .. } = &grant.source;
    (id, &grant.role)
}

pub(super) async fn desired(
    options: &ScimOptions,
    transaction: Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    sources: &[ScimIdentitySource],
) -> Result<Vec<DesiredGrant>, ScimError> {
    let Some(roles) = options.projection.as_ref().and_then(|value| value.roles()) else {
        return Ok(Vec::new());
    };
    let mut desired = HashMap::new();
    let mut existence = HashMap::new();
    for source in sources.iter().filter(|source| source.active) {
        let memberships = transaction
            .find_records(
                "scimGroupMember",
                &[query::equal("scimUserId", json!(source.id))],
                None,
                0,
                None,
                &[],
            )
            .await
            .map_err(query::database_error)?;
        for membership in memberships {
            map_membership(
                roles,
                &transaction,
                provisioning_domain_id,
                user_id,
                source,
                &membership,
                &mut existence,
                &mut desired,
            )
            .await?;
        }
    }
    Ok(desired.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
async fn map_membership(
    roles: &dyn ScimRoleProjection,
    transaction: &Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    scim_user: &ScimIdentitySource,
    membership: &Map<String, Value>,
    existence: &mut HashMap<(String, String), bool>,
    desired: &mut HashMap<String, DesiredGrant>,
) -> Result<(), ScimError> {
    let group_id = query::string(membership, "groupId")?;
    let Some(group) = query::find_one(
        transaction,
        "scimGroup",
        &[query::equal("id", json!(group_id))],
    )
    .await?
    else {
        return Ok(());
    };
    if query::string(&group, "connectionId")? != scim_user.connection_id
        || query::string(&group, "provisioningDomainId")? != provisioning_domain_id
    {
        return Ok(());
    }
    let source = ScimAuthorizationSource::Group {
        id: group_id,
        external_id: query::optional_string(&group, "externalId")?,
        display_name: query::string(&group, "displayName")?,
    };
    let mapped = roles
        .map(
            ScimRoleMappingInput {
                connection_id: scim_user.connection_id.clone(),
                provisioning_domain_id: provisioning_domain_id.into(),
                scim_user_id: scim_user.id.clone(),
                user_id: user_id.into(),
                source: source.clone(),
            },
            ScimTransactionContext {
                database: transaction.clone(),
            },
        )
        .await?
        .unwrap_or_default();
    let mut normalized = Vec::new();
    for role in mapped {
        let role = role.trim().to_owned();
        if !role.is_empty() && !normalized.contains(&role) {
            normalized.push(role);
        }
    }
    for role in normalized {
        add_grant(
            roles,
            transaction,
            provisioning_domain_id,
            scim_user,
            source.clone(),
            role,
            existence,
            desired,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn add_grant(
    roles: &dyn ScimRoleProjection,
    transaction: &Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    scim_user: &ScimIdentitySource,
    source: ScimAuthorizationSource,
    role: String,
    existence: &mut HashMap<(String, String), bool>,
    desired: &mut HashMap<String, DesiredGrant>,
) -> Result<(), ScimError> {
    let cache_key = (scim_user.connection_id.clone(), role.clone());
    let exists = if let Some(exists) = existence.get(&cache_key) {
        *exists
    } else {
        let exists = roles
            .exists(
                ScimRoleExistenceInput {
                    connection_id: scim_user.connection_id.clone(),
                    provisioning_domain_id: provisioning_domain_id.into(),
                    role: role.clone(),
                },
                ScimTransactionContext {
                    database: transaction.clone(),
                },
            )
            .await?;
        existence.insert(cache_key, exists);
        exists
    };
    if !exists {
        return Ok(());
    }
    let ScimAuthorizationSource::Group { id: source_id, .. } = &source;
    let key = super::super::database::keys::projection_grant(
        &scim_user.connection_id,
        &scim_user.id,
        "group",
        source_id,
        &role,
    );
    desired.insert(
        key.clone(),
        DesiredGrant {
            key,
            connection_id: scim_user.connection_id.clone(),
            scim_user_id: scim_user.id.clone(),
            source,
            role,
        },
    );
    Ok(())
}

pub(super) async fn sync(
    transaction: &Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    desired: &[DesiredGrant],
) -> Result<(), ScimError> {
    let existing = transaction
        .find_records(
            "scimProjectionGrant",
            &[
                query::equal("provisioningDomainId", json!(provisioning_domain_id)),
                query::equal("userId", json!(user_id)),
            ],
            None,
            0,
            None,
            &[],
        )
        .await
        .map_err(query::database_error)?;
    let desired_by_key = desired
        .iter()
        .map(|grant| (grant.key.as_str(), grant))
        .collect::<HashMap<_, _>>();
    let existing_by_key = existing
        .iter()
        .filter_map(|record| {
            record
                .get("grantKey")
                .and_then(Value::as_str)
                .map(|key| (key, record))
        })
        .collect::<HashMap<_, _>>();
    for (key, record) in &existing_by_key {
        if !desired_by_key.contains_key(key) {
            transaction
                .delete_records(
                    "scimProjectionGrant",
                    &[query::equal("id", record["id"].clone())],
                )
                .await
                .map_err(query::database_error)?;
        }
    }
    create_missing(
        transaction,
        provisioning_domain_id,
        user_id,
        desired,
        &existing_by_key,
    )
    .await
}

async fn create_missing(
    transaction: &Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    desired: &[DesiredGrant],
    existing: &HashMap<&str, &Map<String, Value>>,
) -> Result<(), ScimError> {
    let now = Utc::now().to_rfc3339();
    for grant in desired {
        if existing.contains_key(grant.key.as_str()) {
            continue;
        }
        let ScimAuthorizationSource::Group {
            id: source_id,
            external_id,
            display_name,
        } = &grant.source;
        transaction
            .create_record(
                "scimProjectionGrant",
                query::object(json!({
                    "id": super::super::random_urlsafe(32),
                    "connectionId": grant.connection_id,
                    "provisioningDomainId": provisioning_domain_id,
                    "scimUserId": grant.scim_user_id,
                    "userId": user_id,
                    "sourceKind": "group",
                    "sourceId": source_id,
                    "sourceValue": external_id.as_ref().unwrap_or(display_name),
                    "role": grant.role,
                    "grantKey": grant.key,
                    "createdAt": now,
                    "updatedAt": now,
                })),
            )
            .await
            .map_err(query::database_error)?;
    }
    Ok(())
}
