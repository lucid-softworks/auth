use crate::scim::{
    ScimError, ScimGroup, ScimPlugin, plugin::store_error, projection, store::StoredScimGroup,
};
use std::{collections::BTreeSet, sync::Arc};

pub(super) async fn create(
    plugin: Arc<ScimPlugin>,
    group: StoredScimGroup,
) -> Result<StoredScimGroup, ScimError> {
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            let operation_plugin = operation_plugin.clone();
            let group = group.clone();
            Box::pin(async move {
                let stored = operation_plugin
                    .store
                    .create_group(group)
                    .await
                    .map_err(store_error)?;
                reconcile_members(
                    &operation_plugin,
                    &stored.provisioning_domain_id,
                    stored
                        .resource
                        .members
                        .iter()
                        .map(|member| member.value.clone())
                        .collect(),
                )
                .await?;
                Ok(stored)
            })
        })
        .await
}

pub(super) async fn replace(
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    group_id: String,
    resource: ScimGroup,
) -> Result<StoredScimGroup, ScimError> {
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            let operation_plugin = operation_plugin.clone();
            let connection_id = connection_id.clone();
            let group_id = group_id.clone();
            let resource = resource.clone();
            Box::pin(async move {
                let existing = operation_plugin
                    .store
                    .find_group(&connection_id, &group_id)
                    .await
                    .map_err(store_error)?
                    .ok_or_else(|| ScimError::new(404, "Group not found"))?;
                let mut affected = member_ids(&existing.resource);
                affected.extend(member_ids(&resource));
                let stored = operation_plugin
                    .store
                    .replace_group(
                        &connection_id,
                        &group_id,
                        resource,
                        super::super::super::timestamp::now(),
                    )
                    .await
                    .map_err(store_error)?;
                reconcile_members(
                    &operation_plugin,
                    &stored.provisioning_domain_id,
                    affected,
                )
                .await?;
                Ok(stored)
            })
        })
        .await
}

pub(super) async fn delete(
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    provisioning_domain_id: String,
    group_id: String,
) -> Result<Option<StoredScimGroup>, ScimError> {
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            let operation_plugin = operation_plugin.clone();
            let connection_id = connection_id.clone();
            let provisioning_domain_id = provisioning_domain_id.clone();
            let group_id = group_id.clone();
            Box::pin(async move {
                let existing = operation_plugin
                    .store
                    .find_group(&connection_id, &group_id)
                    .await
                    .map_err(store_error)?;
                let Some(existing) = existing else {
                    return Ok(None);
                };
                let affected = member_ids(&existing.resource);
                let deleted = operation_plugin
                    .store
                    .delete_group(&connection_id, &group_id)
                    .await
                    .map_err(store_error)?;
                reconcile_members(&operation_plugin, &provisioning_domain_id, affected).await?;
                Ok(deleted)
            })
        })
        .await
}

async fn reconcile_members(
    plugin: &ScimPlugin,
    provisioning_domain_id: &str,
    scim_user_ids: BTreeSet<String>,
) -> Result<(), ScimError> {
    let Some(transaction) = crate::database_hooks::current_transaction() else {
        return Ok(());
    };
    projection::reconcile_scim_users(
        &plugin.options,
        transaction,
        provisioning_domain_id,
        &scim_user_ids.into_iter().collect::<Vec<_>>(),
    )
    .await
}

fn member_ids(group: &ScimGroup) -> BTreeSet<String> {
    group
        .members
        .iter()
        .map(|member| member.value.clone())
        .collect()
}
