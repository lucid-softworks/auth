use crate::{
    AuthService,
    scim::{
        ScimError, ScimErrorType, ScimPlugin, ScimUser,
        plugin::{ScimPrincipal, store_error},
        store::StoredScimUser,
    },
};
use chrono::{DateTime, Utc};
use std::sync::Arc;

pub(super) async fn create(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    principal: ScimPrincipal,
    resource: ScimUser,
    now: DateTime<Utc>,
) -> Result<StoredScimUser, ScimError> {
    let transaction_backed = plugin.store.backing_auth_store().is_some();
    let operation_service = service.clone();
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            Box::pin(async move {
                let auth_user = operation_service
                    .scim_create_user(
                        resource.primary_email().to_owned(),
                        resource.display_name.clone().unwrap_or_default(),
                    )
                    .await
                    .map_err(create_auth_error)?;
                let stored = StoredScimUser {
                    resource,
                    connection_id: principal.connection_id,
                    provisioning_domain_id: principal.provisioning_domain_id,
                    user_id: auth_user.id.clone(),
                    profile_managed: true,
                    created_at: now,
                    updated_at: now,
                };
                match operation_plugin.store.create_user(stored).await {
                    Ok(stored) => Ok(stored),
                    Err(error) => {
                        if !transaction_backed {
                            operation_service.scim_rollback_created_user(&auth_user).await;
                        }
                        Err(store_error(error))
                    }
                }
            })
        })
        .await
}

pub(super) async fn replace(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    user_id: String,
    resource: ScimUser,
) -> Result<StoredScimUser, ScimError> {
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            Box::pin(async move {
                let existing = operation_plugin
                    .store
                    .find_user(&connection_id, &user_id)
                    .await
                    .map_err(store_error)?
                    .ok_or_else(|| ScimError::new(404, "User not found"))?;
                let old_email = existing.resource.primary_email().to_owned();
                let new_email = resource.primary_email().to_owned();
                let new_name = resource.display_name.clone().unwrap_or_default();
                let active_changed_to_false = existing.resource.active && !resource.active;
                let stored = operation_plugin
                    .store
                    .replace_user(
                        &connection_id,
                        &user_id,
                        resource,
                        super::super::super::timestamp::now(),
                    )
                    .await
                    .map_err(store_error)?;
                if stored.profile_managed {
                    service
                        .scim_update_user_profile(&stored.user_id, new_name, &old_email, new_email)
                        .await
                        .map_err(reconciliation_error)?;
                }
                if active_changed_to_false {
                    service
                        .scim_revoke_user_sessions(&stored.user_id)
                        .await
                        .map_err(reconciliation_error)?;
                }
                Ok(stored)
            })
        })
        .await
}

pub(super) async fn delete(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    user_id: String,
) -> Result<(), ScimError> {
    let operation_plugin = plugin.clone();
    plugin
        .run_mutation(move || {
            Box::pin(async move {
                let user = operation_plugin
                    .store
                    .delete_user(
                        &connection_id,
                        &user_id,
                        super::super::super::timestamp::now(),
                    )
                    .await
                    .map_err(store_error)?
                    .ok_or_else(|| ScimError::new(404, "User not found"))?;
                service
                    .scim_revoke_user_sessions(&user.user_id)
                    .await
                    .map_err(reconciliation_error)
            })
        })
        .await
}

fn create_auth_error(error: crate::AuthError) -> ScimError {
    ScimError::typed(409, error.to_string(), ScimErrorType::Uniqueness)
}

fn reconciliation_error(error: crate::AuthError) -> ScimError {
    match error {
        crate::AuthError::UserAlreadyExists | crate::AuthError::UserAlreadyExistsEmail => {
            ScimError::typed(409, error.to_string(), ScimErrorType::Uniqueness)
        }
        _ => ScimError::new(500, format!("SCIM User reconciliation failed: {error}")),
    }
}
