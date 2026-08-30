use crate::{
    AuthService,
    scim::{
        ScimError, ScimErrorType, ScimIdentityProfile, ScimIdentityResolution, ScimPlugin,
        ScimUser, identity, projection,
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
            let operation_service = operation_service.clone();
            let operation_plugin = operation_plugin.clone();
            Box::pin(create_inner(
                operation_service,
                operation_plugin,
                principal.clone(),
                resource.clone(),
                now,
                transaction_backed,
            ))
        })
        .await
}

async fn create_inner(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    principal: ScimPrincipal,
    resource: ScimUser,
    now: DateTime<Utc>,
    transaction_backed: bool,
) -> Result<StoredScimUser, ScimError> {
    let resolved = resolve_identity(&plugin, &principal, &resource).await?;
    let (auth_user, profile_managed) =
        resolve_auth_user(&service, &resource, &resolved.resolution).await?;
    let stored = StoredScimUser {
        resource,
        connection_id: principal.connection_id,
        provisioning_domain_id: principal.provisioning_domain_id,
        user_id: auth_user.id.clone(),
        profile_managed,
        created_at: now,
        updated_at: now,
    };
    let stored = match plugin.store.create_user(stored).await {
        Ok(stored) => stored,
        Err(error) => {
            if !transaction_backed {
                service.scim_rollback_created_user(&auth_user).await;
            }
            return Err(store_error(error));
        }
    };
    finish_identity_create(&service, &plugin, &auth_user, &stored, resolved).await?;
    Ok(stored)
}

async fn resolve_identity(
    plugin: &ScimPlugin,
    principal: &ScimPrincipal,
    resource: &ScimUser,
) -> Result<identity::ResolvedIdentity, ScimError> {
    let Some(transaction) = crate::database_hooks::current_transaction() else {
        return Ok(identity::ResolvedIdentity {
            resolution: ScimIdentityResolution::Create,
            tombstone_id: None,
        });
    };
    identity::resolve(
        &plugin.options,
        transaction,
        &principal.connection_id,
        &principal.provisioning_domain_id,
        resource,
    )
    .await
}

async fn resolve_auth_user(
    service: &AuthService,
    resource: &ScimUser,
    resolution: &ScimIdentityResolution,
) -> Result<(crate::AuthUser, bool), ScimError> {
    match resolution {
        ScimIdentityResolution::Create => Ok((
            service
                .scim_create_user(
                    resource.primary_email().to_owned(),
                    resource.display_name.clone().unwrap_or_default(),
                )
                .await
                .map_err(create_auth_error)?,
            true,
        )),
        ScimIdentityResolution::Link { user_id, profile } => Ok((
            identity::linked_user(
                &crate::database_hooks::current_transaction().ok_or_else(|| {
                    ScimError::new(500, "SCIM identity transaction is unavailable")
                })?,
                user_id,
            )
            .await?,
            *profile == ScimIdentityProfile::Manage,
        )),
    }
}

async fn finish_identity_create(
    service: &AuthService,
    plugin: &ScimPlugin,
    auth_user: &crate::AuthUser,
    stored: &StoredScimUser,
    resolved: identity::ResolvedIdentity,
) -> Result<(), ScimError> {
    if matches!(
        resolved.resolution,
        ScimIdentityResolution::Link {
            profile: ScimIdentityProfile::Manage,
            ..
        }
    ) {
        service
            .scim_update_user_profile(
                &stored.user_id,
                stored.resource.display_name.clone().unwrap_or_default(),
                &auth_user.email,
                stored.resource.primary_email().to_owned(),
            )
            .await
            .map_err(reconciliation_error)?;
    }
    if let Some(transaction) = crate::database_hooks::current_transaction() {
        identity::consume_tombstone(&transaction, resolved.tombstone_id.as_deref()).await?;
        reconcile_identity(
            service,
            plugin,
            transaction,
            &stored.provisioning_domain_id,
            &stored.user_id,
        )
        .await?;
    }
    Ok(())
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
            let operation_plugin = operation_plugin.clone();
            let service = service.clone();
            let connection_id = connection_id.clone();
            let user_id = user_id.clone();
            let resource = resource.clone();
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
                    if let Some(transaction) = crate::database_hooks::current_transaction() {
                        reconcile_identity(
                            &service,
                            &operation_plugin,
                            transaction,
                            &stored.provisioning_domain_id,
                            &stored.user_id,
                        )
                        .await?;
                    } else {
                        service
                            .scim_revoke_user_sessions(&stored.user_id)
                            .await
                            .map_err(reconciliation_error)?;
                    }
                } else if let Some(transaction) = crate::database_hooks::current_transaction() {
                    reconcile_identity(
                        &service,
                        &operation_plugin,
                        transaction,
                        &stored.provisioning_domain_id,
                        &stored.user_id,
                    )
                    .await?;
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
            let operation_plugin = operation_plugin.clone();
            let service = service.clone();
            let connection_id = connection_id.clone();
            let user_id = user_id.clone();
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
                if let Some(transaction) = crate::database_hooks::current_transaction() {
                    reconcile_identity(
                        &service,
                        &operation_plugin,
                        transaction,
                        &user.provisioning_domain_id,
                        &user.user_id,
                    )
                    .await
                } else {
                    service
                        .scim_revoke_user_sessions(&user.user_id)
                        .await
                        .map_err(reconciliation_error)
                }
            })
        })
        .await
}

async fn reconcile_identity(
    service: &AuthService,
    plugin: &ScimPlugin,
    transaction: Arc<dyn crate::DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
) -> Result<(), ScimError> {
    projection::reconcile_user(
        &plugin.options,
        transaction.clone(),
        provisioning_domain_id,
        user_id,
        false,
    )
    .await?;
    let state = identity::state(&plugin.options, transaction, user_id).await?;
    if !state.active {
        service
            .scim_revoke_user_sessions(user_id)
            .await
            .map_err(reconciliation_error)?;
    }
    Ok(())
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
