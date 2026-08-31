use crate::{AuthError, AuthService, SsoPlugin, SsoProvider, SsoProviderUpdate};

pub(crate) async fn update(
    service: &AuthService,
    plugin: &SsoPlugin,
    accepted: &SsoProvider,
    update: SsoProviderUpdate,
    identity_boundary_changed: bool,
) -> Result<SsoProvider, AuthError> {
    let store = service.database_store();
    let service = service.clone();
    let plugin = plugin.clone();
    let accepted = accepted.clone();
    crate::run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let provider = current(&plugin, &accepted).await?;
            guard_directory_pairing(
                &service,
                transaction.clone(),
                &provider,
                identity_boundary_changed,
            )
            .await?;
            if plugin.has_provider_mutation_guard() {
                plugin
                    .guard_provider_mutation(
                        crate::SsoProviderMutationGuardInput::Update {
                            provider: summary(&provider),
                            provider_reference: super::super::super::provider_reference::current(
                                &provider,
                            ),
                            is_authentication_boundary_change: identity_boundary_changed,
                        },
                        transaction,
                    )
                    .await?;
            }
            plugin
                .store()
                .update_guarded(
                    &provider.id,
                    &provider.provider_id,
                    update,
                    identity_boundary_changed,
                )
                .await
                .map_err(AuthError::from)
        })
    })
    .await
}

pub(crate) async fn delete(
    service: &AuthService,
    plugin: &SsoPlugin,
    accepted: &SsoProvider,
) -> Result<bool, AuthError> {
    let store = service.database_store();
    let service = service.clone();
    let plugin = plugin.clone();
    let accepted = accepted.clone();
    crate::run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let provider = current(&plugin, &accepted).await?;
            guard_directory_pairing(&service, transaction.clone(), &provider, true).await?;
            if plugin.has_provider_mutation_guard() {
                plugin
                    .guard_provider_mutation(
                        crate::SsoProviderMutationGuardInput::Delete {
                            provider: summary(&provider),
                            provider_reference: super::super::super::provider_reference::current(
                                &provider,
                            ),
                        },
                        transaction,
                    )
                    .await?;
            }
            plugin
                .store()
                .delete_with_accounts(&provider.id, &provider.provider_id)
                .await
                .map_err(AuthError::from)
        })
    })
    .await
}

async fn guard_directory_pairing(
    service: &AuthService,
    database: std::sync::Arc<dyn crate::DatabaseTransaction>,
    provider: &SsoProvider,
    boundary_change: bool,
) -> Result<(), AuthError> {
    if !boundary_change
        || !service
            .plugins()
            .find::<crate::DashPlugin>()
            .is_some_and(|dash| {
                dash.options().managed_directory_sync.enabled
                    && dash.options().managed_directory_sync.sso_pairing
            })
    {
        return Ok(());
    }
    let equal = |field: &str, value: serde_json::Value| crate::DashAdapterWhere {
        field: field.into(),
        value,
        operator: crate::DashAdapterOperator::Eq,
        connector: None,
    };
    let paired = database
        .find_records(
            "directorySyncConnection",
            &[
                equal("ssoProviderRecordId", serde_json::json!(provider.id)),
                equal("ssoProviderId", serde_json::json!(provider.provider_id)),
                equal("organizationId", serde_json::json!(provider.organization_id)),
                equal("pairingEnforced", serde_json::json!(true)),
            ],
            Some(1),
            0,
            None,
            &[],
        )
        .await?;
    if paired.is_empty() {
        Ok(())
    } else {
        Err(AuthError::SsoProviderMutationRejected)
    }
}

async fn current(plugin: &SsoPlugin, accepted: &SsoProvider) -> Result<SsoProvider, AuthError> {
    let current = plugin
        .store()
        .find_by_id(&accepted.id)
        .await
        .map_err(AuthError::from)?
        .ok_or(crate::SsoStoreError::NotFound)?;
    let accepted_reference = super::super::super::provider_reference::current(accepted);
    if current.provider_id != accepted.provider_id || !accepted_reference.is_current(&current) {
        return Err(crate::SsoStoreError::NotFound.into());
    }
    Ok(current)
}

fn summary(provider: &SsoProvider) -> crate::SsoMutationProvider {
    crate::SsoMutationProvider {
        id: provider.id.clone(),
        provider_id: provider.provider_id.clone(),
        organization_id: provider.organization_id.clone(),
    }
}
