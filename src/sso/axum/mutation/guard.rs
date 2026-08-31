use crate::{AuthError, AuthService, SsoPlugin, SsoProvider, SsoProviderUpdate};

pub(super) async fn update(
    service: &AuthService,
    plugin: &SsoPlugin,
    accepted: &SsoProvider,
    update: SsoProviderUpdate,
    identity_boundary_changed: bool,
) -> Result<SsoProvider, AuthError> {
    let store = service.database_store();
    let plugin = plugin.clone();
    let accepted = accepted.clone();
    crate::run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let provider = current(&plugin, &accepted).await?;
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
    let plugin = plugin.clone();
    let accepted = accepted.clone();
    crate::run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let provider = current(&plugin, &accepted).await?;
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
