use crate::{Organization, StripePlugin};

pub(super) async fn sync(plugin: &StripePlugin, organization: &Organization) {
    let result = async {
        let Some(customer_id) = plugin
            .store
            .organization_customer_id(organization.id)
            .await?
        else {
            return Ok::<(), NameSyncError>(());
        };
        let customer = plugin
            .options
            .client
            .retrieve_customer(&customer_id)
            .await?;
        if customer.deleted {
            tracing::warn!("Stripe customer {customer_id} was deleted");
            return Ok(());
        }
        if customer.name.as_deref() != Some(organization.name.as_str()) {
            plugin
                .options
                .client
                .update_customer(
                    &customer_id,
                    serde_json::json!({ "name": organization.name }),
                )
                .await?;
            tracing::info!(
                "Synced organization name to Stripe: \"{}\" → \"{}\"",
                customer.name.as_deref().unwrap_or(""),
                organization.name
            );
        }
        Ok(())
    }
    .await;

    if let Err(error) = result {
        tracing::error!("Failed to sync organization to Stripe: {error}");
    }
}

#[derive(Debug, thiserror::Error)]
enum NameSyncError {
    #[error(transparent)]
    Store(#[from] crate::StripeStoreError),
    #[error(transparent)]
    Provider(#[from] crate::StripeProviderError),
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{TestStripeClient, organization, plugin};
    use crate::{MemoryStripeStore, StripeCustomer, StripeStore};
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn updates_only_a_live_changed_customer() {
        let client = Arc::new(TestStripeClient::new());
        *client.customer.lock().unwrap() = Some(StripeCustomer {
            id: "cus_org".into(),
            deleted: false,
            email: None,
            name: Some("Old name".into()),
            metadata: Default::default(),
            extra: Default::default(),
        });
        let store = Arc::new(MemoryStripeStore::new());
        let organization = organization();
        store
            .set_organization_customer_id(organization.id, Some("cus_org".into()))
            .await
            .unwrap();
        plugin(client.clone(), store, false)
            .after_organization_update(&organization)
            .await;
        assert_eq!(
            client.customer_updates.lock().unwrap().as_slice(),
            &[json!({ "name": "New name" })]
        );
    }
}
