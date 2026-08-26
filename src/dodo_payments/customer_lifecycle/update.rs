use super::{enabled, support};
use crate::{AuthUser, DatabaseHookContext};

pub(super) async fn after(
    plugin: &super::super::DodoPaymentsPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    if !enabled(plugin, context) {
        return;
    }

    let result = async {
        let customer_id = match support::stored_customer_id(user) {
            Some(customer_id) => customer_id.to_owned(),
            None => {
                let customers = support::CustomerLifecycleClient::list_by_email(
                    plugin.options.client.as_ref(),
                    &user.email,
                )
                .await?;
                let Some(customer) = customers.items.into_iter().next() else {
                    return Ok::<(), UpdateError>(());
                };
                support::schedule_customer_id_write(
                    context,
                    plugin.auth_store.clone(),
                    user.id.clone(),
                    customer.customer_id.clone(),
                    "backfill",
                );
                customer.customer_id
            }
        };
        let params = support::customer_params(plugin, user).await?;
        support::CustomerLifecycleClient::update(
            plugin.options.client.as_ref(),
            &customer_id,
            support::update_request(user, params),
        )
        .await?;
        Ok(())
    }
    .await;

    if let Err(error) = result {
        tracing::error!("DodoPayments customer update failed. Error: {error}");
    }
}

#[derive(Debug, thiserror::Error)]
enum UpdateError {
    #[error(transparent)]
    Provider(#[from] super::super::DodoPaymentsProviderError),
    #[error(transparent)]
    Callback(#[from] super::super::DodoPaymentsCallbackError),
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{FakeCustomerClient, context, plugin, plugin_with_options};
    use super::*;
    use crate::{
        DodoCustomer, DodoCustomerParams, DodoCustomerParamsProvider, DodoPaymentsCallbackError,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::{collections::BTreeMap, sync::Arc};

    struct Params(Result<DodoCustomerParams, DodoPaymentsCallbackError>);

    #[async_trait]
    impl DodoCustomerParamsProvider for Params {
        async fn params(
            &self,
            _user: &crate::DodoUser,
        ) -> Result<DodoCustomerParams, DodoPaymentsCallbackError> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn stored_customer_id_avoids_lookup() {
        let client = FakeCustomerClient::shared();
        let (plugin, mut user) = plugin(client.clone()).await;
        user.additional_fields
            .insert("dodoCustomerId".into(), json!("customer_stored"));
        after(&plugin, &user, &context()).await;
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["update:customer_stored"]
        );
    }

    #[tokio::test]
    async fn lookup_backfills_first_customer_and_missing_customer_returns() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin(client.clone()).await;
        after(&plugin, &user, &context()).await;
        assert_eq!(client.calls.lock().unwrap().as_slice(), ["list"]);

        client.calls.lock().unwrap().clear();
        client.customers.lock().unwrap().push(DodoCustomer {
            customer_id: "customer_first".into(),
            value: json!({"customer_id":"customer_first"}),
        });
        after(&plugin, &user, &context()).await;
        tokio::task::yield_now().await;
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["list", "update:customer_first"]
        );
        assert_eq!(
            plugin
                .auth_store
                .find_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .additional_fields["dodoCustomerId"],
            "customer_first"
        );
    }

    #[tokio::test]
    async fn provider_failures_are_swallowed() {
        let client = FakeCustomerClient::shared();
        *client.error.lock().unwrap() = Some("offline".into());
        let (plugin, user) = plugin(client).await;
        after(&plugin, &user, &context()).await;
    }

    #[tokio::test]
    async fn disabled_flag_and_missing_request_context_skip_the_provider() {
        let client = FakeCustomerClient::shared();
        let (disabled_plugin, user) = plugin_with_options(client.clone(), false, None).await;
        after(&disabled_plugin, &user, &context()).await;

        let (enabled_plugin, user) = plugin(client.clone()).await;
        after(&enabled_plugin, &user, &DatabaseHookContext::default()).await;

        assert!(client.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn callback_values_are_forwarded_and_callback_failures_are_swallowed() {
        let client = FakeCustomerClient::shared();
        let params = DodoCustomerParams {
            metadata: Some(BTreeMap::from([("tier".into(), "enterprise".into())])),
            phone_number: Some(None),
        };
        let (plugin, mut user) =
            plugin_with_options(client.clone(), true, Some(Arc::new(Params(Ok(params))))).await;
        user.additional_fields
            .insert("dodoCustomerId".into(), json!("customer_stored"));
        after(&plugin, &user, &context()).await;

        {
            let requests = client.update_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].metadata,
                Some(Some(BTreeMap::from([("tier".into(), "enterprise".into())])))
            );
            assert_eq!(requests[0].phone_number, Some(None));
        }

        let failing = FakeCustomerClient::shared();
        let (plugin, mut user) = plugin_with_options(
            failing.clone(),
            true,
            Some(Arc::new(Params(Err(DodoPaymentsCallbackError::new(
                "customer callback unavailable",
            ))))),
        )
        .await;
        user.additional_fields
            .insert("dodoCustomerId".into(), json!("customer_stored"));
        after(&plugin, &user, &context()).await;
        assert!(failing.calls.lock().unwrap().is_empty());
        assert!(failing.update_requests.lock().unwrap().is_empty());
    }
}
