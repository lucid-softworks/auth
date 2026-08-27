use super::{enabled, support};
use crate::{AuthError, AuthUser, DatabaseHookContext, PluginApiError};

pub(super) async fn after(
    plugin: &super::super::DodoPaymentsPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !enabled(plugin, context) {
        return Ok(());
    }

    let result = async {
        let customers = support::CustomerLifecycleClient::list_by_email(
            plugin.options.client.as_ref(),
            &user.email,
        )
        .await
        .map_err(|error| error.to_string())?;
        let params = support::customer_params(plugin, user)
            .await
            .map_err(|error| error.to_string())?;
        let customer_id = match customers.items.into_iter().next() {
            Some(customer) => {
                support::CustomerLifecycleClient::update(
                    plugin.options.client.as_ref(),
                    &customer.customer_id,
                    support::update_request(user, params),
                )
                .await
                .map_err(|error| error.to_string())?;
                customer.customer_id
            }
            None => {
                let customer = support::CustomerLifecycleClient::create(
                    plugin.options.client.as_ref(),
                    super::super::DodoCustomerCreateRequest {
                        email: user.email.clone(),
                        name: user.name.clone(),
                        metadata: params.metadata,
                        phone_number: params.phone_number,
                    },
                    &user.id.to_string(),
                )
                .await
                .map_err(|error| error.to_string())?;
                customer.customer_id
            }
        };
        support::schedule_customer_id_write(
            context,
            plugin.auth_store.clone(),
            user.id.clone(),
            customer_id,
            "store",
        );
        Ok::<(), String>(())
    }
    .await;

    result.map_err(|error| {
        PluginApiError::new(
            500,
            "INTERNAL_SERVER_ERROR",
            format!("DodoPayments customer creation failed. Error: {error}"),
        )
        .into()
    })
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
    async fn existing_customer_is_updated_then_linked() {
        let client = FakeCustomerClient::shared();
        client.customers.lock().unwrap().push(DodoCustomer {
            customer_id: "customer_first".into(),
            value: json!({"customer_id":"customer_first"}),
        });
        let (plugin, user) = plugin(client.clone()).await;
        after(&plugin, &user, &context()).await.unwrap();
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
    async fn new_customer_uses_the_user_id_as_idempotency_key() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin(client.clone()).await;
        after(&plugin, &user, &context()).await.unwrap();
        assert_eq!(
            client.idempotency_keys.lock().unwrap().as_slice(),
            std::slice::from_ref(&user.id)
        );
    }

    #[tokio::test]
    async fn disabled_flag_skips_the_provider_even_with_request_context() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin_with_options(client.clone(), false, None).await;
        after(&plugin, &user, &context()).await.unwrap();
        assert!(client.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn customer_params_preserve_metadata_and_explicit_null_phone() {
        let client = FakeCustomerClient::shared();
        let params = DodoCustomerParams {
            metadata: Some(BTreeMap::from([("plan".into(), "pro".into())])),
            phone_number: Some(None),
        };
        let (plugin, user) =
            plugin_with_options(client.clone(), true, Some(Arc::new(Params(Ok(params))))).await;

        after(&plugin, &user, &context()).await.unwrap();

        let requests = client.create_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].metadata,
            Some(BTreeMap::from([("plan".into(), "pro".into())]))
        );
        assert_eq!(requests[0].phone_number, Some(None));
    }

    #[tokio::test]
    async fn callback_failure_interrupts_create_with_the_adapter_error() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin_with_options(
            client,
            true,
            Some(Arc::new(Params(Err(DodoPaymentsCallbackError::new(
                "customer callback unavailable",
            ))))),
        )
        .await;

        let error = after(&plugin, &user, &context()).await.unwrap_err();
        let AuthError::PluginApi(error) = error else {
            panic!("expected plugin API error");
        };
        assert_eq!(error.status, 500);
        assert_eq!(
            error.message,
            "DodoPayments customer creation failed. Error: customer callback unavailable"
        );
    }

    #[tokio::test]
    async fn missing_persistence_target_does_not_interrupt_customer_creation() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin(client.clone()).await;
        plugin.auth_store.delete_user(&user.id).await.unwrap();

        after(&plugin, &user, &context()).await.unwrap();
        tokio::task::yield_now().await;

        assert_eq!(client.calls.lock().unwrap().as_slice(), ["list", "create"]);
        assert!(
            plugin
                .auth_store
                .find_user_by_id(&user.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn missing_context_disables_the_hook_and_provider_errors_are_exact() {
        let client = FakeCustomerClient::shared();
        let (plugin, user) = plugin(client.clone()).await;
        after(&plugin, &user, &DatabaseHookContext::default())
            .await
            .unwrap();
        assert!(client.calls.lock().unwrap().is_empty());

        *client.error.lock().unwrap() = Some("offline".into());
        let error = after(&plugin, &user, &context()).await.unwrap_err();
        let AuthError::PluginApi(error) = error else {
            panic!("expected plugin API error");
        };
        assert_eq!(error.status, 500);
        assert_eq!(
            error.message,
            "DodoPayments customer creation failed. Error: offline"
        );
    }
}
