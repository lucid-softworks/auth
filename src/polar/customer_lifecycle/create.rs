use super::enabled;
use crate::{AuthError, AuthUser, DatabaseHookContext};

pub(super) async fn before(
    options: &super::super::PolarOptions,
    user: &crate::polar::PolarUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !enabled(options, user.is_anonymous, context) {
        return Ok(());
    }

    async {
        let metadata = match &options.get_customer_create_params {
            Some(provider) => provider
                .params(user)
                .await?
                .metadata
                .map(super::super::metadata_to_json),
            None => None,
        };
        if user.email.is_empty() {
            return Err(super::super::PolarCallbackError::new(
                "An associated email is required",
            ));
        }

        let customers = options
            .client
            .list_customers(&user.email)
            .await
            .map_err(|error| super::super::PolarCallbackError::new(error.to_string()))?;
        if customers.items.is_empty() {
            options
                .client
                .create_customer(super::super::PolarCustomerCreate {
                    email: user.email.clone(),
                    name: Some(user.name.clone()),
                    metadata,
                })
                .await
                .map_err(|error| super::super::PolarCallbackError::new(error.to_string()))?;
        }
        Ok::<_, super::super::PolarCallbackError>(())
    }
    .await
    .map_err(super::super::customer_creation_error)
}

pub(super) async fn after(
    options: &super::super::PolarOptions,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !enabled(options, user.is_anonymous, context) {
        return Ok(());
    }

    async {
        let customers = options.client.list_customers(&user.email).await?;
        let user_id = user.id.to_string();
        if let Some(customer) = customers.items.first()
            && customer.external_id.as_deref() != Some(user_id.as_str())
        {
            options
                .client
                .update_customer(
                    &customer.id,
                    super::super::PolarCustomerUpdate {
                        external_id: user_id,
                    },
                )
                .await?;
        }
        Ok::<_, super::super::PolarProviderError>(())
    }
    .await
    .map_err(super::super::customer_creation_error)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{FakePolarClient, context, options, user};
    use super::*;
    use crate::polar::{PolarCustomerCreateParams, PolarCustomerCreateParamsProvider};
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;

    fn draft(user: &AuthUser) -> crate::polar::PolarUser {
        crate::polar::PolarUser {
            id: None,
            name: user.name.clone(),
            email: user.email.clone(),
            is_anonymous: user.is_anonymous,
            fields: serde_json::Map::new(),
        }
    }

    struct CustomerParams;

    #[async_trait]
    impl PolarCustomerCreateParamsProvider for CustomerParams {
        async fn params(
            &self,
            user: &crate::polar::PolarUser,
        ) -> Result<PolarCustomerCreateParams, crate::polar::PolarCallbackError> {
            Ok(PolarCustomerCreateParams {
                metadata: Some(
                    serde_json::from_value(json!({
                        "source": "signup",
                        "anonymous": user.is_anonymous
                    }))
                    .unwrap(),
                ),
            })
        }
    }

    #[tokio::test]
    async fn before_create_uses_callback_metadata_and_creates_only_when_first_page_is_empty() {
        let client = Arc::new(FakePolarClient::default());
        let mut options = options(client.clone());
        options.get_customer_create_params = Some(Arc::new(CustomerParams));
        let user = user();

        before(&options, &draft(&user), &context()).await.unwrap();

        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["list:ada@example.com", "create"]
        );
        let creates = client.creates.lock().unwrap();
        assert_eq!(creates[0].email, user.email);
        assert_eq!(creates[0].name.as_deref(), Some("Ada"));
        assert_eq!(
            creates[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("source")),
            Some(&json!("signup"))
        );
    }

    #[tokio::test]
    async fn before_create_skips_without_request_for_anonymous_and_for_first_existing_customer() {
        let client = Arc::new(FakePolarClient::default());
        let options = options(client.clone());
        let mut anonymous = user();
        anonymous.is_anonymous = true;
        before(&options, &draft(&anonymous), &context())
            .await
            .unwrap();
        before(&options, &draft(&user()), &DatabaseHookContext::default())
            .await
            .unwrap();
        client
            .customers
            .lock()
            .unwrap()
            .push(FakePolarClient::customer("first", None));
        before(&options, &draft(&user()), &context()).await.unwrap();

        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["list:ada@example.com"]
        );
        assert!(client.creates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_failures_keep_the_exact_plugin_api_error() {
        let client = Arc::new(FakePolarClient::default());
        *client.list_error.lock().unwrap() = Some(crate::polar::PolarProviderError::new("offline"));
        let error = before(&options(client), &draft(&user()), &context())
            .await
            .unwrap_err();
        let crate::AuthError::PluginApi(error) = error else {
            panic!("expected plugin API error");
        };
        assert_eq!(error.status, 500);
        assert_eq!(error.code, "INTERNAL_SERVER_ERROR");
        assert_eq!(
            error.message,
            "Polar customer creation failed. Error: offline"
        );
    }

    #[tokio::test]
    async fn after_create_links_only_the_first_customer_and_skips_an_existing_link() {
        let client = Arc::new(FakePolarClient::default());
        let user = user();
        client.customers.lock().unwrap().extend([
            FakePolarClient::customer("first", None),
            FakePolarClient::customer("second", None),
        ]);
        after(&options(client.clone()), &user, &context())
            .await
            .unwrap();
        assert_eq!(client.updates.lock().unwrap()[0].0, "first");
        assert_eq!(
            client.updates.lock().unwrap()[0].1.external_id,
            user.id.to_string()
        );

        client.updates.lock().unwrap().clear();
        client.customers.lock().unwrap()[0].external_id = Some(user.id.to_string());
        after(&options(client.clone()), &user, &context())
            .await
            .unwrap();
        assert!(client.updates.lock().unwrap().is_empty());
    }
}
