use super::enabled;
use crate::{AuthUser, DatabaseHookContext};

pub(super) async fn after(
    options: &super::super::PolarOptions,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    if !enabled(options, user.is_anonymous, context) {
        return;
    }

    let result = async {
        if user.email.is_empty() {
            return Ok(());
        }
        let customers = options.client.list_customers(&user.email).await?;
        if let Some(customer) = customers.items.first() {
            options.client.delete_customer(&customer.id).await?;
        }
        Ok::<_, super::super::PolarProviderError>(())
    }
    .await;
    if let Err(error) = result {
        tracing::error!("Polar customer delete failed. Error: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{FakePolarClient, context, options, user};
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn delete_uses_only_the_first_customer_and_swallows_provider_errors() {
        let client = Arc::new(FakePolarClient::default());
        client.customers.lock().unwrap().extend([
            FakePolarClient::customer("first", None),
            FakePolarClient::customer("second", None),
        ]);
        *client.delete_error.lock().unwrap() =
            Some(crate::polar::PolarProviderError::new("offline"));

        after(&options(client.clone()), &user(), &context()).await;

        assert_eq!(client.deletes.lock().unwrap().as_slice(), ["first"]);
    }

    #[tokio::test]
    async fn delete_skips_customer_lookup_when_email_is_empty() {
        let client = Arc::new(FakePolarClient::default());
        let mut user = user();
        user.email.clear();
        after(&options(client.clone()), &user, &context()).await;
        assert!(client.calls.lock().unwrap().is_empty());
    }
}
