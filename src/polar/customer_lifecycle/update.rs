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
    if let Err(error) = options
        .client
        .update_customer_external(
            &user.id.to_string(),
            super::super::PolarCustomerUpdateExternal {
                email: user.email.clone(),
                name: user.name.clone(),
            },
        )
        .await
    {
        tracing::error!("Polar customer update failed. Error: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{FakePolarClient, context, options, user};
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn update_sends_email_and_name_by_external_id_and_swallows_provider_errors() {
        let client = Arc::new(FakePolarClient::default());
        *client.update_error.lock().unwrap() =
            Some(crate::polar::PolarProviderError::new("duplicate email"));
        let user = user();
        after(&options(client.clone()), &user, &context()).await;

        let updates = client.external_updates.lock().unwrap();
        assert_eq!(updates[0].0, user.id.to_string());
        assert_eq!(updates[0].1.email, user.email);
        assert_eq!(updates[0].1.name, user.name);
    }
}
