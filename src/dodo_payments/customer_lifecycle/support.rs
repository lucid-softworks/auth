use super::super::{
    DodoCustomer, DodoCustomerCreateRequest, DodoCustomerListRequest, DodoCustomerPage,
    DodoCustomerParams, DodoCustomerUpdateRequest, DodoPaymentsClient, DodoPaymentsProviderError,
};
use crate::{AuthStore, AuthUser, DatabaseHookContext, UserProfileUpdate};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::Arc;

#[async_trait]
pub(super) trait CustomerLifecycleClient: Send + Sync {
    async fn list_by_email(
        &self,
        email: &str,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError>;

    async fn create(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: &str,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError>;

    async fn update(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError>;
}

#[async_trait]
impl<T> CustomerLifecycleClient for T
where
    T: DodoPaymentsClient + ?Sized,
{
    async fn list_by_email(
        &self,
        email: &str,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        self.list_customers(DodoCustomerListRequest {
            email: email.to_owned(),
        })
        .await
    }

    async fn create(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: &str,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.create_customer(request, Some(idempotency_key)).await
    }

    async fn update(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.update_customer(customer_id, request).await
    }
}

pub(super) async fn customer_params(
    plugin: &super::super::DodoPaymentsPlugin,
    user: &AuthUser,
) -> Result<DodoCustomerParams, super::super::DodoPaymentsCallbackError> {
    match &plugin.options.get_customer_params {
        Some(provider) => provider.params(user).await,
        None => Ok(DodoCustomerParams::default()),
    }
}

pub(super) fn update_request(
    user: &AuthUser,
    params: DodoCustomerParams,
) -> DodoCustomerUpdateRequest {
    DodoCustomerUpdateRequest {
        email: None,
        name: Some(Some(user.name.clone())),
        metadata: params.metadata.map(Some),
        phone_number: params.phone_number,
    }
}

pub(super) fn schedule_customer_id_write(
    context: &DatabaseHookContext,
    store: Arc<dyn AuthStore>,
    user_id: String,
    customer_id: String,
    operation: &'static str,
) {
    context.run_in_background(async move {
        let update = UserProfileUpdate {
            additional_fields: Map::from_iter([(
                "dodoCustomerId".to_owned(),
                Value::String(customer_id),
            )]),
            ..UserProfileUpdate::default()
        };
        if let Err(error) = store.update_user_profile(&user_id, update).await {
            tracing::warn!(
                "DodoPayments: failed to {operation} dodoCustomerId for user {user_id}. Error: {error}"
            );
        }
    });
}

pub(super) fn stored_customer_id(user: &AuthUser) -> Option<&str> {
    user.additional_fields
        .get("dodoCustomerId")
        .and_then(Value::as_str)
        .filter(|customer_id| !customer_id.is_empty())
}
