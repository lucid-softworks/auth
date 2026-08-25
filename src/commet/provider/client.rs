use super::super::{
    CommetCustomerCreate, CommetCustomerUpdate, CommetHttpTransport, CommetProviderConfig,
    CommetProviderError, CommetSeatMutation, CommetSeatSetAll, CommetSubscriptionCancel,
    CommetTransport, CommetTransportRequest, CommetUsageEvent,
};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use std::{fmt, sync::Arc};

#[async_trait]
pub trait CommetClient: Send + Sync {
    async fn list_customers(&self, external_id: &str) -> Result<Value, CommetProviderError>;
    async fn create_customer(
        &self,
        request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError>;
    async fn update_customer(
        &self,
        customer_id: &str,
        request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError>;
    async fn create_portal_session(&self, customer_id: &str) -> Result<Value, CommetProviderError>;
    async fn get_active_subscription(
        &self,
        customer_id: &str,
    ) -> Result<Value, CommetProviderError>;
    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError>;
    async fn list_feature_access(&self, customer_id: &str) -> Result<Value, CommetProviderError>;
    async fn get_feature_access(
        &self,
        customer_id: &str,
        code: &str,
    ) -> Result<Value, CommetProviderError>;
    async fn check_usage(
        &self,
        customer_id: &str,
        feature_code: &str,
    ) -> Result<Value, CommetProviderError>;
    async fn create_usage_event(
        &self,
        request: CommetUsageEvent,
        idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError>;
    async fn list_seat_balances(&self, customer_id: &str) -> Result<Value, CommetProviderError>;
    async fn add_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError>;
    async fn remove_seats(&self, request: CommetSeatMutation)
    -> Result<Value, CommetProviderError>;
    async fn set_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError>;
    async fn set_all_seats(&self, request: CommetSeatSetAll) -> Result<Value, CommetProviderError>;
}

#[derive(Clone)]
pub struct CommetHttpClient {
    transport: Arc<dyn CommetTransport>,
}

impl CommetHttpClient {
    pub fn new(config: CommetProviderConfig) -> Self {
        Self::with_transport(Arc::new(CommetHttpTransport::new(config)))
    }

    pub fn with_transport(transport: Arc<dyn CommetTransport>) -> Self {
        Self { transport }
    }
}

impl fmt::Debug for CommetHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetHttpClient")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CommetClient for CommetHttpClient {
    async fn list_customers(&self, external_id: &str) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::get(
                "/customers",
                vec![("externalId".into(), external_id.into())],
            ))
            .await
    }

    async fn create_customer(
        &self,
        request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError> {
        self.send_body(CommetTransportRequest::post, "/customers", request)
            .await
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError> {
        self.send_body(
            CommetTransportRequest::patch,
            &format!("/customers/{customer_id}"),
            request,
        )
        .await
    }

    async fn create_portal_session(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::post(
                "/portal/sessions",
                serde_json::json!({"customerId": customer_id}),
            ))
            .await
    }

    async fn get_active_subscription(
        &self,
        customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::get(
                "/subscriptions/active",
                vec![("customerId".into(), customer_id.into())],
            ))
            .await
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError> {
        self.send_body(
            CommetTransportRequest::post,
            &format!("/subscriptions/{subscription_id}/cancel"),
            request,
        )
        .await
    }

    async fn list_feature_access(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::get(
                "/feature-access",
                vec![("customerId".into(), customer_id.into())],
            ))
            .await
    }

    async fn get_feature_access(
        &self,
        customer_id: &str,
        code: &str,
    ) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::get(
                format!("/feature-access/{code}"),
                vec![("customerId".into(), customer_id.into())],
            ))
            .await
    }

    async fn check_usage(
        &self,
        customer_id: &str,
        feature_code: &str,
    ) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::post(
                "/usage/check",
                serde_json::json!({
                    "customerId": customer_id,
                    "featureCode": feature_code,
                }),
            ))
            .await
    }

    async fn create_usage_event(
        &self,
        request: CommetUsageEvent,
        idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        let body = to_value(request)?;
        self.transport
            .send(
                CommetTransportRequest::post("/usage/events", body)
                    .with_idempotency_key(idempotency_key),
            )
            .await
    }

    async fn list_seat_balances(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.transport
            .send(CommetTransportRequest::get(
                "/seats/balances",
                vec![("customerId".into(), customer_id.into())],
            ))
            .await
    }

    async fn add_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        self.send_body(CommetTransportRequest::post, "/seats", request)
            .await
    }

    async fn remove_seats(
        &self,
        request: CommetSeatMutation,
    ) -> Result<Value, CommetProviderError> {
        self.send_body(CommetTransportRequest::post, "/seats/remove", request)
            .await
    }

    async fn set_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        self.send_body(CommetTransportRequest::put, "/seats", request)
            .await
    }

    async fn set_all_seats(&self, request: CommetSeatSetAll) -> Result<Value, CommetProviderError> {
        self.send_body(CommetTransportRequest::put, "/seats/bulk", request)
            .await
    }
}

impl CommetHttpClient {
    async fn send_body<T: Serialize>(
        &self,
        constructor: fn(String, Value) -> CommetTransportRequest,
        path: &str,
        request: T,
    ) -> Result<Value, CommetProviderError> {
        self.transport
            .send(constructor(path.to_owned(), to_value(request)?))
            .await
    }
}

fn to_value(value: impl Serialize) -> Result<Value, CommetProviderError> {
    serde_json::to_value(value)
        .map_err(|_| CommetProviderError::new("Commet request serialization failed"))
}

#[cfg(test)]
#[path = "client/contract.rs"]
mod contract;
