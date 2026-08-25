use super::{
    DodoCheckoutSession, DodoCustomer, DodoCustomerCreateRequest, DodoCustomerListRequest,
    DodoCustomerPage, DodoCustomerPortal, DodoCustomerUpdateRequest, DodoPaymentListRequest,
    DodoPaymentOrSubscription, DodoProviderItemPage, DodoProviderProduct,
    DodoSubscriptionListRequest, DodoUsageIngestRequest, DodoUsageIngestResult,
    DodoUsageListRequest,
};
use crate::dodo_payments::transport::{
    DodoPaymentsEnvironment, DodoPaymentsHttpTransport, DodoPaymentsProviderConfig,
    DodoPaymentsProviderError, DodoPaymentsTransport, DodoPaymentsTransportRequest,
};
use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use serde_json::Value;
use std::{fmt, sync::Arc};

use super::checkout::normalize_checkout_session;

const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

#[async_trait]
pub trait DodoPaymentsClient: Send + Sync {
    fn environment(&self) -> DodoPaymentsEnvironment;

    async fn list_customers(
        &self,
        request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError>;

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError>;

    async fn update_customer(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError>;

    async fn create_customer_portal(
        &self,
        customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError>;

    async fn retrieve_product(
        &self,
        product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError>;

    async fn create_checkout_session(
        &self,
        request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError>;

    async fn create_payment(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError>;

    async fn list_payments(
        &self,
        request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError>;

    async fn create_subscription(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError>;

    async fn list_subscriptions(
        &self,
        request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError>;

    async fn ingest_usage(
        &self,
        request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError>;

    async fn list_usage(
        &self,
        request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError>;
}

#[derive(Clone)]
pub struct DodoPaymentsHttpClient {
    transport: Arc<dyn DodoPaymentsTransport>,
}

impl DodoPaymentsHttpClient {
    pub fn new(config: DodoPaymentsProviderConfig) -> Self {
        Self::with_transport(Arc::new(DodoPaymentsHttpTransport::new(config)))
    }

    pub fn with_transport(transport: Arc<dyn DodoPaymentsTransport>) -> Self {
        Self { transport }
    }
}

impl fmt::Debug for DodoPaymentsHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsHttpClient")
            .field("environment", &self.transport.environment())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DodoPaymentsClient for DodoPaymentsHttpClient {
    fn environment(&self) -> DodoPaymentsEnvironment {
        self.transport.environment()
    }

    async fn list_customers(
        &self,
        request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::get(
                "customers",
                vec![("email".into(), request.email)],
            ))
            .await?;
        customer_page(value)
    }

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        let body = to_value(request)?;
        let value = self
            .transport
            .send(
                DodoPaymentsTransportRequest::post("customers", body)
                    .with_idempotency_key(idempotency_key),
            )
            .await?;
        customer(value)
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        let path = format!("customers/{}", encode_component(customer_id));
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::patch(
                path,
                to_value(request)?,
            ))
            .await?;
        customer(value)
    }

    async fn create_customer_portal(
        &self,
        customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError> {
        let path = format!(
            "customers/{}/customer-portal/session",
            encode_component(customer_id)
        );
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::post_empty(path))
            .await?;
        let link = string_field(&value, "link")?;
        Ok(DodoCustomerPortal { link, value })
    }

    async fn retrieve_product(
        &self,
        product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError> {
        let path = format!("products/{}", encode_component(product_id));
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::get(path, Vec::new()))
            .await?;
        let is_recurring = value
            .get("is_recurring")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(DodoProviderProduct {
            is_recurring,
            value,
        })
    }

    async fn create_checkout_session(
        &self,
        request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::post("checkouts", request))
            .await?;
        normalize_checkout_session(value)
    }

    async fn create_payment(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        create_payment_or_subscription(&*self.transport, "payments", request).await
    }

    async fn list_payments(
        &self,
        request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        let mut query = list_query(request.customer_id, request.page_number, request.page_size);
        if let Some(status) = request.status {
            query.push(("status".into(), status.as_str().into()));
        }
        list_items(&*self.transport, "payments", query).await
    }

    async fn create_subscription(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        create_payment_or_subscription(&*self.transport, "subscriptions", request).await
    }

    async fn list_subscriptions(
        &self,
        request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        let mut query = list_query(request.customer_id, request.page_number, request.page_size);
        if let Some(status) = request.status {
            query.push(("status".into(), status.as_str().into()));
        }
        list_items(&*self.transport, "subscriptions", query).await
    }

    async fn ingest_usage(
        &self,
        request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError> {
        let value = self
            .transport
            .send(DodoPaymentsTransportRequest::post(
                "events/ingest",
                to_value(request)?,
            ))
            .await?;
        let ingested_count = value
            .get("ingested_count")
            .and_then(Value::as_u64)
            .ok_or_else(response_validation)?;
        Ok(DodoUsageIngestResult {
            ingested_count,
            value,
        })
    }

    async fn list_usage(
        &self,
        request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        let mut query = Vec::with_capacity(7);
        push_option(&mut query, "customer_id", request.customer_id);
        push_number(&mut query, "page_number", request.page_number);
        push_number(&mut query, "page_size", request.page_size);
        push_option(&mut query, "event_name", request.event_name);
        push_option(&mut query, "meter_id", request.meter_id);
        push_option(&mut query, "start", request.start);
        push_option(&mut query, "end", request.end);
        list_items(&*self.transport, "events", query).await
    }
}

async fn create_payment_or_subscription(
    transport: &dyn DodoPaymentsTransport,
    path: &str,
    request: Value,
) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
    let value = transport
        .send(DodoPaymentsTransportRequest::post(path, request))
        .await?;
    let payment_link = optional_string_field(&value, "payment_link")?;
    Ok(DodoPaymentOrSubscription {
        payment_link,
        value,
    })
}

async fn list_items(
    transport: &dyn DodoPaymentsTransport,
    path: &str,
    query: Vec<(String, String)>,
) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
    let value = transport
        .send(DodoPaymentsTransportRequest::get(path, query))
        .await?;
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(DodoProviderItemPage { items, value })
}

fn customer_page(value: Value) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(customer)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DodoCustomerPage { items, value })
}

fn customer(value: Value) -> Result<DodoCustomer, DodoPaymentsProviderError> {
    let customer_id = string_field(&value, "customer_id")?;
    Ok(DodoCustomer { customer_id, value })
}

fn string_field(value: &Value, field: &str) -> Result<String, DodoPaymentsProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(response_validation)
}

fn optional_string_field(
    value: &Value,
    field: &str,
) -> Result<Option<String>, DodoPaymentsProviderError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(response_validation()),
    }
}

fn list_query(
    customer_id: String,
    page_number: Option<f64>,
    page_size: Option<f64>,
) -> Vec<(String, String)> {
    let mut query = vec![("customer_id".into(), customer_id)];
    push_number(&mut query, "page_number", page_number);
    push_number(&mut query, "page_size", page_size);
    query
}

fn push_option(query: &mut Vec<(String, String)>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        query.push((name.into(), value));
    }
}

fn push_number(query: &mut Vec<(String, String)>, name: &str, value: Option<f64>) {
    if let Some(value) = value {
        query.push((name.into(), ryu_js::Buffer::new().format(value).to_owned()));
    }
}

fn to_value(request: impl Serialize) -> Result<Value, DodoPaymentsProviderError> {
    serde_json::to_value(request)
        .map_err(|_| DodoPaymentsProviderError::new("Dodo Payments request serialization failed"))
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

fn response_validation() -> DodoPaymentsProviderError {
    DodoPaymentsProviderError::new("Dodo Payments response validation failed")
}

#[cfg(test)]
#[path = "client/contract.rs"]
mod contract;
