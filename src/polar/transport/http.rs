use super::{
    PolarCheckout, PolarCheckoutCreate, PolarClient, PolarCustomer, PolarCustomerCreate,
    PolarCustomerList, PolarCustomerSession, PolarCustomerSessionCreate, PolarCustomerUpdate,
    PolarCustomerUpdateExternal, PolarEventsIngest, PolarOrderQuery, PolarPageItemKind,
    PolarPageQuery, PolarProviderError, PolarReferenceSubscriptionQuery, PolarResponseKind,
    PolarSubscriptionQuery,
};
use crate::polar::schema::OutboundKind;
use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::{fmt, sync::Arc, time::Duration};
use url::Url;

mod request;

use request::{customer, outbound_body, outbound_query, page, path_segment, transport_error};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct PolarHttpClient {
    http: reqwest::Client,
    access_token: Arc<str>,
    api_base: Url,
    response_limit: usize,
}

impl PolarHttpClient {
    pub fn new(access_token: impl Into<String>) -> Self {
        Self::with_limits(access_token, DEFAULT_TIMEOUT, DEFAULT_RESPONSE_LIMIT)
            .expect("Polar HTTP client configuration is valid")
    }

    pub fn sandbox(access_token: impl Into<String>) -> Self {
        let mut client = Self::new(access_token);
        client.api_base =
            Url::parse("https://sandbox-api.polar.sh/").expect("Polar sandbox URL is valid");
        client
    }

    pub fn with_limits(
        access_token: impl Into<String>,
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Self, PolarProviderError> {
        if timeout.is_zero() || response_limit == 0 {
            return Err(PolarProviderError::new(
                "Polar timeout and response limit must be greater than zero",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(transport_error)?;
        Ok(Self {
            http,
            access_token: Arc::from(access_token.into()),
            api_base: Url::parse("https://api.polar.sh/").expect("Polar API URL is valid"),
            response_limit,
        })
    }

    /// Explicit override for deterministic tests and compatible private proxies.
    pub fn with_api_base(mut self, mut api_base: Url) -> Self {
        if !api_base.path().ends_with('/') {
            let mut path = api_base.path().to_owned();
            path.push('/');
            api_base.set_path(&path);
        }
        self.api_base = api_base;
        self
    }
}

impl fmt::Debug for PolarHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolarHttpClient")
            .field("access_token", &"[REDACTED]")
            .field("api_base", &self.api_base)
            .field("response_limit", &self.response_limit)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PolarClient for PolarHttpClient {
    async fn create_checkout(
        &self,
        request: PolarCheckoutCreate,
    ) -> Result<PolarCheckout, PolarProviderError> {
        let request = outbound_body(&request, OutboundKind::CheckoutCreate)?;
        let value = self
            .organization_json(
                Method::POST,
                "v1/checkouts/",
                Some(&request),
                &[],
                &[StatusCode::CREATED],
                PolarResponseKind::Checkout,
            )
            .await?;
        let url = value["url"]
            .as_str()
            .expect("checkout response validation required a URL")
            .to_owned();
        Ok(PolarCheckout { url, value })
    }

    async fn list_customers(&self, email: &str) -> Result<PolarCustomerList, PolarProviderError> {
        let query = outbound_query(
            &serde_json::json!({ "email": email }),
            OutboundKind::CustomersList,
        )?;
        let result = self
            .organization_json::<Value>(
                Method::GET,
                "v1/customers/",
                None,
                &query,
                &[StatusCode::OK],
                PolarResponseKind::Page(PolarPageItemKind::Customer),
            )
            .await?;
        let items = result["items"]
            .as_array()
            .expect("page response validation required items")
            .iter()
            .cloned()
            .map(customer)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolarCustomerList {
            items,
            value: page(result, Some(1.0), Some(10.0))?,
        })
    }

    async fn create_customer(
        &self,
        request: PolarCustomerCreate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        let request = outbound_body(&request, OutboundKind::CustomerCreate)?;
        let value = self
            .organization_json(
                Method::POST,
                "v1/customers/",
                Some(&request),
                &[],
                &[StatusCode::CREATED],
                PolarResponseKind::Customer,
            )
            .await?;
        customer(value)
    }

    async fn update_customer(
        &self,
        id: &str,
        request: PolarCustomerUpdate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        let path = format!("v1/customers/{}", path_segment(id));
        let request = outbound_body(&request, OutboundKind::CustomerUpdate)?;
        let value = self
            .organization_json(
                Method::PATCH,
                &path,
                Some(&request),
                &[],
                &[StatusCode::OK],
                PolarResponseKind::Customer,
            )
            .await?;
        customer(value)
    }

    async fn update_customer_external(
        &self,
        external_id: &str,
        request: PolarCustomerUpdateExternal,
    ) -> Result<PolarCustomer, PolarProviderError> {
        let path = format!("v1/customers/external/{}", path_segment(external_id));
        let request = outbound_body(&request, OutboundKind::CustomerUpdateExternal)?;
        let value = self
            .organization_json(
                Method::PATCH,
                &path,
                Some(&request),
                &[],
                &[StatusCode::OK],
                PolarResponseKind::Customer,
            )
            .await?;
        customer(value)
    }

    async fn delete_customer(&self, id: &str) -> Result<(), PolarProviderError> {
        self.organization_empty(
            Method::DELETE,
            &format!("v1/customers/{}", path_segment(id)),
            StatusCode::NO_CONTENT,
        )
        .await
    }

    async fn customer_state_external(
        &self,
        external_id: &str,
    ) -> Result<Value, PolarProviderError> {
        self.organization_json::<Value>(
            Method::GET,
            &format!("v1/customers/external/{}/state", path_segment(external_id)),
            None,
            &[],
            &[StatusCode::OK],
            PolarResponseKind::CustomerState,
        )
        .await
    }

    async fn create_customer_session(
        &self,
        request: PolarCustomerSessionCreate,
    ) -> Result<PolarCustomerSession, PolarProviderError> {
        let request = outbound_body(&request, OutboundKind::CustomerSessionCreate)?;
        let value = self
            .organization_json(
                Method::POST,
                "v1/customer-sessions/",
                Some(&request),
                &[],
                &[StatusCode::CREATED],
                PolarResponseKind::CustomerSession,
            )
            .await?;
        Ok(PolarCustomerSession {
            token: value["token"]
                .as_str()
                .expect("customer session validation required a token")
                .into(),
            customer_portal_url: value["customerPortalUrl"]
                .as_str()
                .expect("customer session validation required a portal URL")
                .into(),
            value,
        })
    }

    async fn list_benefits(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        let values = outbound_query(&query, OutboundKind::BenefitGrantsList)?;
        page(
            self.portal_json::<Value>(
                "v1/customer-portal/benefit-grants/",
                None,
                &values,
                customer_session,
                PolarResponseKind::Page(PolarPageItemKind::BenefitGrant),
            )
            .await?,
            query.page,
            query.limit,
        )
    }

    async fn list_customer_subscriptions(
        &self,
        customer_session: &str,
        query: PolarSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        let values = outbound_query(&query, OutboundKind::CustomerSubscriptionsList)?;
        page(
            self.portal_json::<Value>(
                "v1/customer-portal/subscriptions/",
                None,
                &values,
                customer_session,
                PolarResponseKind::Page(PolarPageItemKind::CustomerSubscription),
            )
            .await?,
            query.page,
            query.limit,
        )
    }

    async fn list_orders(
        &self,
        customer_session: &str,
        query: PolarOrderQuery,
    ) -> Result<Value, PolarProviderError> {
        let values = outbound_query(&query, OutboundKind::CustomerOrdersList)?;
        page(
            self.portal_json::<Value>(
                "v1/customer-portal/orders/",
                None,
                &values,
                customer_session,
                PolarResponseKind::Page(PolarPageItemKind::Order),
            )
            .await?,
            query.page,
            query.limit,
        )
    }

    async fn list_meters(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        let values = outbound_query(&query, OutboundKind::CustomerMetersList)?;
        page(
            self.portal_json::<Value>(
                "v1/customer-portal/meters/",
                None,
                &values,
                customer_session,
                PolarResponseKind::Page(PolarPageItemKind::Meter),
            )
            .await?,
            query.page,
            query.limit,
        )
    }

    async fn list_subscriptions_by_reference(
        &self,
        query: PolarReferenceSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        let values = outbound_query(
            &serde_json::json!({
                "page": query.page,
                "limit": query.limit,
                "active": query.active,
                "metadata": { "referenceId": query.reference_id },
            }),
            OutboundKind::SubscriptionsList,
        )?;
        page(
            self.organization_json::<Value>(
                Method::GET,
                "v1/subscriptions/",
                None,
                &values,
                &[StatusCode::OK],
                PolarResponseKind::Page(PolarPageItemKind::Subscription),
            )
            .await?,
            query.page,
            query.limit,
        )
    }

    async fn ingest_events(&self, request: PolarEventsIngest) -> Result<Value, PolarProviderError> {
        let request = outbound_body(&request, OutboundKind::EventsIngest)?;
        self.organization_json(
            Method::POST,
            "v1/events/ingest",
            Some(&request),
            &[],
            &[StatusCode::OK],
            PolarResponseKind::Ingestion,
        )
        .await
    }
}

#[cfg(test)]
#[path = "http/contract.rs"]
mod contract;
