use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{fmt, sync::Arc};

pub type PolarMetadata = Map<String, Value>;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PolarCheckoutCreate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_customer_id: Option<String>,
    pub products: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolarMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_field_data: Option<PolarMetadata>,
    pub allow_discount_codes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discount_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_trial: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_interval: Option<PolarTrialInterval>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_interval_count: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolarTrialInterval {
    Day,
    Week,
    Month,
    Year,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarCheckout {
    pub url: String,
    /// Complete SDK-normalized checkout value.
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarCustomerCreate {
    pub email: String,
    pub name: Option<String>,
    pub metadata: Option<PolarMetadata>,
}

impl Serialize for PolarCustomerCreate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        if let Some(metadata) = &self.metadata {
            map.serialize_entry("metadata", metadata)?;
        }
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("type", "individual")?;
        map.serialize_entry("email", &self.email)?;
        map.end()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolarCustomerUpdate {
    #[serde(rename = "external_id")]
    pub external_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolarCustomerUpdateExternal {
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarCustomer {
    pub id: String,
    pub external_id: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarCustomerList {
    pub items: Vec<PolarCustomer>,
    /// Complete SDK page value, including `result`.
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PolarCustomerSessionCreate {
    pub external_customer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarCustomerSession {
    pub token: String,
    pub customer_portal_url: String,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct PolarPageQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct PolarSubscriptionQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct PolarOrderQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    #[serde(
        rename = "product_billing_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub product_billing_type: Option<PolarProductBillingType>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolarProductBillingType {
    Recurring,
    OneTime,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolarReferenceSubscriptionQuery {
    pub reference_id: String,
    pub page: Option<f64>,
    pub limit: Option<f64>,
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PolarEventsIngest {
    pub events: Vec<PolarEventIngest>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct PolarEventIngest {
    pub name: String,
    pub metadata: PolarMetadata,
    pub external_customer_id: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PolarProviderError {
    pub status: Option<u16>,
    pub message: String,
    pub(crate) response: Option<Arc<str>>,
}

impl PolarProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
            response: None,
        }
    }

    pub(crate) fn response(status: u16, message: String, response: String) -> Self {
        Self {
            status: Some(status),
            message,
            response: Some(response.into()),
        }
    }
}

impl fmt::Debug for PolarProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolarProviderError")
            .field("status", &self.status)
            .field("message", &self.message)
            .field("response", &self.response.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl fmt::Display for PolarProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PolarProviderError {}
