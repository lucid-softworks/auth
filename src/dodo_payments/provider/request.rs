use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub type DodoUsageMetadata = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DodoCustomerListRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DodoCustomerCreateRequest {
    pub email: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Option<String>>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DodoCustomerUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Option<BTreeMap<String, String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DodoSubscriptionStatus {
    Active,
    Cancelled,
    OnHold,
    Pending,
    Failed,
    Expired,
}

impl DodoSubscriptionStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cancelled => "cancelled",
            Self::OnHold => "on_hold",
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoSubscriptionListRequest {
    pub customer_id: String,
    pub page_number: Option<f64>,
    pub page_size: Option<f64>,
    pub status: Option<DodoSubscriptionStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DodoPaymentStatus {
    Succeeded,
    Failed,
    Cancelled,
    Processing,
    RequiresCustomerAction,
    RequiresMerchantAction,
    RequiresPaymentMethod,
    RequiresConfirmation,
    RequiresCapture,
    PartiallyCaptured,
    PartiallyCapturedAndCapturable,
}

impl DodoPaymentStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Processing => "processing",
            Self::RequiresCustomerAction => "requires_customer_action",
            Self::RequiresMerchantAction => "requires_merchant_action",
            Self::RequiresPaymentMethod => "requires_payment_method",
            Self::RequiresConfirmation => "requires_confirmation",
            Self::RequiresCapture => "requires_capture",
            Self::PartiallyCaptured => "partially_captured",
            Self::PartiallyCapturedAndCapturable => "partially_captured_and_capturable",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoPaymentListRequest {
    pub customer_id: String,
    pub page_number: Option<f64>,
    pub page_size: Option<f64>,
    pub status: Option<DodoPaymentStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DodoUsageEvent {
    pub customer_id: String,
    pub event_id: String,
    pub event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Option<DodoUsageMetadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DodoUsageIngestRequest {
    pub events: Vec<DodoUsageEvent>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DodoUsageListRequest {
    pub customer_id: Option<String>,
    pub page_number: Option<f64>,
    pub page_size: Option<f64>,
    pub event_name: Option<String>,
    pub meter_id: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn customer_fields_preserve_absent_and_explicit_null() {
        let request = DodoCustomerUpdateRequest {
            name: Some(Some("Ada".into())),
            phone_number: Some(None),
            ..DodoCustomerUpdateRequest::default()
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"name": "Ada", "phone_number": null})
        );
    }

    #[test]
    fn status_names_match_the_adapter_vocabulary() {
        assert_eq!(DodoSubscriptionStatus::OnHold.as_str(), "on_hold");
        assert_eq!(
            DodoPaymentStatus::PartiallyCapturedAndCapturable.as_str(),
            "partially_captured_and_capturable"
        );
    }
}
