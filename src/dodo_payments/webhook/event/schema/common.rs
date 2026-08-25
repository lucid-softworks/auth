#![allow(dead_code)]

use serde::Deserialize;
use serde_json::{Map, Value};

use super::projection;

pub(super) type Metadata = Map<String, Value>;

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum RequiredNullable<T> {
    Value(T),
    Null(()),
}

#[derive(Deserialize)]
pub(super) struct Customer {
    customer_id: String,
    email: String,
    name: String,
    metadata: Option<Metadata>,
    phone_number: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct BillingAddress {
    city: RequiredNullable<String>,
    country: String,
    state: RequiredNullable<String>,
    street: RequiredNullable<String>,
    zipcode: RequiredNullable<String>,
}

#[derive(Deserialize)]
pub(super) struct CustomFieldResponse {
    key: String,
    value: String,
}

#[derive(Deserialize)]
pub(super) struct DiscountDetail {
    amount: f64,
    business_id: String,
    code: String,
    created_at: String,
    discount_id: String,
    metadata: Metadata,
    position: f64,
    preserve_on_plan_change: bool,
    restricted_to: Vec<String>,
    times_used: f64,
    #[serde(rename = "type")]
    discount_type: DiscountType,
    cycles_remaining: Option<f64>,
    expires_at: Option<String>,
    name: Option<String>,
    subscription_cycles: Option<f64>,
    usage_limit: Option<f64>,
}

#[derive(Deserialize)]
enum DiscountType {
    #[serde(rename = "percentage")]
    Percentage,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DisputeStage {
    PreDispute,
    Dispute,
    PreArbitration,
}

#[derive(Deserialize)]
pub(super) enum DisputeStatus {
    #[serde(rename = "dispute_opened")]
    Opened,
    #[serde(rename = "dispute_expired")]
    Expired,
    #[serde(rename = "dispute_accepted")]
    Accepted,
    #[serde(rename = "dispute_cancelled")]
    Cancelled,
    #[serde(rename = "dispute_challenged")]
    Challenged,
    #[serde(rename = "dispute_won")]
    Won,
    #[serde(rename = "dispute_lost")]
    Lost,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RefundStatus {
    Succeeded,
    Failed,
    Pending,
    Review,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IntentStatus {
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PaymentProvider {
    Stripe,
    Adyen,
    Dodo,
}

#[derive(Deserialize)]
pub(super) enum TimeInterval {
    Day,
    Week,
    Month,
    Year,
}

pub(super) fn customer(value: &Value) -> Value {
    projection::object(
        value,
        &["customer_id", "email", "name", "metadata", "phone_number"],
    )
}

pub(super) fn billing_address(value: &Value) -> Value {
    projection::object(value, &["city", "country", "state", "street", "zipcode"])
}

pub(super) fn custom_field_response(value: &Value) -> Value {
    projection::object(value, &["key", "value"])
}

pub(super) fn discount_detail(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "amount",
            "business_id",
            "code",
            "created_at",
            "discount_id",
            "metadata",
            "position",
            "preserve_on_plan_change",
            "restricted_to",
            "times_used",
            "type",
            "cycles_remaining",
            "expires_at",
            "name",
            "subscription_cycles",
            "usage_limit",
        ],
    )
}
