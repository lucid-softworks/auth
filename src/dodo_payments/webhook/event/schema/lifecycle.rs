#![allow(dead_code)]

use super::common::Metadata;
use super::projection;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub(super) struct CreditLedgerEntry {
    payload_type: CreditLedgerPayloadType,
    id: String,
    amount: String,
    balance_after: String,
    balance_before: String,
    brand_id: String,
    business_id: String,
    created_at: String,
    credit_entitlement_id: String,
    customer_id: String,
    is_credit: bool,
    metadata: Metadata,
    overage_after: String,
    overage_before: String,
    transaction_type: CreditTransactionType,
    description: Option<String>,
    grant_id: Option<String>,
    reference_id: Option<String>,
    reference_type: Option<String>,
}

#[derive(Deserialize)]
enum CreditLedgerPayloadType {
    CreditLedgerEntry,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CreditTransactionType {
    CreditAdded,
    CreditDeducted,
    CreditExpired,
    CreditRolledOver,
    RolloverForfeited,
    OverageCharged,
    OverageReset,
    AutoTopUp,
    ManualAdjustment,
    Refund,
}

#[derive(Deserialize)]
pub(super) struct CreditBalanceLow {
    payload_type: CreditBalancePayloadType,
    available_balance: String,
    brand_id: String,
    credit_entitlement_id: String,
    credit_entitlement_name: String,
    customer_id: String,
    subscription_credits_amount: String,
    subscription_id: String,
    threshold_amount: String,
    threshold_percent: f64,
}

#[derive(Deserialize)]
enum CreditBalancePayloadType {
    CreditBalanceLow,
}

#[derive(Deserialize)]
pub(super) struct AbandonedCheckout {
    payload_type: AbandonedCheckoutPayloadType,
    abandoned_at: String,
    abandonment_reason: AbandonmentReason,
    brand_id: String,
    customer_id: String,
    payment_id: String,
    status: AbandonedCheckoutStatus,
    recovered_payment_id: Option<String>,
}

#[derive(Deserialize)]
enum AbandonedCheckoutPayloadType {
    AbandonedCheckout,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AbandonmentReason {
    PaymentFailed,
    CheckoutIncomplete,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AbandonedCheckoutStatus {
    Abandoned,
    Recovering,
    Recovered,
    Exhausted,
    OptedOut,
}

#[derive(Deserialize)]
pub(super) struct DunningAttempt {
    payload_type: DunningPayloadType,
    brand_id: String,
    created_at: String,
    customer_id: String,
    status: DunningStatus,
    subscription_id: String,
    trigger_state: DunningTriggerState,
    payment_id: Option<String>,
}

#[derive(Deserialize)]
enum DunningPayloadType {
    DunningAttempt,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DunningStatus {
    Recovering,
    Recovered,
    Exhausted,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DunningTriggerState {
    OnHold,
    Cancelled,
}

#[derive(Deserialize)]
pub(super) struct EntitlementGrant {
    payload_type: EntitlementGrantPayloadType,
    id: String,
    brand_id: String,
    business_id: String,
    created_at: String,
    customer_id: String,
    entitlement_id: String,
    integration_type: EntitlementIntegrationType,
    metadata: Metadata,
    status: EntitlementStatus,
    updated_at: String,
    delivered_at: Option<String>,
    digital_product_delivery: Option<DigitalProductDelivery>,
    error_code: Option<String>,
    error_message: Option<String>,
    feature: Option<EntitlementFeature>,
    license_key: Option<LicenseKeyGrant>,
    oauth_expires_at: Option<String>,
    oauth_url: Option<String>,
    payment_id: Option<String>,
    revocation_reason: Option<String>,
    revoked_at: Option<String>,
    subscription_id: Option<String>,
}

#[derive(Deserialize)]
enum EntitlementGrantPayloadType {
    EntitlementGrant,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EntitlementIntegrationType {
    Discord,
    Telegram,
    Github,
    Figma,
    Framer,
    Notion,
    DigitalFiles,
    LicenseKey,
    FeatureFlag,
}

#[derive(Deserialize)]
enum EntitlementStatus {
    Pending,
    Delivered,
    Failed,
    Revoked,
}

#[derive(Deserialize)]
struct EntitlementFeature {
    feature_id: String,
    feature_type: EntitlementFeatureType,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EntitlementFeatureType {
    Boolean,
}

#[derive(Deserialize)]
struct LicenseKeyGrant {
    activations_used: f64,
    key: String,
    activations_limit: Option<f64>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct DigitalProductDelivery {
    files: Vec<DigitalProductDeliveryFile>,
    external_url: Option<String>,
    instructions: Option<String>,
}

#[derive(Deserialize)]
struct DigitalProductDeliveryFile {
    download_url: String,
    expires_in: f64,
    file_id: String,
    filename: String,
    content_type: Option<String>,
    file_size: Option<f64>,
}

pub(super) fn credit_ledger_entry(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "payload_type",
            "id",
            "amount",
            "balance_after",
            "balance_before",
            "brand_id",
            "business_id",
            "created_at",
            "credit_entitlement_id",
            "customer_id",
            "is_credit",
            "metadata",
            "overage_after",
            "overage_before",
            "transaction_type",
            "description",
            "grant_id",
            "reference_id",
            "reference_type",
        ],
    )
}

pub(super) fn credit_balance_low(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "payload_type",
            "available_balance",
            "brand_id",
            "credit_entitlement_id",
            "credit_entitlement_name",
            "customer_id",
            "subscription_credits_amount",
            "subscription_id",
            "threshold_amount",
            "threshold_percent",
        ],
    )
}

pub(super) fn abandoned_checkout(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "payload_type",
            "abandoned_at",
            "abandonment_reason",
            "brand_id",
            "customer_id",
            "payment_id",
            "status",
            "recovered_payment_id",
        ],
    )
}

pub(super) fn dunning_attempt(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "payload_type",
            "brand_id",
            "created_at",
            "customer_id",
            "status",
            "subscription_id",
            "trigger_state",
            "payment_id",
        ],
    )
}

pub(super) fn entitlement_grant(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "payload_type",
            "id",
            "brand_id",
            "business_id",
            "created_at",
            "customer_id",
            "entitlement_id",
            "integration_type",
            "metadata",
            "status",
            "updated_at",
            "delivered_at",
            "digital_product_delivery",
            "error_code",
            "error_message",
            "feature",
            "license_key",
            "oauth_expires_at",
            "oauth_url",
            "payment_id",
            "revocation_reason",
            "revoked_at",
            "subscription_id",
        ],
    );
    projection::nested_object(
        &mut value,
        "digital_product_delivery",
        digital_product_delivery,
    );
    projection::nested_object(&mut value, "feature", entitlement_feature);
    projection::nested_object(&mut value, "license_key", license_key_grant);
    value
}

fn entitlement_feature(value: &Value) -> Value {
    projection::object(value, &["feature_id", "feature_type"])
}

fn license_key_grant(value: &Value) -> Value {
    projection::object(
        value,
        &["activations_used", "key", "activations_limit", "expires_at"],
    )
}

fn digital_product_delivery(value: &Value) -> Value {
    let mut value = projection::object(value, &["files", "external_url", "instructions"]);
    projection::object_array(&mut value, "files", digital_product_delivery_file);
    value
}

fn digital_product_delivery_file(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "download_url",
            "expires_in",
            "file_id",
            "filename",
            "content_type",
            "file_size",
        ],
    )
}
