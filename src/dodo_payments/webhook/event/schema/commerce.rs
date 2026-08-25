#![allow(dead_code)]

use super::common::{
    BillingAddress, CustomFieldResponse, Customer, DiscountDetail, DisputeStage, DisputeStatus,
    IntentStatus, Metadata, PaymentProvider, RefundStatus,
};
use super::projection;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub(super) struct Payment {
    payload_type: PaymentPayloadType,
    billing: BillingAddress,
    brand_id: String,
    business_id: String,
    created_at: String,
    currency: String,
    customer: Customer,
    digital_products_delivered: bool,
    disputes: Vec<PaymentDispute>,
    is_update_payment_method: bool,
    metadata: Metadata,
    payment_id: String,
    payment_provider: PaymentProvider,
    refunds: Vec<RefundListItem>,
    retry_attempt: f64,
    settlement_amount: f64,
    settlement_currency: String,
    total_amount: f64,
    card_holder_name: Option<String>,
    card_issuing_country: Option<String>,
    card_last_four: Option<String>,
    card_network: Option<String>,
    card_type: Option<String>,
    checkout_session_id: Option<String>,
    custom_field_responses: Option<Vec<CustomFieldResponse>>,
    discount_id: Option<String>,
    discounts: Option<Vec<DiscountDetail>>,
    error_code: Option<String>,
    error_message: Option<String>,
    invoice_id: Option<String>,
    invoice_url: Option<String>,
    payment_link: Option<String>,
    payment_method: Option<String>,
    payment_method_id: Option<String>,
    payment_method_type: Option<String>,
    product_cart: Option<Vec<ProductCartItem>>,
    refund_status: Option<PaymentRefundStatus>,
    settlement_tax: Option<f64>,
    status: Option<IntentStatus>,
    subscription_id: Option<String>,
    tax: Option<f64>,
    updated_at: Option<String>,
}

#[derive(Deserialize)]
enum PaymentPayloadType {
    Payment,
}

#[derive(Deserialize)]
struct ProductCartItem {
    product_id: String,
    quantity: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PaymentRefundStatus {
    Partial,
    Full,
}

#[derive(Deserialize)]
struct RefundListItem {
    business_id: String,
    created_at: String,
    is_partial: bool,
    payment_id: String,
    refund_id: String,
    status: RefundStatus,
    amount: Option<f64>,
    currency: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct PaymentDispute {
    amount: String,
    business_id: String,
    created_at: String,
    currency: String,
    dispute_id: String,
    dispute_stage: DisputeStage,
    dispute_status: DisputeStatus,
    payment_id: String,
    is_resolved_by_rdr: Option<bool>,
    remarks: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Refund {
    payload_type: RefundPayloadType,
    brand_id: String,
    business_id: String,
    created_at: String,
    customer: Customer,
    is_partial: bool,
    metadata: Metadata,
    payment_id: String,
    refund_id: String,
    status: RefundStatus,
    amount: Option<f64>,
    currency: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
enum RefundPayloadType {
    Refund,
}

#[derive(Deserialize)]
pub(super) struct Dispute {
    payload_type: DisputePayloadType,
    amount: String,
    brand_id: String,
    business_id: String,
    created_at: String,
    currency: String,
    customer: Customer,
    dispute_id: String,
    dispute_stage: DisputeStage,
    dispute_status: DisputeStatus,
    payment_id: String,
    payment_provider: PaymentProvider,
    is_resolved_by_rdr: Option<bool>,
    reason: Option<String>,
    remarks: Option<String>,
}

#[derive(Deserialize)]
enum DisputePayloadType {
    Dispute,
}

#[derive(Deserialize)]
pub(super) struct LicenseKey {
    payload_type: LicenseKeyPayloadType,
    id: String,
    brand_id: String,
    business_id: String,
    created_at: String,
    customer_id: String,
    instances_count: f64,
    key: String,
    product_id: String,
    source: LicenseKeySource,
    status: LicenseKeyStatus,
    activations_limit: Option<f64>,
    expires_at: Option<String>,
    payment_id: Option<String>,
    subscription_id: Option<String>,
}

#[derive(Deserialize)]
enum LicenseKeyPayloadType {
    LicenseKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LicenseKeySource {
    Auto,
    Import,
    Manual,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LicenseKeyStatus {
    Active,
    Expired,
    Disabled,
}

#[derive(Deserialize)]
pub(super) struct Payout {
    amount: f64,
    business_id: String,
    chargebacks: f64,
    created_at: String,
    currency: String,
    fee: f64,
    payment_method: String,
    payout_id: String,
    refunds: f64,
    status: PayoutStatus,
    tax: f64,
    updated_at: String,
    name: Option<String>,
    payout_document_url: Option<String>,
    remarks: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PayoutStatus {
    NotInitiated,
    InProgress,
    OnHold,
    Failed,
    Success,
}

pub(super) fn payment(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "payload_type",
            "billing",
            "brand_id",
            "business_id",
            "created_at",
            "currency",
            "customer",
            "digital_products_delivered",
            "disputes",
            "is_update_payment_method",
            "metadata",
            "payment_id",
            "payment_provider",
            "refunds",
            "retry_attempt",
            "settlement_amount",
            "settlement_currency",
            "total_amount",
            "card_holder_name",
            "card_issuing_country",
            "card_last_four",
            "card_network",
            "card_type",
            "checkout_session_id",
            "custom_field_responses",
            "discount_id",
            "discounts",
            "error_code",
            "error_message",
            "invoice_id",
            "invoice_url",
            "payment_link",
            "payment_method",
            "payment_method_id",
            "payment_method_type",
            "product_cart",
            "refund_status",
            "settlement_tax",
            "status",
            "subscription_id",
            "tax",
            "updated_at",
        ],
    );
    projection::nested_object(&mut value, "billing", super::common::billing_address);
    projection::nested_object(&mut value, "customer", super::common::customer);
    projection::object_array(&mut value, "disputes", payment_dispute);
    projection::object_array(&mut value, "refunds", refund_list_item);
    projection::object_array(
        &mut value,
        "custom_field_responses",
        super::common::custom_field_response,
    );
    projection::object_array(&mut value, "discounts", super::common::discount_detail);
    projection::object_array(&mut value, "product_cart", product_cart_item);
    value
}

fn product_cart_item(value: &Value) -> Value {
    projection::object(value, &["product_id", "quantity"])
}

fn refund_list_item(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "business_id",
            "created_at",
            "is_partial",
            "payment_id",
            "refund_id",
            "status",
            "amount",
            "currency",
            "reason",
        ],
    )
}

fn payment_dispute(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "amount",
            "business_id",
            "created_at",
            "currency",
            "dispute_id",
            "dispute_stage",
            "dispute_status",
            "payment_id",
            "is_resolved_by_rdr",
            "remarks",
        ],
    )
}

pub(super) fn refund(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "payload_type",
            "brand_id",
            "business_id",
            "created_at",
            "customer",
            "is_partial",
            "metadata",
            "payment_id",
            "refund_id",
            "status",
            "amount",
            "currency",
            "reason",
        ],
    );
    projection::nested_object(&mut value, "customer", super::common::customer);
    value
}

pub(super) fn dispute(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "payload_type",
            "amount",
            "brand_id",
            "business_id",
            "created_at",
            "currency",
            "customer",
            "dispute_id",
            "dispute_stage",
            "dispute_status",
            "payment_id",
            "payment_provider",
            "is_resolved_by_rdr",
            "reason",
            "remarks",
        ],
    );
    projection::nested_object(&mut value, "customer", super::common::customer);
    value
}

pub(super) fn license_key(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "payload_type",
            "id",
            "brand_id",
            "business_id",
            "created_at",
            "customer_id",
            "instances_count",
            "key",
            "product_id",
            "source",
            "status",
            "activations_limit",
            "expires_at",
            "payment_id",
            "subscription_id",
        ],
    )
}

pub(super) fn payout(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "amount",
            "business_id",
            "chargebacks",
            "created_at",
            "currency",
            "fee",
            "payment_method",
            "payout_id",
            "refunds",
            "status",
            "tax",
            "updated_at",
            "name",
            "payout_document_url",
            "remarks",
        ],
    )
}
