#![allow(dead_code)]

use super::common::{
    BillingAddress, CustomFieldResponse, Customer, DiscountDetail, Metadata, TimeInterval,
};
use super::projection;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub(super) struct Subscription {
    payload_type: SubscriptionPayloadType,
    addons: Vec<Addon>,
    billing: BillingAddress,
    brand_id: String,
    cancel_at_next_billing_date: bool,
    created_at: String,
    credit_entitlement_cart: Vec<CreditEntitlement>,
    currency: String,
    customer: Customer,
    metadata: Metadata,
    meter_credit_entitlement_cart: Vec<MeterCreditEntitlement>,
    meters: Vec<Meter>,
    next_billing_date: String,
    on_demand: bool,
    payment_frequency_count: f64,
    payment_frequency_interval: TimeInterval,
    previous_billing_date: String,
    product_id: String,
    quantity: f64,
    recurring_pre_tax_amount: f64,
    status: SubscriptionStatus,
    subscription_id: String,
    subscription_period_count: f64,
    subscription_period_interval: TimeInterval,
    tax_inclusive: bool,
    trial_period_days: f64,
    cancellation_comment: Option<String>,
    cancellation_feedback: Option<CancellationFeedback>,
    cancelled_at: Option<String>,
    custom_field_responses: Option<Vec<CustomFieldResponse>>,
    customer_business_name: Option<String>,
    discount_cycles_remaining: Option<f64>,
    discount_id: Option<String>,
    discounts: Option<Vec<DiscountDetail>>,
    expires_at: Option<String>,
    paused_at: Option<String>,
    payment_method_id: Option<String>,
    scheduled_change: Option<ScheduledPlanChange>,
    tax_id: Option<String>,
    trial_amount: Option<f64>,
}

#[derive(Deserialize)]
enum SubscriptionPayloadType {
    Subscription,
}

#[derive(Deserialize)]
struct Addon {
    addon_id: String,
    quantity: f64,
}

#[derive(Deserialize)]
struct CreditEntitlement {
    credit_entitlement_id: String,
    credit_entitlement_name: String,
    credits_amount: String,
    overage_balance: String,
    overage_behavior: OverageBehavior,
    overage_enabled: bool,
    product_id: String,
    remaining_balance: String,
    rollover_enabled: bool,
    unit: String,
    expires_after_days: Option<f64>,
    low_balance_threshold_percent: Option<f64>,
    max_rollover_count: Option<f64>,
    overage_limit: Option<String>,
    rollover_percentage: Option<f64>,
    rollover_timeframe_count: Option<f64>,
    rollover_timeframe_interval: Option<TimeInterval>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OverageBehavior {
    ForgiveAtReset,
    InvoiceAtBilling,
    CarryDeficit,
    CarryDeficitAutoRepay,
}

#[derive(Deserialize)]
struct MeterCreditEntitlement {
    credit_entitlement_id: String,
    meter_id: String,
    meter_name: String,
    meter_units_per_credit: String,
    product_id: String,
}

#[derive(Deserialize)]
struct Meter {
    currency: String,
    free_threshold: f64,
    measurement_unit: String,
    meter_id: String,
    name: String,
    description: Option<String>,
    price_per_unit: Option<String>,
}

#[derive(Deserialize)]
struct ScheduledPlanChange {
    id: String,
    addons: Vec<ScheduledAddon>,
    created_at: String,
    effective_at: String,
    product_id: String,
    quantity: f64,
    product_description: Option<String>,
    product_name: Option<String>,
}

#[derive(Deserialize)]
struct ScheduledAddon {
    addon_id: String,
    name: String,
    quantity: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubscriptionStatus {
    Pending,
    Active,
    OnHold,
    Paused,
    Cancelled,
    Failed,
    Expired,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CancellationFeedback {
    TooExpensive,
    MissingFeatures,
    SwitchedService,
    Unused,
    CustomerService,
    LowQuality,
    TooComplex,
    Other,
}

pub(super) fn subscription(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "payload_type",
            "addons",
            "billing",
            "brand_id",
            "cancel_at_next_billing_date",
            "created_at",
            "credit_entitlement_cart",
            "currency",
            "customer",
            "metadata",
            "meter_credit_entitlement_cart",
            "meters",
            "next_billing_date",
            "on_demand",
            "payment_frequency_count",
            "payment_frequency_interval",
            "previous_billing_date",
            "product_id",
            "quantity",
            "recurring_pre_tax_amount",
            "status",
            "subscription_id",
            "subscription_period_count",
            "subscription_period_interval",
            "tax_inclusive",
            "trial_period_days",
            "cancellation_comment",
            "cancellation_feedback",
            "cancelled_at",
            "custom_field_responses",
            "customer_business_name",
            "discount_cycles_remaining",
            "discount_id",
            "discounts",
            "expires_at",
            "paused_at",
            "payment_method_id",
            "scheduled_change",
            "tax_id",
            "trial_amount",
        ],
    );
    projection::object_array(&mut value, "addons", addon);
    projection::nested_object(&mut value, "billing", super::common::billing_address);
    projection::object_array(&mut value, "credit_entitlement_cart", credit_entitlement);
    projection::nested_object(&mut value, "customer", super::common::customer);
    projection::object_array(
        &mut value,
        "meter_credit_entitlement_cart",
        meter_credit_entitlement,
    );
    projection::object_array(&mut value, "meters", meter);
    projection::object_array(
        &mut value,
        "custom_field_responses",
        super::common::custom_field_response,
    );
    projection::object_array(&mut value, "discounts", super::common::discount_detail);
    projection::nested_object(&mut value, "scheduled_change", scheduled_plan_change);
    value
}

fn addon(value: &Value) -> Value {
    projection::object(value, &["addon_id", "quantity"])
}

fn credit_entitlement(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "credit_entitlement_id",
            "credit_entitlement_name",
            "credits_amount",
            "overage_balance",
            "overage_behavior",
            "overage_enabled",
            "product_id",
            "remaining_balance",
            "rollover_enabled",
            "unit",
            "expires_after_days",
            "low_balance_threshold_percent",
            "max_rollover_count",
            "overage_limit",
            "rollover_percentage",
            "rollover_timeframe_count",
            "rollover_timeframe_interval",
        ],
    )
}

fn meter_credit_entitlement(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "credit_entitlement_id",
            "meter_id",
            "meter_name",
            "meter_units_per_credit",
            "product_id",
        ],
    )
}

fn meter(value: &Value) -> Value {
    projection::object(
        value,
        &[
            "currency",
            "free_threshold",
            "measurement_unit",
            "meter_id",
            "name",
            "description",
            "price_per_unit",
        ],
    )
}

fn scheduled_plan_change(value: &Value) -> Value {
    let mut value = projection::object(
        value,
        &[
            "id",
            "addons",
            "created_at",
            "effective_at",
            "product_id",
            "quantity",
            "product_description",
            "product_name",
        ],
    );
    projection::object_array(&mut value, "addons", scheduled_addon);
    value
}

fn scheduled_addon(value: &Value) -> Value {
    projection::object(value, &["addon_id", "name", "quantity"])
}
