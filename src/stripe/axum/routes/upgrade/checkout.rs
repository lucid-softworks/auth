use crate::{
    CheckoutSessionOverrides, CustomerType, StripeMetadata, StripePlan, Subscription,
    UpgradeSubscriptionInput, merge_metadata,
};
use serde_json::{Map, Value, json};

pub(super) struct CheckoutArguments<'a> {
    pub input: &'a UpgradeSubscriptionInput,
    pub plan: &'a StripePlan,
    pub subscription: &'a Subscription,
    pub customer_id: Option<&'a str>,
    pub customer_type: CustomerType,
    pub user_id: &'a str,
    pub user_email: &'a str,
    pub reference_id: &'a str,
    pub price_id: &'a str,
    pub metered: bool,
    pub automatic_seats: bool,
    pub member_count: f64,
    pub free_trial: bool,
    pub callback: Option<CheckoutSessionOverrides>,
    pub success_endpoint: &'a str,
    pub absolute_success_url: &'a dyn Fn(&str) -> String,
    pub absolute_cancel_url: &'a dyn Fn(&str) -> String,
}

pub(super) fn params(arguments: CheckoutArguments<'_>) -> Value {
    let callback = callback_object(arguments.callback.as_ref());
    let mut output = callback.clone();
    for protected in [
        "mode",
        "customer",
        "customer_email",
        "success_url",
        "cancel_url",
        "line_items",
        "client_reference_id",
        "subscription_data",
        "metadata",
    ] {
        output.remove(protected);
    }
    apply_checkout_fields(&mut output, &callback, &arguments);
    apply_metadata_fields(&mut output, &callback, &arguments);
    Value::Object(output)
}

fn apply_checkout_fields(
    output: &mut Map<String, Value>,
    callback: &Map<String, Value>,
    arguments: &CheckoutArguments<'_>,
) {
    output.insert("mode".into(), json!("subscription"));
    if let Some(customer_id) = arguments.customer_id {
        output.insert("customer".into(), json!(customer_id));
        let provided = callback.get("customer_update");
        if provided.is_none_or(Value::is_null) {
            output.insert(
                "customer_update".into(),
                if arguments.customer_type == CustomerType::User {
                    json!({ "name": "auto", "address": "auto" })
                } else {
                    json!({ "address": "auto" })
                },
            );
        }
    } else {
        output.insert("customer_email".into(), json!(arguments.user_email));
    }
    if let Some(locale) = &arguments.input.locale {
        output.insert("locale".into(), json!(locale));
    } else if let Some(locale) = callback.get("locale") {
        output.insert("locale".into(), locale.clone());
    }
    let callback_url = encode_uri_component(&arguments.input.success_url);
    let success = format!(
        "{}?callbackURL={callback_url}&checkoutSessionId={{CHECKOUT_SESSION_ID}}",
        arguments.success_endpoint
    );
    output.insert(
        "success_url".into(),
        json!((arguments.absolute_success_url)(&success)),
    );
    output.insert(
        "cancel_url".into(),
        json!((arguments.absolute_cancel_url)(&arguments.input.cancel_url)),
    );
    output.insert("line_items".into(), Value::Array(line_items(arguments)));
    output.insert("client_reference_id".into(), json!(arguments.reference_id));
}

fn apply_metadata_fields(
    output: &mut Map<String, Value>,
    callback: &Map<String, Value>,
    arguments: &CheckoutArguments<'_>,
) {
    let request_metadata = input_metadata(arguments.input);
    let callback_metadata = metadata(callback.get("metadata"));
    // Keep the UUID allocation alive while the borrowed protected fields are merged.
    let subscription_id = arguments.subscription.id.to_string();
    let protected = [
        ("userId", arguments.user_id),
        ("subscriptionId", subscription_id.as_str()),
        ("referenceId", arguments.reference_id),
    ];
    output.insert(
        "metadata".into(),
        serde_json::to_value(merge_metadata(
            [&request_metadata, &callback_metadata],
            protected,
        ))
        .expect("Stripe metadata is JSON"),
    );

    let mut subscription_data = callback
        .get("subscription_data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if arguments.free_trial {
        subscription_data
            .entry("trial_period_days")
            .or_insert(json!(
                arguments.plan.free_trial.as_ref().map(|trial| trial.days)
            ));
    }
    let callback_subscription_metadata = metadata(subscription_data.get("metadata"));
    subscription_data.insert(
        "metadata".into(),
        serde_json::to_value(merge_metadata(
            [&request_metadata, &callback_subscription_metadata],
            protected,
        ))
        .expect("Stripe metadata is JSON"),
    );
    output.insert("subscription_data".into(), Value::Object(subscription_data));
}

fn line_items(arguments: &CheckoutArguments<'_>) -> Vec<Value> {
    let seat_only = arguments.automatic_seats
        && arguments.plan.seat_price_id.as_deref() == arguments.plan.price_id.as_deref();
    let mut items = Vec::new();
    if !seat_only {
        let mut base = Map::from_iter([("price".into(), json!(arguments.price_id))]);
        if !arguments.metered {
            base.insert(
                "quantity".into(),
                json!(if arguments.automatic_seats {
                    1.0
                } else {
                    js_or_one(arguments.input.seats)
                }),
            );
        }
        items.push(Value::Object(base));
    }
    if arguments.automatic_seats {
        items.push(json!({
            "price": arguments.plan.seat_price_id,
            "quantity": arguments.member_count,
        }));
    }
    items.extend(arguments.plan.line_items.iter().map(|item| {
        let mut value = item.extra.clone();
        if let Some(price) = &item.price {
            value.insert("price".into(), price.clone());
        }
        if let Some(quantity) = item.quantity {
            value.insert("quantity".into(), json!(quantity));
        }
        Value::Object(value)
    }));
    items
}

pub(super) fn js_or_one(value: Option<f64>) -> f64 {
    value.filter(|value| *value != 0.0).unwrap_or(1.0)
}

fn callback_object(callback: Option<&CheckoutSessionOverrides>) -> Map<String, Value> {
    callback
        .and_then(|callback| callback.params.as_object())
        .cloned()
        .unwrap_or_default()
}

fn input_metadata(input: &UpgradeSubscriptionInput) -> StripeMetadata {
    input
        .metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| metadata.iter())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn metadata(value: Option<&Value>) -> StripeMetadata {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|metadata| metadata.iter())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn encode_uri_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckoutLineItem, ProrationBehavior, StripeRequestOptions, SubscriptionStatus};
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn callback_keeps_broad_fields_but_cannot_override_protected_fields() {
        let input = request();
        let plan = plan();
        let subscription = subscription();
        let callback = CheckoutSessionOverrides {
            params: json!({
                "mode": "payment",
                "customer": "attacker",
                "success_url": "https://evil.test",
                "line_items": [{ "price": "evil" }],
                "allow_promotion_codes": true,
                "locale": "fr",
                "customer_update": { "shipping": "auto" },
                "metadata": { "subscriptionId": "evil", "callback": "kept" },
                "subscription_data": {
                    "description": "kept",
                    "metadata": { "referenceId": "evil", "nested": "kept" }
                }
            }),
            options: Some(StripeRequestOptions::default()),
        };
        let value = params(arguments(&input, &plan, &subscription, Some(callback)));
        assert_eq!(value["mode"], "subscription");
        assert_eq!(value["customer"], "cus_real");
        assert_eq!(value["allow_promotion_codes"], true);
        assert_eq!(value["locale"], "fr");
        assert_eq!(value["customer_update"]["shipping"], "auto");
        assert_eq!(
            value["metadata"]["subscriptionId"],
            subscription.id.to_string()
        );
        assert_eq!(value["metadata"]["callback"], "kept");
        assert_eq!(value["subscription_data"]["description"], "kept");
        assert_eq!(value["subscription_data"]["referenceId"], Value::Null);
        assert_eq!(value["subscription_data"]["metadata"]["referenceId"], "ref");
    }

    #[test]
    fn metered_seat_only_checkout_has_one_seat_item() {
        let input = request();
        let mut plan = plan();
        plan.price_id = Some("seat".into());
        plan.seat_price_id = Some("seat".into());
        plan.line_items.clear();
        let subscription = subscription();
        let mut arguments = arguments(&input, &plan, &subscription, None);
        arguments.metered = true;
        arguments.automatic_seats = true;
        arguments.member_count = 7.0;
        let value = params(arguments);
        assert_eq!(
            value["line_items"],
            json!([{ "price": "seat", "quantity": 7.0 }])
        );
    }

    #[test]
    fn zero_seats_matches_javascript_or_one() {
        assert_eq!(js_or_one(Some(0.0)), 1.0);
        assert_eq!(js_or_one(Some(-2.0)), -2.0);
    }

    fn arguments<'a>(
        input: &'a UpgradeSubscriptionInput,
        plan: &'a StripePlan,
        subscription: &'a Subscription,
        callback: Option<CheckoutSessionOverrides>,
    ) -> CheckoutArguments<'a> {
        CheckoutArguments {
            input,
            plan,
            subscription,
            customer_id: Some("cus_real"),
            customer_type: CustomerType::User,
            user_id: "user",
            user_email: "user@example.test",
            reference_id: "ref",
            price_id: "price",
            metered: false,
            automatic_seats: false,
            member_count: 0.0,
            free_trial: true,
            callback,
            success_endpoint: "https://app.test/api/auth/subscription/success",
            absolute_success_url: &|value| value.to_owned(),
            absolute_cancel_url: &|value| format!("https://app.test{value}"),
        }
    }

    fn request() -> UpgradeSubscriptionInput {
        serde_json::from_value(json!({
            "plan": "pro",
            "metadata": { "request": "kept", "referenceId": "evil" }
        }))
        .unwrap()
    }

    fn plan() -> StripePlan {
        StripePlan {
            name: "Pro".into(),
            price_id: Some("price".into()),
            lookup_key: None,
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: None,
            group: None,
            seat_price_id: None,
            proration_behavior: ProrationBehavior::CreateProrations,
            line_items: vec![CheckoutLineItem {
                price: None,
                quantity: Some(2),
                extra: Map::from_iter([("price_data".into(), json!({ "currency": "gbp" }))]),
            }],
            free_trial: Some(crate::FreeTrial {
                days: 14,
                callbacks: None,
            }),
        }
    }

    fn subscription() -> Subscription {
        let now = Utc::now();
        Subscription {
            id: Uuid::new_v4(),
            plan: "pro".into(),
            reference_id: "ref".into(),
            stripe_customer_id: Some("cus_real".into()),
            stripe_subscription_id: None,
            status: SubscriptionStatus::Incomplete,
            period_start: None,
            period_end: None,
            trial_start: None,
            trial_end: None,
            cancel_at_period_end: false,
            cancel_at: None,
            canceled_at: None,
            ended_at: None,
            seats: Some(1.0),
            billing_interval: None,
            stripe_schedule_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}
