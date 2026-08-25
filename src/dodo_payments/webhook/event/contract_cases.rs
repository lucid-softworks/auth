use super::*;
use serde_json::{Value, json};

const TS: &str = "2024-01-01T00:00:00.000Z";

#[derive(Clone, Copy)]
enum Family {
    Payment,
    Refund,
    Dispute,
    Subscription,
    LicenseKey,
    AbandonedCheckout,
    Dunning,
    CreditLedger,
    CreditBalanceLow,
    EntitlementGrant,
    Payout,
}

#[test]
fn every_known_event_accepts_its_complete_pinned_payload() {
    let specs = known_events();
    assert_eq!(specs.len(), 47);
    for (event_name, family) in specs {
        parse(event_name, valid_data(family)).unwrap_or_else(|error| {
            panic!("{event_name} should accept its complete payload: {error}")
        });
    }
}

#[test]
fn every_known_event_rejects_a_malformed_nested_payload() {
    for (event_name, family) in known_events() {
        let error = parse(event_name, malformed_data(family)).unwrap_err();
        assert_eq!(error.to_string(), format!("Invalid {event_name} payload"));
    }
}

#[test]
fn nested_optional_objects_are_validated_when_present() {
    let mut payment = valid_data(Family::Payment);
    payment["discounts"] = json!([{"discount_id": 7}]);
    assert!(parse("payment.succeeded", payment).is_err());

    let mut subscription = valid_data(Family::Subscription);
    subscription["credit_entitlement_cart"] = json!([{
        "credit_entitlement_id": "ce_1",
        "credit_entitlement_name": "Credits",
        "credits_amount": "10",
        "overage_balance": "0",
        "overage_behavior": "unsupported",
        "overage_enabled": false,
        "product_id": "pdt_1",
        "remaining_balance": "10",
        "rollover_enabled": false,
        "unit": "request"
    }]);
    assert!(parse("subscription.active", subscription).is_err());

    let mut entitlement = valid_data(Family::EntitlementGrant);
    entitlement["license_key"] = json!({"activations_used": "zero", "key": "XYZ"});
    assert!(parse("entitlement_grant.delivered", entitlement).is_err());
}

#[test]
fn required_nullable_billing_fields_cannot_be_omitted() {
    let mut payment = valid_data(Family::Payment);
    payment["billing"].as_object_mut().unwrap().remove("city");
    assert!(parse("payment.succeeded", payment).is_err());
}

#[test]
fn unknown_events_are_permissive_but_require_the_top_level_schema() {
    let event = parse_webhook_payload(
        &json!({
            "business_id": "biz_1",
            "type": "future.event",
            "timestamp": TS,
            "data": {"anything": [true, 7, null]},
            "extra": true
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(event.event_type, DodoWebhookEventType::Unknown);
    assert_eq!(event.payload["data"]["anything"][1], 7);
    assert!(event.payload.get("extra").is_none());

    for invalid in [
        json!({"type":"future.event","timestamp":TS,"data":{}}),
        json!({"business_id":"biz_1","timestamp":TS,"data":{}}),
        json!({"business_id":"biz_1","type":"future.event","data":{}}),
        json!({"business_id":"biz_1","type":"future.event","timestamp":TS}),
        json!({"business_id":"biz_1","type":"future.event","timestamp":TS,"data":[]}),
    ] {
        assert!(parse_webhook_payload(&invalid.to_string()).is_err());
    }
}

#[test]
fn known_payload_projection_strips_unknown_top_level_fields() {
    let body = {
        let mut body = envelope("payment.succeeded", valid_data(Family::Payment));
        body["ignored"] = json!({"server": "must not receive this"});
        body
    };
    let event = parse_webhook_payload(&body.to_string()).unwrap();
    assert!(event.payload.get("ignored").is_none());
}

#[test]
fn every_known_payload_root_strips_unknown_fields() {
    for (event_name, family) in known_events() {
        let mut data = valid_data(family);
        data["provider_extension"] = json!({"must": "be stripped"});
        let event = parse(event_name, data).unwrap();
        assert!(
            event.payload["data"].get("provider_extension").is_none(),
            "{event_name} retained an unknown data field"
        );
    }
}

#[test]
fn known_nested_objects_strip_extras_but_open_metadata_records_do_not() {
    let mut payment = valid_data(Family::Payment);
    payment["billing"]["extra"] = json!(true);
    payment["customer"]["extra"] = json!(true);
    payment["metadata"]["provider_extension"] = json!({"nested": true});
    let payment = parse("payment.succeeded", payment).unwrap();
    assert!(payment.payload["data"]["billing"].get("extra").is_none());
    assert!(payment.payload["data"]["customer"].get("extra").is_none());
    assert_eq!(
        payment.payload["data"]["metadata"]["provider_extension"]["nested"],
        true
    );

    let mut subscription = valid_data(Family::Subscription);
    subscription["addons"] = json!([{"addon_id":"addon_1","quantity":1,"extra":true}]);
    let subscription = parse("subscription.active", subscription).unwrap();
    assert!(
        subscription.payload["data"]["addons"][0]
            .get("extra")
            .is_none()
    );

    let mut entitlement = valid_data(Family::EntitlementGrant);
    entitlement["license_key"] = json!({"activations_used":0,"key":"XYZ","extra":true});
    entitlement["digital_product_delivery"] = json!({
        "files":[{
            "download_url":"https://example.com/file",
            "expires_in":60,
            "file_id":"file_1",
            "filename":"asset.zip",
            "extra":true
        }],
        "extra":true
    });
    let entitlement = parse("entitlement_grant.delivered", entitlement).unwrap();
    assert!(
        entitlement.payload["data"]["license_key"]
            .get("extra")
            .is_none()
    );
    assert!(
        entitlement.payload["data"]["digital_product_delivery"]
            .get("extra")
            .is_none()
    );
    assert!(
        entitlement.payload["data"]["digital_product_delivery"]["files"][0]
            .get("extra")
            .is_none()
    );
}

#[test]
fn projection_preserves_explicit_null_and_omitted_optional_fields() {
    let mut payment = valid_data(Family::Payment);
    payment["card_last_four"] = Value::Null;
    payment["customer"]["phone_number"] = Value::Null;
    let payment = parse("payment.succeeded", payment).unwrap();
    assert!(payment.payload["data"]["card_last_four"].is_null());
    assert!(payment.payload["data"]["customer"]["phone_number"].is_null());
    assert!(payment.payload["data"].get("invoice_id").is_none());
}

#[test]
fn zod_date_transform_inputs_remain_native_json_strings() {
    let event = parse("payout.created", valid_data(Family::Payout)).unwrap();
    assert_eq!(event.payload["timestamp"], TS);
    assert_eq!(event.payload["data"]["created_at"], TS);

    let mut payout = valid_data(Family::Payout);
    payout["created_at"] = json!(7);
    assert!(parse("payout.created", payout).is_err());
}

fn parse(event_name: &str, data: Value) -> Result<DodoWebhookEvent, DodoWebhookParseError> {
    parse_webhook_payload(&envelope(event_name, data).to_string())
}

fn envelope(event_name: &str, data: Value) -> Value {
    json!({
        "business_id": "biz_1",
        "type": event_name,
        "timestamp": TS,
        "data": data,
    })
}

fn malformed_data(family: Family) -> Value {
    let mut data = valid_data(family);
    match family {
        Family::Payment | Family::Refund | Family::Dispute => {
            data["customer"]["email"] = json!(7);
        }
        Family::Subscription => data["billing"]["country"] = json!(7),
        Family::LicenseKey => data["source"] = json!("generated"),
        Family::AbandonedCheckout => data["status"] = json!("missing"),
        Family::Dunning => data["trigger_state"] = json!("paused"),
        Family::CreditLedger => data["metadata"] = json!([]),
        Family::CreditBalanceLow => data["threshold_percent"] = json!("10"),
        Family::EntitlementGrant => data["integration_type"] = json!("email"),
        Family::Payout => data["status"] = json!("cancelled"),
    }
    data
}

fn valid_data(family: Family) -> Value {
    match family {
        Family::Payment => payment(),
        Family::Refund => refund(),
        Family::Dispute => dispute(),
        Family::Subscription => subscription(),
        Family::LicenseKey => license_key(),
        Family::AbandonedCheckout => abandoned_checkout(),
        Family::Dunning => dunning(),
        Family::CreditLedger => credit_ledger(),
        Family::CreditBalanceLow => credit_balance_low(),
        Family::EntitlementGrant => entitlement_grant(),
        Family::Payout => payout(),
    }
}

fn billing() -> Value {
    json!({"city":null,"country":"US","state":null,"street":null,"zipcode":null})
}

fn customer() -> Value {
    json!({"customer_id":"cus_1","email":"a@b.com","name":"A"})
}

fn payment() -> Value {
    json!({
        "payload_type":"Payment","billing":billing(),"brand_id":"brand_1",
        "business_id":"biz_1","created_at":TS,"currency":"USD","customer":customer(),
        "digital_products_delivered":false,"disputes":[],"is_update_payment_method":false,
        "metadata":{},"payment_id":"pay_1","payment_provider":"dodo","refunds":[],
        "retry_attempt":0,"settlement_amount":1000,"settlement_currency":"USD",
        "total_amount":1000
    })
}

fn refund() -> Value {
    json!({
        "payload_type":"Refund","brand_id":"brand_1","business_id":"biz_1",
        "created_at":TS,"customer":customer(),"is_partial":false,"metadata":{},
        "payment_id":"pay_1","refund_id":"ref_1","status":"succeeded"
    })
}

fn dispute() -> Value {
    json!({
        "payload_type":"Dispute","amount":"1000","brand_id":"brand_1",
        "business_id":"biz_1","created_at":TS,"currency":"USD","customer":customer(),
        "dispute_id":"dis_1","dispute_stage":"pre_dispute",
        "dispute_status":"dispute_opened","payment_id":"pay_1","payment_provider":"dodo"
    })
}

fn subscription() -> Value {
    json!({
        "payload_type":"Subscription","addons":[],"billing":billing(),"brand_id":"brand_1",
        "cancel_at_next_billing_date":false,"created_at":TS,"credit_entitlement_cart":[],
        "currency":"USD","customer":customer(),"metadata":{},
        "meter_credit_entitlement_cart":[],"meters":[],"next_billing_date":TS,
        "on_demand":false,"payment_frequency_count":1,"payment_frequency_interval":"Month",
        "previous_billing_date":TS,"product_id":"pdt_1","quantity":1,
        "recurring_pre_tax_amount":1000,"status":"active","subscription_id":"sub_1",
        "subscription_period_count":1,"subscription_period_interval":"Month",
        "tax_inclusive":false,"trial_period_days":0
    })
}

fn license_key() -> Value {
    json!({
        "payload_type":"LicenseKey","id":"lic_1","brand_id":"brand_1",
        "business_id":"biz_1","created_at":TS,"customer_id":"cus_1",
        "instances_count":0,"key":"XYZ","product_id":"pdt_1","source":"auto",
        "status":"active"
    })
}

fn abandoned_checkout() -> Value {
    json!({
        "payload_type":"AbandonedCheckout","abandoned_at":TS,
        "abandonment_reason":"payment_failed","brand_id":"brand_1","customer_id":"cus_1",
        "payment_id":"pay_1","status":"abandoned"
    })
}

fn dunning() -> Value {
    json!({
        "payload_type":"DunningAttempt","brand_id":"brand_1","created_at":TS,
        "customer_id":"cus_1","status":"recovering","subscription_id":"sub_1",
        "trigger_state":"on_hold"
    })
}

fn credit_ledger() -> Value {
    json!({
        "payload_type":"CreditLedgerEntry","id":"cle_1","amount":"1",
        "balance_after":"1","balance_before":"0","brand_id":"brand_1",
        "business_id":"biz_1","created_at":TS,"credit_entitlement_id":"ce_1",
        "customer_id":"cus_1","is_credit":true,"metadata":{},"overage_after":"0",
        "overage_before":"0","transaction_type":"overage_reset"
    })
}

fn credit_balance_low() -> Value {
    json!({
        "payload_type":"CreditBalanceLow","available_balance":"1","brand_id":"brand_1",
        "credit_entitlement_id":"ce_1","credit_entitlement_name":"Credits",
        "customer_id":"cus_1","subscription_credits_amount":"10",
        "subscription_id":"sub_1","threshold_amount":"1","threshold_percent":10
    })
}

fn entitlement_grant() -> Value {
    json!({
        "payload_type":"EntitlementGrant","id":"eg_1","brand_id":"brand_1",
        "business_id":"biz_1","created_at":TS,"customer_id":"cus_1",
        "entitlement_id":"ent_1","integration_type":"license_key","metadata":{},
        "status":"Delivered","updated_at":TS
    })
}

fn payout() -> Value {
    json!({
        "amount":1000,"business_id":"biz_1","chargebacks":0,"created_at":TS,
        "currency":"USD","fee":50,"payment_method":"bank_transfer","payout_id":"po_1",
        "refunds":0,"status":"success","tax":0,"updated_at":TS
    })
}

fn known_events() -> Vec<(&'static str, Family)> {
    use Family::*;
    vec![
        ("payment.succeeded", Payment),
        ("payment.failed", Payment),
        ("payment.processing", Payment),
        ("payment.cancelled", Payment),
        ("refund.succeeded", Refund),
        ("refund.failed", Refund),
        ("dispute.opened", Dispute),
        ("dispute.expired", Dispute),
        ("dispute.accepted", Dispute),
        ("dispute.cancelled", Dispute),
        ("dispute.challenged", Dispute),
        ("dispute.won", Dispute),
        ("dispute.lost", Dispute),
        ("subscription.active", Subscription),
        ("subscription.on_hold", Subscription),
        ("subscription.renewed", Subscription),
        ("subscription.plan_changed", Subscription),
        ("subscription.cancelled", Subscription),
        ("subscription.failed", Subscription),
        ("subscription.expired", Subscription),
        ("subscription.updated", Subscription),
        ("subscription.paused", Subscription),
        ("subscription.unpaused", Subscription),
        ("subscription.update_payment_method", Subscription),
        ("license_key.created", LicenseKey),
        ("abandoned_checkout.detected", AbandonedCheckout),
        ("abandoned_checkout.recovered", AbandonedCheckout),
        ("dunning.started", Dunning),
        ("dunning.recovered", Dunning),
        ("credit.added", CreditLedger),
        ("credit.deducted", CreditLedger),
        ("credit.expired", CreditLedger),
        ("credit.rolled_over", CreditLedger),
        ("credit.rollover_forfeited", CreditLedger),
        ("credit.overage_charged", CreditLedger),
        ("credit.overage_reset", CreditLedger),
        ("credit.manual_adjustment", CreditLedger),
        ("credit.balance_low", CreditBalanceLow),
        ("entitlement_grant.created", EntitlementGrant),
        ("entitlement_grant.delivered", EntitlementGrant),
        ("entitlement_grant.failed", EntitlementGrant),
        ("entitlement_grant.revoked", EntitlementGrant),
        ("payout.created", Payout),
        ("payout.on_hold", Payout),
        ("payout.in_progress", Payout),
        ("payout.failed", Payout),
        ("payout.success", Payout),
    ]
}
