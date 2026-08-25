mod customer;
mod customization;
mod product;

use super::common::*;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoCheckoutSessionInput {
    pub(crate) body: Map<String, Value>,
}

impl DodoCheckoutSessionInput {
    pub(crate) fn slug(&self) -> Option<&str> {
        string(&self.body, "slug")
    }

    pub(crate) fn reference_id(&self) -> Option<&str> {
        string(&self.body, "referenceId")
    }

    pub(crate) fn product_cart(&self) -> Option<&Vec<Value>> {
        self.body.get("product_cart").and_then(Value::as_array)
    }

    pub(crate) fn into_body(self) -> Map<String, Value> {
        self.body
    }
}

pub(crate) fn parse_checkout_session(
    value: Value,
) -> Result<DodoCheckoutSessionInput, DodoInputError> {
    let mut body = root_object(value)?;
    retain_schema_fields(&mut body);
    product::normalize_cart(&mut body)?;
    product::normalize_payment_methods(&mut body)?;
    customer::normalize_billing_address(&mut body)?;
    optional_string_rule(
        &body,
        "billing_currency",
        "body.billing_currency",
        true,
        StringRule::Length(3),
    )?;
    normalize_scalar_fields(&body)?;
    customer::normalize_customer(&mut body)?;
    customer::normalize_custom_fields(&mut body)?;
    customization::normalize_customization(&mut body)?;
    customization::normalize_feature_flags(&mut body)?;
    customer::normalize_subscription_data(&mut body)?;
    normalize_discount_codes(&mut body, "discount_codes", "body.discount_codes", true)?;
    normalize_record(&mut body, "metadata", "body.metadata", true)?;
    Ok(DodoCheckoutSessionInput { body })
}

fn retain_schema_fields(body: &mut Map<String, Value>) {
    const FIELDS: &[&str] = &[
        "product_cart",
        "allowed_payment_method_types",
        "billing_address",
        "billing_currency",
        "cancel_url",
        "confirm",
        "custom_fields",
        "customer",
        "customer_business_name",
        "customization",
        "discount_code",
        "discount_codes",
        "feature_flags",
        "force_3ds",
        "mandate_min_amount_inr_paise",
        "metadata",
        "minimal_address",
        "payment_method_id",
        "product_collection_id",
        "return_url",
        "short_link",
        "show_saved_payment_methods",
        "subscription_data",
        "tax_id",
        "slug",
        "referenceId",
    ];
    body.retain(|key, _| FIELDS.contains(&key.as_str()));
}

fn normalize_scalar_fields(body: &Map<String, Value>) -> Result<(), DodoInputError> {
    for key in [
        "cancel_url",
        "customer_business_name",
        "discount_code",
        "payment_method_id",
        "product_collection_id",
        "tax_id",
    ] {
        optional_string(body, key, &format!("body.{key}"), true)?;
    }
    for key in [
        "confirm",
        "minimal_address",
        "short_link",
        "show_saved_payment_methods",
    ] {
        optional_bool(body, key, &format!("body.{key}"), false)?;
    }
    optional_bool(body, "force_3ds", "body.force_3ds", true)?;
    optional_number(
        body,
        "mandate_min_amount_inr_paise",
        "body.mandate_min_amount_inr_paise",
        NumberRule::Integer,
        true,
    )?;
    optional_string_rule(body, "return_url", "body.return_url", true, StringRule::Url)?;
    optional_string(body, "slug", "body.slug", false)?;
    optional_string(body, "referenceId", "body.referenceId", false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_every_nested_field_family() {
        let parsed = parse_checkout_session(json!({
            "product_cart":[{"product_id":"product_1","quantity":1,"amount":0,
                "addons":[{"addon_id":"addon_1","quantity":0,"unknown":true}],
                "credit_entitlements":[{"credit_entitlement_id":"credit_1","credits_amount":"2.5","unknown":true}],"unknown":true}],
            "allowed_payment_method_types":["ach","satispay"],
            "billing_address":{"country":"GB","city":null,"unknown":true},"billing_currency":"GBP",
            "cancel_url":"/cancel","confirm":true,
            "custom_fields":[{"field_type":"dropdown","key":"size","label":"Size","options":["S","M"],"placeholder":null,"required":true,"unknown":true}],
            "customer":{"email":"user@example.com","name":"User","phone_number":null,"customer_id":"stripped"},
            "customer_business_name":null,
            "customization":{"force_language":"en","show_on_demand_tag":true,"show_order_details":false,"theme":"system",
                "theme_config":{"dark":{"bg_primary":"#000","text_success":null,"unknown":true},"light":null,
                    "font_primary_url":null,"font_secondary_url":"font","font_size":"2xl","font_weight":"extraBold",
                    "pay_button_text":"Pay","radius":"4px","unknown":true},"unknown":true},
            "discount_code":null,"discount_codes":["SAVE","VIP"],
            "feature_flags":{"allow_currency_selection":true,"require_phone_number":false,"unknown":true},
            "force_3ds":null,"mandate_min_amount_inr_paise":-1,
            "metadata":{"source":"auth","count":2,"trial":true},"minimal_address":false,
            "payment_method_id":null,"product_collection_id":"collection_1",
            "return_url":"https://app.example.test/done","short_link":true,"show_saved_payment_methods":false,
            "subscription_data":{"on_demand":{"mandate_only":true,"adaptive_currency_fees_inclusive":null,
                "product_currency":"USD","product_description":null,"product_price":100,"unknown":true},
                "trial_period_days":0,"unknown":true},
            "tax_id":null,"slug":"pro","referenceId":"reference_1","unknown_top_level":true
        })).unwrap();
        assert_eq!(parsed.slug(), Some("pro"));
        assert_eq!(parsed.reference_id(), Some("reference_1"));
        assert_eq!(parsed.product_cart().unwrap().len(), 1);
        assert!(parsed.body.get("unknown_top_level").is_none());
        assert!(parsed.body["product_cart"][0].get("unknown").is_none());
        assert!(
            parsed.body["customization"]["theme_config"]["dark"]
                .get("unknown")
                .is_none()
        );
        assert_eq!(
            parsed.body["customer"],
            json!({"email":"user@example.com","name":"User","phone_number":null})
        );
        assert_eq!(
            parsed.into_body()["subscription_data"]["on_demand"]["product_price"],
            100
        );
    }

    #[test]
    fn customer_union_and_nullability_match_zod_order() {
        let by_id = parse_checkout_session(json!({
            "customer":{"email":"invalid","customer_id":"customer_1","unknown":true}
        }))
        .unwrap();
        assert_eq!(by_id.body["customer"], json!({"customer_id":"customer_1"}));
        let fallback = parse_checkout_session(json!({
            "customer":{"email":"user@example.com","name":3,"customer_id":"customer_2"}
        }))
        .unwrap();
        assert_eq!(
            fallback.body["customer"],
            json!({"customer_id":"customer_2"})
        );
        assert!(parse_checkout_session(json!({"customer":{"email":"invalid"}})).is_err());
        assert!(parse_checkout_session(json!({"customer":{"email":".a@example.com"}})).is_err());
        assert!(parse_checkout_session(json!({"customer":{"email":"a..b@example.com"}})).is_err());
        assert_eq!(
            parse_checkout_session(json!({"customer":null}))
                .unwrap()
                .body["customer"],
            Value::Null
        );
        assert_eq!(
            parse_checkout_session(json!({"subscription_data":null}))
                .unwrap()
                .body["subscription_data"],
            Value::Null
        );
        assert_eq!(
            parse_checkout_session(json!({"custom_fields":[{
                "field_type":"dropdown","key":"size","label":"Size","options":[""]
            }]}))
            .unwrap()
            .body["custom_fields"][0]["options"],
            json!([""])
        );
    }

    #[test]
    fn rejects_each_pinned_boundary() {
        let cases = [
            (
                json!({"product_cart":[]}),
                "At least one product is required",
            ),
            (
                json!({"product_cart":[{"product_id":"","quantity":1}]}),
                "Product ID is required",
            ),
            (
                json!({"product_cart":[{"product_id":"p","quantity":1.5}]}),
                "Invalid number",
            ),
            (
                json!({"billing_address":{"country":"USA"}}),
                "Country must be a 2-letter ISO code",
            ),
            (
                json!({"billing_currency":"US"}),
                "Currency must be a 3-letter ISO code",
            ),
            (json!({"return_url":"/relative"}), "Invalid url"),
            (
                json!({"discount_codes":[""]}),
                "Discount code cannot be empty",
            ),
            (json!({"subscription_data":{}}), "on_demand] Required"),
        ];
        for (input, message) in cases {
            assert!(
                parse_checkout_session(input)
                    .unwrap_err()
                    .message()
                    .contains(message)
            );
        }
        let too_many = json!({"discount_codes":(0..21).map(|index|format!("code_{index}")).collect::<Vec<_>>()});
        assert!(
            parse_checkout_session(too_many)
                .unwrap_err()
                .message()
                .contains("At most 20")
        );
    }
}
