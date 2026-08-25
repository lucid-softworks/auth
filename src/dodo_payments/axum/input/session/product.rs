use super::super::common::*;
use serde_json::{Map, Value};

pub(super) fn normalize_cart(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("product_cart") else {
        return Ok(());
    };
    let items = array_mut_at(value, "body.product_cart")?;
    if items.is_empty() {
        return Err(error(
            "[body.product_cart] At least one product is required".into(),
        ));
    }
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("body.product_cart.{index}");
        let map = object_mut_at(item, &path)?;
        require_nested(map, "product_id", &path)?;
        require_nested(map, "quantity", &path)?;
        optional_string_rule(
            map,
            "product_id",
            &format!("{path}.product_id"),
            false,
            StringRule::Nonempty("Product ID is required"),
        )?;
        optional_number(
            map,
            "quantity",
            &format!("{path}.quantity"),
            NumberRule::PositiveInteger,
            false,
        )?;
        optional_number(
            map,
            "amount",
            &format!("{path}.amount"),
            NumberRule::NonnegativeInteger,
            true,
        )?;
        normalize_addons(map, &path)?;
        normalize_credits(map, &path)?;
        map.retain(|key, _| {
            [
                "product_id",
                "quantity",
                "addons",
                "amount",
                "credit_entitlements",
            ]
            .contains(&key.as_str())
        });
    }
    Ok(())
}

fn normalize_addons(map: &mut Map<String, Value>, parent: &str) -> Result<(), DodoInputError> {
    let Some(value) = map.get_mut("addons") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let items = array_mut_at(value, &format!("{parent}.addons"))?;
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("{parent}.addons.{index}");
        let fields = object_mut_at(item, &path)?;
        require_nested(fields, "addon_id", &path)?;
        require_nested(fields, "quantity", &path)?;
        optional_string(fields, "addon_id", &format!("{path}.addon_id"), false)?;
        optional_number(
            fields,
            "quantity",
            &format!("{path}.quantity"),
            NumberRule::NonnegativeInteger,
            false,
        )?;
        fields.retain(|key, _| key == "addon_id" || key == "quantity");
    }
    Ok(())
}

fn normalize_credits(map: &mut Map<String, Value>, parent: &str) -> Result<(), DodoInputError> {
    let Some(value) = map.get_mut("credit_entitlements") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let items = array_mut_at(value, &format!("{parent}.credit_entitlements"))?;
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("{parent}.credit_entitlements.{index}");
        let fields = object_mut_at(item, &path)?;
        for key in ["credit_entitlement_id", "credits_amount"] {
            require_nested(fields, key, &path)?;
            let message = if key == "credit_entitlement_id" {
                "credit_entitlement_id is required"
            } else {
                "credits_amount is required (string for precision)"
            };
            optional_string_rule(
                fields,
                key,
                &format!("{path}.{key}"),
                false,
                StringRule::Nonempty(message),
            )?;
        }
        fields.retain(|key, _| key == "credit_entitlement_id" || key == "credits_amount");
    }
    Ok(())
}

pub(super) fn normalize_payment_methods(
    body: &mut Map<String, Value>,
) -> Result<(), DodoInputError> {
    const METHODS: &str = "ach|affirm|afterpay_clearpay|alfamart|ali_pay|ali_pay_hk|alma|amazon_pay|apple_pay|atome|bacs|bancontact_card|becs|benefit|bizum|blik|boleto|bca_bank_transfer|bni_va|bri_va|card_redirect|cimb_va|classic|credit|crypto_currency|cashapp|dana|danamon_va|debit|duit_now|efecty|eft|eps|fps|evoucher|giropay|givex|google_pay|go_pay|gcash|ideal|interac|indomaret|klarna|kakao_pay|local_bank_redirect|mandiri_va|knet|mb_way|mobile_pay|momo|momo_atm|multibanco|online_banking_thailand|online_banking_czech_republic|online_banking_finland|online_banking_fpx|online_banking_poland|online_banking_slovakia|oxxo|pago_efectivo|permata_bank_transfer|open_banking_uk|pay_bright|paypal|paze|pix|pay_safe_card|przelewy24|prompt_pay|pse|red_compra|red_pagos|samsung_pay|sepa|sepa_bank_transfer|sofort|sunbit|swish|touch_n_go|trustly|twint|upi_collect|upi_intent|vipps|viet_qr|venmo|walley|we_chat_pay|seven_eleven|lawson|mini_stop|family_mart|seicomart|pay_easy|local_bank_transfer|mifinity|open_banking_pis|direct_carrier_billing|instant_bank_transfer|billie|zip|revolut_pay|naver_pay|payco|satispay";
    optional_string_array(
        body,
        "allowed_payment_method_types",
        "body.allowed_payment_method_types",
        true,
        false,
    )?;
    if let Some(Value::Array(methods)) = body.get("allowed_payment_method_types") {
        for (index, method) in methods.iter().enumerate() {
            let Some(method) = method.as_str() else {
                continue;
            };
            if !METHODS.split('|').any(|candidate| candidate == method) {
                return Err(error(format!(
                    "[body.allowed_payment_method_types.{index}] Invalid enum value"
                )));
            }
        }
    }
    Ok(())
}
