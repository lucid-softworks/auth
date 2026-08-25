use super::super::common::*;
use serde_json::{Map, Value};

pub(super) fn normalize_customer(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("customer") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let fields = object_mut_at(value, "body.customer")?;
    let mut email_branch = fields.clone();
    let email_branch_valid = email_branch
        .get("email")
        .and_then(Value::as_str)
        .is_some_and(email_is_valid)
        && optional_string_rule(
            &email_branch,
            "name",
            "body.customer.name",
            true,
            StringRule::Nonempty("String must contain at least 1 character(s)"),
        )
        .is_ok()
        && optional_string(
            &email_branch,
            "phone_number",
            "body.customer.phone_number",
            true,
        )
        .is_ok();
    if email_branch_valid {
        email_branch.retain(|key, _| ["email", "name", "phone_number"].contains(&key.as_str()));
        *fields = email_branch;
        return Ok(());
    }
    if fields.get("customer_id").is_some_and(Value::is_string) {
        fields.retain(|key, _| key == "customer_id");
        return Ok(());
    }
    Err(error("[body.customer] Invalid input".into()))
}

pub(super) fn normalize_billing_address(
    body: &mut Map<String, Value>,
) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("billing_address") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let fields = object_mut_at(value, "body.billing_address")?;
    require_nested(fields, "country", "body.billing_address")?;
    optional_string_rule(
        fields,
        "country",
        "body.billing_address.country",
        false,
        StringRule::Length(2),
    )?;
    for key in ["street", "city", "state", "zipcode"] {
        optional_string(fields, key, &format!("body.billing_address.{key}"), true)?;
    }
    fields
        .retain(|key, _| ["street", "city", "state", "country", "zipcode"].contains(&key.as_str()));
    Ok(())
}

pub(super) fn normalize_custom_fields(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("custom_fields") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let items = array_mut_at(value, "body.custom_fields")?;
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("body.custom_fields.{index}");
        let fields = object_mut_at(item, &path)?;
        for key in ["field_type", "key", "label"] {
            require_nested(fields, key, &path)?;
        }
        enum_string(
            fields,
            "field_type",
            &format!("{path}.field_type"),
            "text|number|email|url|date|dropdown|boolean",
            false,
        )?;
        optional_string(fields, "key", &format!("{path}.key"), false)?;
        optional_string(fields, "label", &format!("{path}.label"), false)?;
        optional_string(fields, "placeholder", &format!("{path}.placeholder"), true)?;
        optional_bool(fields, "required", &format!("{path}.required"), false)?;
        optional_string_array(fields, "options", &format!("{path}.options"), true, true)?;
        fields.retain(|key, _| {
            [
                "field_type",
                "key",
                "label",
                "options",
                "placeholder",
                "required",
            ]
            .contains(&key.as_str())
        });
    }
    Ok(())
}

pub(super) fn normalize_subscription_data(
    body: &mut Map<String, Value>,
) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("subscription_data") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let fields = object_mut_at(value, "body.subscription_data")?;
    require_nested(fields, "on_demand", "body.subscription_data")?;
    optional_number(
        fields,
        "trial_period_days",
        "body.subscription_data.trial_period_days",
        NumberRule::NonnegativeInteger,
        true,
    )?;
    if let Some(on_demand) = fields.get_mut("on_demand")
        && !on_demand.is_null()
    {
        normalize_on_demand(on_demand)?;
    }
    fields.retain(|key, _| key == "on_demand" || key == "trial_period_days");
    Ok(())
}

fn normalize_on_demand(value: &mut Value) -> Result<(), DodoInputError> {
    let fields = object_mut_at(value, "body.subscription_data.on_demand")?;
    require_nested(fields, "mandate_only", "body.subscription_data.on_demand")?;
    optional_bool(
        fields,
        "mandate_only",
        "body.subscription_data.on_demand.mandate_only",
        false,
    )?;
    optional_bool(
        fields,
        "adaptive_currency_fees_inclusive",
        "body.subscription_data.on_demand.adaptive_currency_fees_inclusive",
        true,
    )?;
    for key in ["product_currency", "product_description"] {
        optional_string(
            fields,
            key,
            &format!("body.subscription_data.on_demand.{key}"),
            true,
        )?;
    }
    optional_number(
        fields,
        "product_price",
        "body.subscription_data.on_demand.product_price",
        NumberRule::Integer,
        true,
    )?;
    fields.retain(|key, _| {
        [
            "mandate_only",
            "adaptive_currency_fees_inclusive",
            "product_currency",
            "product_description",
            "product_price",
        ]
        .contains(&key.as_str())
    });
    Ok(())
}
