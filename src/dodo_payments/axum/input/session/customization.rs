use super::super::common::*;
use serde_json::{Map, Value};

pub(super) fn normalize_customization(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("customization") else {
        return Ok(());
    };
    let fields = object_mut_at(value, "body.customization")?;
    optional_string(
        fields,
        "force_language",
        "body.customization.force_language",
        true,
    )?;
    optional_bool(
        fields,
        "show_on_demand_tag",
        "body.customization.show_on_demand_tag",
        false,
    )?;
    optional_bool(
        fields,
        "show_order_details",
        "body.customization.show_order_details",
        false,
    )?;
    enum_string(
        fields,
        "theme",
        "body.customization.theme",
        "dark|light|system",
        true,
    )?;
    normalize_theme_config(fields)?;
    fields.retain(|key, _| {
        [
            "force_language",
            "show_on_demand_tag",
            "show_order_details",
            "theme",
            "theme_config",
        ]
        .contains(&key.as_str())
    });
    Ok(())
}

fn normalize_theme_config(customization: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = customization.get_mut("theme_config") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let fields = object_mut_at(value, "body.customization.theme_config")?;
    for mode in ["dark", "light"] {
        normalize_theme_mode(fields, mode)?;
    }
    for key in [
        "font_primary_url",
        "font_secondary_url",
        "pay_button_text",
        "radius",
    ] {
        optional_string(
            fields,
            key,
            &format!("body.customization.theme_config.{key}"),
            true,
        )?;
    }
    enum_string(
        fields,
        "font_size",
        "body.customization.theme_config.font_size",
        "xs|sm|md|lg|xl|2xl",
        true,
    )?;
    enum_string(
        fields,
        "font_weight",
        "body.customization.theme_config.font_weight",
        "normal|medium|bold|extraBold",
        true,
    )?;
    fields.retain(|key, _| {
        [
            "dark",
            "font_primary_url",
            "font_secondary_url",
            "font_size",
            "font_weight",
            "light",
            "pay_button_text",
            "radius",
        ]
        .contains(&key.as_str())
    });
    Ok(())
}

fn normalize_theme_mode(theme: &mut Map<String, Value>, mode: &str) -> Result<(), DodoInputError> {
    let Some(value) = theme.get_mut(mode) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let fields = object_mut_at(value, &format!("body.customization.theme_config.{mode}"))?;
    const KEYS: &[&str] = &[
        "bg_primary",
        "bg_secondary",
        "border_primary",
        "border_secondary",
        "button_primary",
        "button_primary_hover",
        "button_secondary",
        "button_secondary_hover",
        "button_text_primary",
        "button_text_secondary",
        "input_focus_border",
        "text_error",
        "text_placeholder",
        "text_primary",
        "text_secondary",
        "text_success",
    ];
    for key in KEYS {
        optional_string(
            fields,
            key,
            &format!("body.customization.theme_config.{mode}.{key}"),
            true,
        )?;
    }
    fields.retain(|key, _| KEYS.contains(&key.as_str()));
    Ok(())
}

pub(super) fn normalize_feature_flags(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut("feature_flags") else {
        return Ok(());
    };
    let fields = object_mut_at(value, "body.feature_flags")?;
    const KEYS: &[&str] = &[
        "allow_currency_selection",
        "allow_customer_editing_business_name",
        "allow_customer_editing_city",
        "allow_customer_editing_country",
        "allow_customer_editing_email",
        "allow_customer_editing_name",
        "allow_customer_editing_state",
        "allow_customer_editing_street",
        "allow_customer_editing_tax_id",
        "allow_customer_editing_zipcode",
        "allow_discount_code",
        "allow_editing_addons",
        "allow_phone_number_collection",
        "allow_tax_id",
        "always_create_new_customer",
        "redirect_immediately",
        "require_phone_number",
    ];
    for key in KEYS {
        optional_bool(fields, key, &format!("body.feature_flags.{key}"), false)?;
    }
    fields.retain(|key, _| KEYS.contains(&key.as_str()));
    Ok(())
}
