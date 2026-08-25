use crate::creem::{
    CreemCheckboxFieldConfig, CreemCustomField, CreemCustomFieldType, CreemTextFieldConfig,
};
use serde::Deserialize;
use serde_json::{Map, Value};

const INVALID_INPUT: &str = "Invalid input";
const MISSING_PRODUCT_ID: &str =
    "[body.productId] Invalid input: expected string, received undefined";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CheckoutInput {
    pub product_id: String,
    pub request_id: Option<String>,
    pub units: Option<f64>,
    pub discount_code: Option<String>,
    pub customer: Option<CheckoutCustomerInput>,
    pub custom_fields: Option<Vec<CustomFieldInput>>,
    pub custom_field: Option<Vec<CustomFieldInput>>,
    pub success_url: Option<String>,
    pub metadata: Option<Map<String, Value>>,
}

impl CheckoutInput {
    pub(super) fn parse(value: Value) -> Result<Self, &'static str> {
        if value.get("productId").is_none() {
            return Err(MISSING_PRODUCT_ID);
        }
        let input: Self = serde_json::from_value(value).map_err(|_| INVALID_INPUT)?;
        if input.units.is_some_and(|units| units <= 0.0) {
            return Err(INVALID_INPUT);
        }
        validate_fields(input.custom_fields.as_deref())?;
        validate_fields(input.custom_field.as_deref())?;
        if input
            .customer
            .as_ref()
            .and_then(|customer| customer.email.as_deref())
            .is_some_and(|email| !crate::service::valid_email(email))
        {
            return Err(INVALID_INPUT);
        }
        Ok(input)
    }

    pub(super) fn selected_custom_fields(&self) -> Option<Vec<CreemCustomField>> {
        self.custom_fields
            .as_ref()
            .or(self.custom_field.as_ref())
            .map(|fields| fields.iter().map(CustomFieldInput::provider).collect())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct CheckoutCustomerInput {
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CustomFieldInput {
    #[serde(rename = "type")]
    field_type: CustomFieldKind,
    key: String,
    label: String,
    optional: Option<bool>,
    text: Option<TextFieldInput>,
    checkbox: Option<CheckboxFieldInput>,
}

impl CustomFieldInput {
    fn provider(&self) -> CreemCustomField {
        CreemCustomField {
            field_type: match self.field_type {
                CustomFieldKind::Text => CreemCustomFieldType::Text,
                CustomFieldKind::Checkbox => CreemCustomFieldType::Checkbox,
            },
            key: self.key.clone(),
            label: self.label.clone(),
            optional: self.optional,
            text: self.text.as_ref().map(|text| CreemTextFieldConfig {
                max_length: text.max_length,
                min_length: text.min_length,
            }),
            checkbox: self
                .checkbox
                .as_ref()
                .map(|checkbox| CreemCheckboxFieldConfig {
                    label: checkbox.label.clone(),
                }),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CustomFieldKind {
    Text,
    Checkbox,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextFieldInput {
    max_length: Option<f64>,
    min_length: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CheckboxFieldInput {
    label: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdInput {
    pub id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortalInput {
    pub customer_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchInput {
    pub customer_id: Option<String>,
    pub order_id: Option<String>,
    pub product_id: Option<String>,
    pub page_number: Option<f64>,
    pub page_size: Option<f64>,
}

impl SearchInput {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.page_number.is_some_and(|page| page < 1.0)
            || self.page_size.is_some_and(|size| size <= 0.0)
        {
            Err(INVALID_INPUT)
        } else {
            Ok(())
        }
    }
}

fn validate_fields(fields: Option<&[CustomFieldInput]>) -> Result<(), &'static str> {
    let Some(fields) = fields else {
        return Ok(());
    };
    if fields.len() > 3
        || fields.iter().any(|field| {
            field.key.encode_utf16().count() > 200 || field.label.encode_utf16().count() > 50
        })
    {
        Err(INVALID_INPUT)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkout_accepts_fractional_units_and_singular_custom_field() {
        let input = CheckoutInput::parse(json!({
            "productId": "",
            "units": 1.5,
            "customField": [{"type":"text", "key":"name", "label":"Name"}]
        }))
        .unwrap();
        assert_eq!(input.selected_custom_fields().unwrap().len(), 1);
    }

    #[test]
    fn plural_custom_fields_has_nullish_precedence_even_when_empty() {
        let input = CheckoutInput::parse(json!({
            "productId": "product",
            "customFields": [],
            "customField": [{"type":"checkbox", "key":"tos", "label":"Terms"}]
        }))
        .unwrap();
        assert!(input.selected_custom_fields().unwrap().is_empty());
    }

    #[test]
    fn zod_number_and_utf16_length_boundaries_are_enforced() {
        assert!(CheckoutInput::parse(json!({"productId":"p", "units":0})).is_err());
        let astral = "🦀".repeat(101);
        assert!(
            CheckoutInput::parse(json!({
                "productId":"p",
                "customFields":[{"type":"text", "key":astral, "label":"ok"}]
            }))
            .is_err()
        );
        assert!(
            SearchInput {
                page_number: Some(1.25),
                page_size: Some(0.5),
                ..SearchInput::default()
            }
            .validate()
            .is_ok()
        );
    }
}
