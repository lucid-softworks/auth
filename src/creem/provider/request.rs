use serde::Serialize;
use serde_json::{Map, Value};

pub type CreemMetadata = Map<String, Value>;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct CreemCheckoutCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CreemCustomFieldType {
    Text,
    Checkbox,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct CreemTextFieldConfig {
    #[serde(rename = "max_length", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<f64>,
    #[serde(rename = "min_length", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct CreemCheckboxFieldConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CreemCustomField {
    #[serde(rename = "type")]
    pub field_type: CreemCustomFieldType,
    pub key: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<CreemTextFieldConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkbox: Option<CreemCheckboxFieldConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CreemCheckoutRequest {
    #[serde(rename = "request_id", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "product_id")]
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<f64>,
    #[serde(rename = "discount_code", skip_serializing_if = "Option::is_none")]
    pub discount_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<CreemCheckoutCustomer>,
    #[serde(rename = "custom_fields", skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CreemCustomField>>,
    #[serde(rename = "success_url", skip_serializing_if = "Option::is_none")]
    pub success_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CreemMetadata>,
}

impl CreemCheckoutRequest {
    pub(crate) fn wire_value(&self) -> Result<Value, &'static str> {
        validate_number(self.units)?;
        if let Some(fields) = &self.custom_fields {
            for field in fields {
                if let Some(text) = &field.text {
                    validate_number(text.max_length)?;
                    validate_number(text.min_length)?;
                }
            }
        }
        serde_json::to_value(self).map_err(|_| "Input validation failed")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CreemPortalRequest {
    #[serde(rename = "customer_id")]
    pub customer_id: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreemTransactionSearch {
    pub customer_id: Option<String>,
    pub order_id: Option<String>,
    pub product_id: Option<String>,
    pub page_number: Option<f64>,
    pub page_size: Option<f64>,
}

impl CreemTransactionSearch {
    pub fn page_number(&self) -> f64 {
        self.page_number.unwrap_or(1.0)
    }

    pub fn page_size(&self) -> f64 {
        self.page_size.unwrap_or(10.0)
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        validate_number(Some(self.page_number()))?;
        validate_number(Some(self.page_size()))
    }
}

fn validate_number(value: Option<f64>) -> Result<(), &'static str> {
    if value.is_some_and(|value| !value.is_finite()) {
        Err("Input validation failed")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkout_serialization_matches_the_sdk_outbound_names() {
        let request = CreemCheckoutRequest {
            request_id: Some("request 1".into()),
            product_id: "product_1".into(),
            units: Some(1.5),
            discount_code: Some("SAVE".into()),
            customer: Some(CreemCheckoutCustomer {
                id: None,
                email: Some("user@example.com".into()),
            }),
            custom_fields: Some(vec![CreemCustomField {
                field_type: CreemCustomFieldType::Text,
                key: "name".into(),
                label: "Name".into(),
                optional: Some(true),
                text: Some(CreemTextFieldConfig {
                    max_length: Some(20.0),
                    min_length: None,
                }),
                checkbox: None,
            }]),
            success_url: Some("https://app.test/success".into()),
            metadata: Some(Map::from_iter([("nested".into(), json!({"kept": true}))])),
        };

        assert_eq!(
            request.wire_value().unwrap(),
            json!({
                "request_id": "request 1",
                "product_id": "product_1",
                "units": 1.5,
                "discount_code": "SAVE",
                "customer": {"email": "user@example.com"},
                "custom_fields": [{
                    "type": "text",
                    "key": "name",
                    "label": "Name",
                    "optional": true,
                    "text": {"max_length": 20.0}
                }],
                "success_url": "https://app.test/success",
                "metadata": {"nested": {"kept": true}}
            })
        );
    }

    #[test]
    fn sdk_pagination_defaults_are_one_and_ten() {
        let search = CreemTransactionSearch::default();
        assert_eq!(search.page_number(), 1.0);
        assert_eq!(search.page_size(), 10.0);
    }

    #[test]
    fn rejects_non_finite_sdk_numbers() {
        let request = CreemCheckoutRequest {
            request_id: None,
            product_id: "product_1".into(),
            units: Some(f64::NAN),
            discount_code: None,
            customer: None,
            custom_fields: None,
            success_url: None,
            metadata: None,
        };
        assert_eq!(request.wire_value(), Err("Input validation failed"));
    }
}
