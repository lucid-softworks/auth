use crate::polar::{PolarMetadata, PolarTrialInterval};
use serde_json::{Map, Value};
use url::Url;

mod query;

pub(super) use query::{SubscriptionsInput, order_query, page_query};

#[derive(Debug, Clone, PartialEq)]
pub(super) struct CheckoutInput {
    pub products: Option<Vec<String>>,
    pub slug: Option<String>,
    pub reference_id: Option<String>,
    pub custom_field_data: Option<PolarMetadata>,
    pub metadata: Option<PolarMetadata>,
    pub allow_discount_codes: bool,
    pub discount_id: Option<String>,
    pub redirect: bool,
    pub embed_origin: Option<String>,
    pub success_url: Option<String>,
    pub return_url: Option<String>,
    pub allow_trial: Option<bool>,
    pub trial_interval: Option<PolarTrialInterval>,
    pub trial_interval_count: Option<u16>,
}

impl CheckoutInput {
    pub fn parse(value: Value) -> Result<Self, InputError> {
        let object = object(value)?;
        Ok(Self {
            products: optional_products(&object, "products")?,
            slug: optional_string(&object, "slug")?,
            reference_id: optional_string(&object, "referenceId")?,
            custom_field_data: optional_primitive_map(&object, "customFieldData", None)?,
            metadata: optional_primitive_map(&object, "metadata", Some(MetadataLimits))?,
            allow_discount_codes: coerced_boolean(&object, "allowDiscountCodes", true),
            discount_id: optional_string(&object, "discountId")?,
            redirect: coerced_boolean(&object, "redirect", true),
            embed_origin: optional_absolute_url(&object, "embedOrigin")?,
            success_url: optional_callback_url(&object, "successUrl")?,
            return_url: optional_callback_url(&object, "returnUrl")?,
            allow_trial: optional_boolean(&object, "allowTrial")?,
            trial_interval: optional_trial_interval(&object)?,
            trial_interval_count: optional_bounded_integer(&object, "trialIntervalCount", 1, 1000)?
                .map(|value| value as u16),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortalInput {
    redirect: Option<bool>,
}

impl PortalInput {
    pub fn redirect(self) -> bool {
        self.redirect.unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct IngestInput {
    pub event: String,
    pub metadata: PolarMetadata,
}

impl IngestInput {
    pub fn parse(value: Value) -> Result<Self, InputError> {
        let object = object(value)?;
        let event = required_string(&object, "event")?;
        let metadata = required_primitive_map(&object, "metadata", None)?;
        Ok(Self { event, metadata })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InputError {
    message: String,
}

impl InputError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

fn object(value: Value) -> Result<Map<String, Value>, InputError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| InputError::new("body must be an object"))
}

fn optional_products(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, InputError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(vec![value.clone()])),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| InputError::new("products must contain only strings"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(InputError::new("products must be a string or string array")),
    }
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<Option<String>, InputError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(InputError::new(format!("{key} must be a string"))),
    }
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, InputError> {
    optional_string(object, key)?.ok_or_else(|| InputError::new(format!("{key} is required")))
}

fn optional_boolean(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, InputError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(InputError::new(format!("{key} must be a boolean"))),
    }
}

fn coerced_boolean(object: &Map<String, Value>, key: &str, default: bool) -> bool {
    object.get(key).map(js_truthy).unwrap_or(default)
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn optional_absolute_url(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, InputError> {
    let value = optional_string(object, key)?;
    value
        .map(|value| {
            Url::parse(&value)
                .map(|_| value)
                .map_err(|_| InputError::new(format!("{key} must be an absolute URL")))
        })
        .transpose()
}

fn optional_callback_url(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, InputError> {
    let value = optional_string(object, key)?;
    value
        .map(|value| {
            if value.starts_with('/') || Url::parse(&value).is_ok() {
                Ok(value)
            } else {
                Err(InputError::new(format!(
                    "{key} must be an absolute URL or start with /"
                )))
            }
        })
        .transpose()
}

fn optional_trial_interval(
    object: &Map<String, Value>,
) -> Result<Option<PolarTrialInterval>, InputError> {
    match optional_string(object, "trialInterval")?.as_deref() {
        None => Ok(None),
        Some("day") => Ok(Some(PolarTrialInterval::Day)),
        Some("week") => Ok(Some(PolarTrialInterval::Week)),
        Some("month") => Ok(Some(PolarTrialInterval::Month)),
        Some("year") => Ok(Some(PolarTrialInterval::Year)),
        Some(_) => Err(InputError::new("trialInterval is invalid")),
    }
}

fn optional_bounded_integer(
    object: &Map<String, Value>,
    key: &str,
    minimum: i64,
    maximum: i64,
) -> Result<Option<i64>, InputError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let value = value
        .as_i64()
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .ok_or_else(|| {
            InputError::new(format!(
                "{key} must be an integer from {minimum} to {maximum}"
            ))
        })?;
    Ok(Some(value))
}

#[derive(Debug, Clone, Copy)]
struct MetadataLimits;

fn optional_primitive_map(
    object: &Map<String, Value>,
    key: &str,
    limits: Option<MetadataLimits>,
) -> Result<Option<PolarMetadata>, InputError> {
    object
        .get(key)
        .map(|value| primitive_map(value, key, limits))
        .transpose()
}

fn required_primitive_map(
    object: &Map<String, Value>,
    key: &str,
    limits: Option<MetadataLimits>,
) -> Result<PolarMetadata, InputError> {
    object
        .get(key)
        .ok_or_else(|| InputError::new(format!("{key} is required")))
        .and_then(|value| primitive_map(value, key, limits))
}

fn primitive_map(
    value: &Value,
    field: &str,
    limits: Option<MetadataLimits>,
) -> Result<PolarMetadata, InputError> {
    let map = value
        .as_object()
        .ok_or_else(|| InputError::new(format!("{field} must be an object")))?;
    if limits.is_some() && map.len() > 50 {
        return Err(InputError::new("metadata must have at most 50 entries"));
    }
    for (key, value) in map {
        if !matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
            return Err(InputError::new(format!(
                "{field} values must be strings, numbers, or booleans"
            )));
        }
        if limits.is_some() && key.encode_utf16().count() > 40 {
            return Err(InputError::new(
                "metadata keys must have at most 40 characters",
            ));
        }
        if limits.is_some()
            && value
                .as_str()
                .is_some_and(|value| value.encode_utf16().count() > 500)
        {
            return Err(InputError::new(
                "metadata string values must have at most 500 characters",
            ));
        }
    }
    Ok(map.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkout_matches_zod_boolean_coercion_and_url_rules() {
        let input = CheckoutInput::parse(json!({
            "products": "product_1",
            "allowDiscountCodes": "false",
            "redirect": "",
            "successUrl": "/thanks"
        }))
        .unwrap();
        assert_eq!(input.products, Some(vec!["product_1".into()]));
        assert!(input.allow_discount_codes);
        assert!(!input.redirect);
        assert_eq!(input.success_url.as_deref(), Some("/thanks"));
        assert!(CheckoutInput::parse(json!({ "returnUrl": "thanks" })).is_err());
    }

    #[test]
    fn metadata_limits_count_javascript_utf16_code_units() {
        let accepted = "😀".repeat(250);
        let rejected = "😀".repeat(251);
        assert!(CheckoutInput::parse(json!({ "metadata": { "key": accepted } })).is_ok());
        assert!(CheckoutInput::parse(json!({ "metadata": { "key": rejected } })).is_err());
        let long_key = "😀".repeat(21);
        assert!(CheckoutInput::parse(json!({ "metadata": { long_key: true } })).is_err());
    }

    #[test]
    fn portal_redirect_defaults_true_and_deserializes_only_booleans() {
        assert!(PortalInput::default().redirect());
        let disabled: PortalInput = serde_json::from_value(json!({ "redirect": false })).unwrap();
        assert!(!disabled.redirect());
        assert!(serde_json::from_value::<PortalInput>(Value::Null).is_err());
        assert!(serde_json::from_value::<PortalInput>(json!({ "redirect": "false" })).is_err());
    }
}
