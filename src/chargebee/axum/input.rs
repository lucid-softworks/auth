use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CustomerType {
    #[default]
    User,
    Organization,
}

#[derive(Debug)]
pub(super) struct InputError(String);

impl InputError {
    pub(super) fn message(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub(super) struct CreateInput {
    pub item_price_ids: Vec<String>,
    pub success_url: String,
    pub cancel_url: String,
    #[allow(dead_code)]
    pub return_url: Option<String>,
    pub reference_id: Option<String>,
    pub customer_type: CustomerType,
    pub seats: Option<f64>,
    pub metadata: Option<Map<String, Value>>,
    pub disable_redirect: bool,
    pub trial_end: Option<f64>,
}

#[derive(Debug)]
pub(super) struct UpdateInput {
    pub item_price_ids: Vec<String>,
    pub success_url: String,
    pub cancel_url: String,
    #[allow(dead_code)]
    pub return_url: Option<String>,
    pub reference_id: Option<String>,
    pub subscription_id: Option<String>,
    pub customer_type: CustomerType,
    pub seats: Option<f64>,
    pub metadata: Option<Map<String, Value>>,
    pub disable_redirect: bool,
}

#[derive(Debug)]
pub(super) struct PortalInput {
    pub reference_id: Option<String>,
    pub customer_type: CustomerType,
    pub return_url: String,
    pub disable_redirect: bool,
}

#[derive(Debug)]
pub(super) struct CancelInput {
    pub reference_id: Option<String>,
    pub subscription_id: Option<String>,
    pub customer_type: CustomerType,
    pub return_url: String,
    pub disable_redirect: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListQuery {
    pub reference_id: Option<String>,
    pub customer_type: Option<CustomerType>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct CallbackQuery {
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "subscriptionId")]
    pub subscription_id: Option<String>,
}

pub(super) fn create(value: Value) -> Result<CreateInput, InputError> {
    let body = object(value)?;
    let mut errors = Vec::new();
    let item_price_ids = capture(item_price_ids(&body), &mut errors);
    let success_url = capture(required_string(&body, "successUrl"), &mut errors);
    let cancel_url = capture(required_string(&body, "cancelUrl"), &mut errors);
    let return_url = capture(optional_string(&body, "returnUrl"), &mut errors);
    let reference_id = capture(optional_string(&body, "referenceId"), &mut errors);
    let customer_type = capture(optional_customer_type(&body), &mut errors);
    let seats = capture(optional_number(&body, "seats"), &mut errors);
    let metadata = capture(optional_object(&body, "metadata"), &mut errors);
    let disable_redirect = capture(optional_bool(&body, "disableRedirect"), &mut errors);
    let trial_end = capture(optional_number(&body, "trialEnd"), &mut errors);
    reject(errors)?;
    Ok(CreateInput {
        item_price_ids: item_price_ids.expect("itemPriceId is valid after validation"),
        success_url: success_url.expect("successUrl is valid after validation"),
        cancel_url: cancel_url.expect("cancelUrl is valid after validation"),
        return_url: return_url.flatten(),
        reference_id: reference_id.flatten(),
        customer_type: customer_type.flatten().unwrap_or_default(),
        seats: seats.flatten(),
        metadata: metadata.flatten(),
        disable_redirect: disable_redirect.flatten().unwrap_or(false),
        trial_end: trial_end.flatten(),
    })
}

pub(super) fn update(value: Value) -> Result<UpdateInput, InputError> {
    let body = object(value)?;
    let mut errors = Vec::new();
    let item_price_ids = capture(item_price_ids(&body), &mut errors);
    let success_url = capture(required_string(&body, "successUrl"), &mut errors);
    let cancel_url = capture(required_string(&body, "cancelUrl"), &mut errors);
    let return_url = capture(optional_string(&body, "returnUrl"), &mut errors);
    let reference_id = capture(optional_string(&body, "referenceId"), &mut errors);
    let subscription_id = capture(optional_string(&body, "subscriptionId"), &mut errors);
    let customer_type = capture(optional_customer_type(&body), &mut errors);
    let seats = capture(optional_number(&body, "seats"), &mut errors);
    let metadata = capture(optional_object(&body, "metadata"), &mut errors);
    let disable_redirect = capture(optional_bool(&body, "disableRedirect"), &mut errors);
    reject(errors)?;
    Ok(UpdateInput {
        item_price_ids: item_price_ids.expect("itemPriceId is valid after validation"),
        success_url: success_url.expect("successUrl is valid after validation"),
        cancel_url: cancel_url.expect("cancelUrl is valid after validation"),
        return_url: return_url.flatten(),
        reference_id: reference_id.flatten(),
        subscription_id: subscription_id.flatten().filter(|value| !value.is_empty()),
        customer_type: customer_type.flatten().unwrap_or_default(),
        seats: seats.flatten(),
        metadata: metadata.flatten(),
        disable_redirect: disable_redirect.flatten().unwrap_or(false),
    })
}

pub(super) fn portal(value: Value) -> Result<PortalInput, InputError> {
    let body = object(value)?;
    let mut errors = Vec::new();
    let reference_id = capture(optional_string(&body, "referenceId"), &mut errors);
    let customer_type = capture(optional_customer_type(&body), &mut errors);
    let return_url = capture(required_string(&body, "returnUrl"), &mut errors);
    let disable_redirect = capture(optional_bool(&body, "disableRedirect"), &mut errors);
    reject(errors)?;
    Ok(PortalInput {
        reference_id: reference_id.flatten(),
        customer_type: customer_type.flatten().unwrap_or_default(),
        return_url: return_url.expect("returnUrl is valid after validation"),
        disable_redirect: disable_redirect.flatten().unwrap_or(false),
    })
}

pub(super) fn cancel(value: Value) -> Result<CancelInput, InputError> {
    let body = object(value)?;
    let mut errors = Vec::new();
    let reference_id = capture(optional_string(&body, "referenceId"), &mut errors);
    let subscription_id = capture(optional_string(&body, "subscriptionId"), &mut errors);
    let customer_type = capture(optional_customer_type(&body), &mut errors);
    let return_url = capture(required_string(&body, "returnUrl"), &mut errors);
    let disable_redirect = capture(optional_bool(&body, "disableRedirect"), &mut errors);
    reject(errors)?;
    Ok(CancelInput {
        reference_id: reference_id.flatten(),
        subscription_id: subscription_id.flatten().filter(|value| !value.is_empty()),
        customer_type: customer_type.flatten().unwrap_or_default(),
        return_url: return_url.expect("returnUrl is valid after validation"),
        disable_redirect: disable_redirect.flatten().unwrap_or(false),
    })
}

fn object(value: Value) -> Result<Map<String, Value>, InputError> {
    value.as_object().cloned().ok_or_else(|| invalid("body"))
}

fn item_price_ids(body: &Map<String, Value>) -> Result<Vec<String>, InputError> {
    match body.get("itemPriceId") {
        Some(Value::String(value)) => Ok(vec![value.clone()]),
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => Ok(values
            .iter()
            .map(|value| value.as_str().expect("checked string").to_owned())
            .collect()),
        _ => Err(invalid("body.itemPriceId")),
    }
}

fn required_string(body: &Map<String, Value>, key: &str) -> Result<String, InputError> {
    match body.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(invalid(&format!("body.{key}"))),
        None => Err(undefined(&format!("body.{key}"), "string")),
    }
}

fn optional_string(body: &Map<String, Value>, key: &str) -> Result<Option<String>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(&format!("body.{key}"))),
    }
}

fn optional_number(body: &Map<String, Value>, key: &str) -> Result<Option<f64>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or_else(|| invalid(&format!("body.{key}"))),
        Some(_) => Err(invalid(&format!("body.{key}"))),
    }
}

fn optional_bool(body: &Map<String, Value>, key: &str) -> Result<Option<bool>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid(&format!("body.{key}"))),
    }
}

fn optional_object(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<Map<String, Value>>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(&format!("body.{key}"))),
    }
}

fn optional_customer_type(body: &Map<String, Value>) -> Result<Option<CustomerType>, InputError> {
    match body.get("customerType") {
        None => Ok(None),
        Some(Value::String(value)) if value == "user" => Ok(Some(CustomerType::User)),
        Some(Value::String(value)) if value == "organization" => {
            Ok(Some(CustomerType::Organization))
        }
        Some(_) => Err(invalid("body.customerType")),
    }
}

fn capture<T>(result: Result<T, InputError>, errors: &mut Vec<InputError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn reject(errors: Vec<InputError>) -> Result<(), InputError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(InputError(
            errors
                .into_iter()
                .map(|error| error.0)
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn invalid(path: &str) -> InputError {
    InputError(format!("[{path}] Invalid input"))
}

fn undefined(path: &str, expected: &str) -> InputError {
    InputError(format!(
        "[{path}] Invalid input: expected {expected}, received undefined"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_aggregates_in_zod_field_order() {
        assert_eq!(
            create(json!({})).unwrap_err().message(),
            "[body.itemPriceId] Invalid input; [body.successUrl] Invalid input: expected string, received undefined; [body.cancelUrl] Invalid input: expected string, received undefined"
        );
    }

    #[test]
    fn create_retains_declared_return_url_and_strips_unknown_keys() {
        let input = create(json!({
            "itemPriceId": [],
            "successUrl": "/success",
            "cancelUrl": "/cancel",
            "returnUrl": "/unused",
            "unknown": true
        }))
        .unwrap();
        assert!(input.item_price_ids.is_empty());
        assert_eq!(input.return_url.as_deref(), Some("/unused"));
    }

    #[test]
    fn callback_query_only_accepts_exact_casing() {
        let query: CallbackQuery =
            serde_urlencoded::from_str("callbackUrl=%2Fwrong&subscriptionId=local").unwrap();
        assert_eq!(query.callback_url, None);
        assert_eq!(query.subscription_id.as_deref(), Some("local"));
    }

    #[test]
    fn empty_subscription_ids_follow_javascript_falsy_selection() {
        let update = update(json!({
            "itemPriceId": "price",
            "successUrl": "/success",
            "cancelUrl": "/cancel",
            "subscriptionId": ""
        }))
        .unwrap();
        let cancel = cancel(json!({"returnUrl": "/return", "subscriptionId": ""})).unwrap();
        assert_eq!(update.subscription_id, None);
        assert_eq!(cancel.subscription_id, None);
    }
}
