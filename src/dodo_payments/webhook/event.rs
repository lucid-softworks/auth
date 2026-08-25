use crate::dodo_payments::{DodoWebhookEvent, DodoWebhookEventType};
use serde_json::{Map, Value};

mod schema;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DodoWebhookParseError {
    message: String,
}

impl DodoWebhookParseError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn parse_webhook_payload(body: &str) -> Result<DodoWebhookEvent, DodoWebhookParseError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|error| DodoWebhookParseError::invalid(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| DodoWebhookParseError::invalid("Invalid webhook payload"))?;
    let business_id = required_string(object, "business_id")?;
    let event_name = required_string(object, "type")?;
    let timestamp = required_string(object, "timestamp")?;
    let data = object
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| DodoWebhookParseError::invalid("Invalid webhook payload data"))?;
    let event_type = DodoWebhookEventType::parse(event_name);
    let data = schema::normalize(event_type, &Value::Object(data.clone()))
        .map_err(|()| DodoWebhookParseError::invalid(format!("Invalid {event_name} payload")))?;

    let payload = serde_json::json!({
        "business_id": business_id,
        "type": event_name,
        "timestamp": timestamp,
        "data": data,
    });
    Ok(DodoWebhookEvent {
        event_type,
        payload,
    })
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, DodoWebhookParseError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DodoWebhookParseError::invalid(format!("Invalid webhook {key}")))
}

#[cfg(test)]
mod tests {
    include!("event/contract_cases.rs");
}
