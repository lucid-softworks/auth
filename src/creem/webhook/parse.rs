use serde_json::{Map, Value};

const ENTITY_DISCRIMINATORS: &[&str] = &[
    "checkout",
    "customer",
    "order",
    "product",
    "subscription",
    "refund",
    "dispute",
    "transaction",
    "discount",
];

#[derive(Debug, Clone, PartialEq)]
pub struct CreemWebhookEvent {
    pub event_type: String,
    pub id: String,
    pub created_at: serde_json::Number,
    pub object: Map<String, Value>,
}

pub fn parse_webhook_event(payload: &str) -> Result<CreemWebhookEvent, CreemWebhookParseError> {
    let value: Value = serde_json::from_str(payload).map_err(|_| CreemWebhookParseError)?;
    let envelope = value.as_object().ok_or(CreemWebhookParseError)?;
    let event_type = envelope
        .get("eventType")
        .and_then(Value::as_str)
        .ok_or(CreemWebhookParseError)?;
    let id = envelope
        .get("id")
        .and_then(Value::as_str)
        .ok_or(CreemWebhookParseError)?;
    let created_at = envelope
        .get("created_at")
        .and_then(Value::as_number)
        .cloned()
        .ok_or(CreemWebhookParseError)?;
    let object = envelope
        .get("object")
        .and_then(Value::as_object)
        .ok_or(CreemWebhookParseError)?;
    let discriminator = object
        .get("object")
        .and_then(Value::as_str)
        .ok_or(CreemWebhookParseError)?;
    if !ENTITY_DISCRIMINATORS.contains(&discriminator) {
        return Err(CreemWebhookParseError);
    }
    Ok(CreemWebhookEvent {
        event_type: event_type.into(),
        id: id.into(),
        created_at,
        object: object.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Invalid webhook event")]
pub struct CreemWebhookParseError;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parser_is_shallow_and_allows_event_entity_mismatches_and_extras() {
        let payload = json!({
            "eventType": "checkout.completed",
            "id": "event_1",
            "created_at": 1.25,
            "envelopeExtra": true,
            "object": {
                "object": "discount",
                "nested": {"not": "validated"},
                "extra": true
            }
        });
        let event = parse_webhook_event(&payload.to_string()).unwrap();
        assert_eq!(event.event_type, "checkout.completed");
        assert_eq!(event.created_at.as_f64(), Some(1.25));
        assert_eq!(event.object["nested"]["not"], "validated");
        assert_eq!(event.object["extra"], true);
    }

    #[test]
    fn parser_recognizes_exactly_the_nine_library_entity_discriminators() {
        for discriminator in ENTITY_DISCRIMINATORS {
            let payload = json!({
                "eventType": "any.string.is.accepted",
                "id": "event_1",
                "created_at": 1,
                "object": {"object": discriminator}
            });
            assert!(parse_webhook_event(&payload.to_string()).is_ok());
        }
        for invalid in [
            json!(null),
            json!({}),
            json!({"eventType": 1, "id": "e", "created_at": 1, "object": {"object":"checkout"}}),
            json!({"eventType": "x", "id": 1, "created_at": 1, "object": {"object":"checkout"}}),
            json!({"eventType": "x", "id": "e", "created_at": "1", "object": {"object":"checkout"}}),
            json!({"eventType": "x", "id": "e", "created_at": 1, "object": {"object":"invoice"}}),
        ] {
            assert!(parse_webhook_event(&invalid.to_string()).is_err());
        }
    }
}
