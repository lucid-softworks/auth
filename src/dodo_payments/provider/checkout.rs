use super::DodoCheckoutSession;
use crate::dodo_payments::transport::DodoPaymentsProviderError;
use serde_json::{Map, Value};
use url::Url;

pub(super) fn normalize_checkout_session(
    value: Value,
) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
    let object = value.as_object().ok_or_else(response_validation)?;
    let session_id = object
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(response_validation)?;
    let checkout_url = optional_string(object, "checkout_url")?;
    if checkout_url
        .as_deref()
        .is_some_and(|value| Url::parse(value).is_err())
    {
        return Err(response_validation());
    }
    let client_secret = optional_string(object, "client_secret")?;
    let payment_id = optional_string(object, "payment_id")?;
    let publishable_key = optional_string(object, "publishable_key")?;

    let mut normalized = Map::new();
    normalized.insert("session_id".into(), Value::String(session_id.clone()));
    copy_optional(object, &mut normalized, "checkout_url");
    copy_optional(object, &mut normalized, "client_secret");
    copy_optional(object, &mut normalized, "payment_id");
    copy_optional(object, &mut normalized, "publishable_key");
    Ok(DodoCheckoutSession {
        session_id,
        checkout_url,
        client_secret,
        payment_id,
        publishable_key,
        value: Value::Object(normalized),
    })
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, DodoPaymentsProviderError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(response_validation()),
    }
}

fn copy_optional(source: &Map<String, Value>, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field) {
        target.insert(field.into(), value.clone());
    }
}

fn response_validation() -> DodoPaymentsProviderError {
    DodoPaymentsProviderError::new("Dodo Payments response validation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_and_strips_checkout_session_responses() {
        let checkout = normalize_checkout_session(json!({
            "session_id": "cks_1",
            "checkout_url": "https://checkout.dodopayments.com/session",
            "client_secret": null,
            "payment_id": "pay_1",
            "provider_extra": {"stripped": true}
        }))
        .unwrap();
        assert_eq!(checkout.session_id, "cks_1");
        assert_eq!(checkout.client_secret, None);
        assert_eq!(checkout.payment_id.as_deref(), Some("pay_1"));
        assert_eq!(
            checkout.value,
            json!({
                "session_id": "cks_1",
                "checkout_url": "https://checkout.dodopayments.com/session",
                "client_secret": null,
                "payment_id": "pay_1"
            })
        );
    }

    #[test]
    fn rejects_missing_session_ids_invalid_urls_and_wrong_nullable_types() {
        for value in [
            json!({"checkout_url": "https://checkout.test"}),
            json!({"session_id": ""}),
            json!({"session_id": "cks_1", "checkout_url": "not a URL"}),
            json!({"session_id": "cks_1", "client_secret": 1}),
        ] {
            assert!(normalize_checkout_session(value).is_err());
        }
        assert!(
            normalize_checkout_session(json!({
                "session_id": "cks_1",
                "checkout_url": null,
                "publishable_key": null
            }))
            .is_ok()
        );
    }
}
