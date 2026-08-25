use crate::creem::CreemPersistenceError;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{Map, Value};

pub(super) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(super) fn truthy_member<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| truthy(value))
}

pub(super) fn truthy_string_member<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, CreemPersistenceError> {
    match truthy_member(object, key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid(key)),
        None => Ok(None),
    }
}

pub(super) fn object_member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|object| object.get(key))
}

pub(super) fn required_object_like_member<'a>(
    object: &'a Map<String, Value>,
    container: &str,
    member: &str,
) -> Result<Option<&'a Value>, CreemPersistenceError> {
    match object.get(container) {
        None | Some(Value::Null) => Err(invalid(container)),
        Some(value) => Ok(object_member(value, member)),
    }
}

pub(super) fn optional_string(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, CreemPersistenceError> {
    match value {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(field)),
    }
}

pub(super) fn truthy_string(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, CreemPersistenceError> {
    match value.filter(|value| truthy(value)) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(field)),
    }
}

pub(super) fn parsed_truthy_date(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, CreemPersistenceError> {
    let Some(value) = value.filter(|value| truthy(value)) else {
        return Ok(None);
    };
    parse_date(value).ok_or_else(|| invalid(field)).map(Some)
}

fn parse_date(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::String(value) => DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc))
            .ok()
            .or_else(|| {
                NaiveDate::parse_from_str(value, "%Y-%m-%d")
                    .ok()?
                    .and_hms_opt(0, 0, 0)
                    .map(|value| value.and_utc())
            }),
        Value::Number(value) => {
            let milliseconds = value.as_f64()?.trunc();
            if !(i64::MIN as f64..=i64::MAX as f64).contains(&milliseconds) {
                return None;
            }
            DateTime::from_timestamp_millis(milliseconds as i64)
        }
        Value::Bool(true) => DateTime::from_timestamp_millis(1),
        _ => None,
    }
}

pub(super) fn invalid(field: &str) -> CreemPersistenceError {
    CreemPersistenceError::new(format!("Invalid Creem webhook field: {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_truthiness_matches_values_reachable_from_webhooks() {
        for value in [json!(null), json!(false), json!(0), json!(0.0), json!("")] {
            assert!(!truthy(&value));
        }
        for value in [json!(true), json!(1), json!("0"), json!([]), json!({})] {
            assert!(truthy(&value));
        }
    }

    #[test]
    fn provider_dates_accept_iso_text_date_only_and_javascript_milliseconds() {
        assert_eq!(
            parsed_truthy_date(Some(&json!("2026-08-25T13:00:00+01:00")), "date")
                .unwrap()
                .unwrap()
                .to_rfc3339(),
            "2026-08-25T12:00:00+00:00"
        );
        assert_eq!(
            parsed_truthy_date(Some(&json!("2026-08-25")), "date")
                .unwrap()
                .unwrap()
                .timestamp(),
            1_787_616_000
        );
        assert_eq!(
            parsed_truthy_date(Some(&json!(1)), "date")
                .unwrap()
                .unwrap()
                .timestamp_millis(),
            1
        );
    }
}
