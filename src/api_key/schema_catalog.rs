use super::ApiKeyConfiguration;
use crate::{AdditionalField, AdditionalFieldType, PluginSchemaTable};
use serde_json::json;

pub(super) fn table(config: Option<&ApiKeyConfiguration>) -> PluginSchemaTable {
    let (window, maximum) = config.map_or((86_400_000, 10), |config| {
        (
            config.rate_limit.time_window_milliseconds,
            config.rate_limit.max_requests,
        )
    });
    let table = PluginSchemaTable::new("apikey")
        .field(
            "configId",
            AdditionalField::new(AdditionalFieldType::String)
                .default_value(json!("default"))
                .input(false)
                .index(true),
        )
        .field("name", server_optional(AdditionalFieldType::String))
        .field("start", server_optional(AdditionalFieldType::String))
        .field(
            "referenceId",
            AdditionalField::new(AdditionalFieldType::String)
                .input(false)
                .index(true),
        )
        .field("prefix", server_optional(AdditionalFieldType::String))
        .field(
            "key",
            AdditionalField::new(AdditionalFieldType::String)
                .input(false)
                .index(true),
        )
        .field(
            "refillInterval",
            server_optional(AdditionalFieldType::Number),
        )
        .field("refillAmount", server_optional(AdditionalFieldType::Number))
        .field("lastRefillAt", server_optional(AdditionalFieldType::Date));
    table
        .field("enabled", server_boolean(true))
        .field("rateLimitEnabled", server_boolean(true))
        .field("rateLimitTimeWindow", server_number(window))
        .field("rateLimitMax", server_number(maximum))
        .field("requestCount", server_number(0))
        .field("remaining", server_optional(AdditionalFieldType::Number))
        .field("lastRequest", server_optional(AdditionalFieldType::Date))
        .field("expiresAt", server_optional(AdditionalFieldType::Date))
        .field(
            "createdAt",
            AdditionalField::new(AdditionalFieldType::Date).input(false),
        )
        .field(
            "updatedAt",
            AdditionalField::new(AdditionalFieldType::Date).input(false),
        )
        .field("permissions", server_optional(AdditionalFieldType::String))
        .field("metadata", metadata())
}

fn optional(field_type: AdditionalFieldType) -> AdditionalField {
    AdditionalField::new(field_type).optional()
}

fn server_optional(field_type: AdditionalFieldType) -> AdditionalField {
    optional(field_type).input(false)
}

fn server_boolean(value: bool) -> AdditionalField {
    optional(AdditionalFieldType::Boolean)
        .input(false)
        .default_value(json!(value))
}

fn server_number(value: i64) -> AdditionalField {
    optional(AdditionalFieldType::Number)
        .input(false)
        .default_value(json!(value))
}

fn metadata() -> AdditionalField {
    optional(AdditionalFieldType::String)
        .transform_input(std::sync::Arc::new(|value: serde_json::Value| {
            serde_json::to_string(&value)
                .map(serde_json::Value::String)
                .map_err(|error| crate::AuthError::InvalidRequest(error.to_string()))
        }))
        .transform_output(std::sync::Arc::new(|value: serde_json::Value| {
            if !json_truthy(&value) {
                return Ok(serde_json::Value::Null);
            }
            let Some(value) = value.as_str() else {
                return Ok(value);
            };
            Ok(serde_json::from_str(value)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_owned())))
        }))
}

fn json_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
        serde_json::Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Array(_)
        | serde_json::Value::Object(_)
        | serde_json::Value::Bool(true) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApiKeyRateLimitConfig;

    #[test]
    fn exact_server_owned_field_policy_and_multi_config_defaults() {
        let config = ApiKeyConfiguration {
            config_id: "custom".into(),
            rate_limit: ApiKeyRateLimitConfig {
                enabled: false,
                time_window_milliseconds: 123,
                max_requests: 7,
            },
            ..ApiKeyConfiguration::default()
        };
        let sole = table(Some(&config));
        assert_eq!(
            sole.fields["configId"].static_default_value(),
            Some(&json!("default"))
        );
        assert!(!sole.fields["configId"].input);
        assert!(sole.fields["configId"].index);
        assert!(sole.fields["key"].index);
        assert!(!sole.fields["key"].input);
        assert_eq!(
            sole.fields["rateLimitTimeWindow"].static_default_value(),
            Some(&json!(123))
        );
        assert_eq!(
            table(None).fields["rateLimitMax"].static_default_value(),
            Some(&json!(10))
        );
        assert_eq!(
            table(Some(&config)).fields["rateLimitEnabled"].static_default_value(),
            Some(&json!(true))
        );
    }
}
