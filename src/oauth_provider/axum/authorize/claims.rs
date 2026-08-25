use serde_json::{Map, Value};

use crate::oauth_provider::OAuthProviderConfig;

pub(super) fn is_valid_request(value: &Value) -> bool {
    let Some(request) = value.as_object() else {
        return false;
    };
    request.get("userinfo").is_none_or(valid_claim_collection)
        && request.get("id_token").is_none_or(valid_id_token_claims)
}

pub(super) fn can_satisfy_essential_acr(value: &Value) -> bool {
    let Some(acr) = value
        .get("id_token")
        .and_then(Value::as_object)
        .and_then(|claims| claims.get("acr"))
        .and_then(Value::as_object)
    else {
        return true;
    };
    if acr.get("essential").and_then(Value::as_bool) != Some(true) {
        return true;
    }
    let value_matches = acr
        .get("value")
        .and_then(Value::as_str)
        .is_none_or(|value| value == "0");
    let values_match = acr
        .get("values")
        .and_then(Value::as_array)
        .is_none_or(|values| values.iter().any(|value| value.as_str() == Some("0")));
    value_matches && values_match
}

pub(super) fn requested_userinfo_claims(
    config: &OAuthProviderConfig,
    value: Option<&Value>,
) -> Vec<String> {
    let supported = supported_claims(config);
    value
        .and_then(|claims| claims.get("userinfo"))
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .keys()
                .filter(|name| supported.contains(*name))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn filter_userinfo_claims(value: &Value, allowed: &[String]) -> Option<Value> {
    let mut request = value.as_object()?.clone();
    if let Some(userinfo) = request.get("userinfo").and_then(Value::as_object) {
        let filtered = userinfo
            .iter()
            .filter(|(name, _)| allowed.contains(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Map<_, _>>();
        if filtered.is_empty() {
            request.remove("userinfo");
        } else {
            request.insert("userinfo".into(), Value::Object(filtered));
        }
    }
    (!request.is_empty()).then_some(Value::Object(request))
}

fn valid_claim_collection(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|claims| claims.values().all(valid_claim_member))
}

fn valid_id_token_claims(value: &Value) -> bool {
    value.as_object().is_some_and(|claims| {
        claims.iter().all(|(name, value)| {
            if name == "acr" {
                valid_acr_claim_member(value)
            } else {
                valid_claim_member(value)
            }
        })
    })
}

fn valid_claim_member(value: &Value) -> bool {
    value.is_null() || value.is_object()
}

fn valid_acr_claim_member(value: &Value) -> bool {
    if value.is_null() {
        return true;
    }
    let Some(acr) = value.as_object() else {
        return false;
    };
    acr.get("essential").is_none_or(Value::is_boolean)
        && acr.get("value").is_none_or(Value::is_string)
        && acr.get("values").is_none_or(|values| {
            values
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string))
        })
}

fn supported_claims(config: &OAuthProviderConfig) -> Vec<String> {
    config
        .advertised_metadata
        .claims_supported
        .clone()
        .unwrap_or_else(|| {
            let mut claims = Vec::new();
            if config.scopes.iter().any(|scope| scope == "profile") {
                claims.extend(["name", "picture", "given_name", "family_name"].map(str::to_owned));
            }
            if config.scopes.iter().any(|scope| scope == "email") {
                claims.extend(["email", "email_verified"].map(str::to_owned));
            }
            claims
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_the_pinned_oidc_claims_request_shape() {
        assert!(is_valid_request(&json!({
            "userinfo": {"email": null, "name": {"essential": true}},
            "id_token": {"acr": {"essential": true, "values": ["0"]}}
        })));
        for invalid in [
            json!(null),
            json!([]),
            json!({"userinfo": []}),
            json!({"userinfo": {"email": true}}),
            json!({"id_token": {"acr": {"essential": "yes"}}}),
            json!({"id_token": {"acr": {"values": [0]}}}),
        ] {
            assert!(!is_valid_request(&invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn essential_acr_requires_the_current_zero_value() {
        assert!(can_satisfy_essential_acr(&json!({
            "id_token": {"acr": {"essential": true, "value": "0"}}
        })));
        assert!(!can_satisfy_essential_acr(&json!({
            "id_token": {"acr": {"essential": true, "value": "1"}}
        })));
    }
}
