use chrono::{DateTime, TimeZone as _, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

/// Exact user/core event constants exported by `@better-auth/infra@0.4.3`.
pub const USER_EVENT_TYPE_ENTRIES: &[(&str, &str)] = &[
    ("USER_CREATED", "user_created"),
    ("USER_SIGNED_IN", "user_signed_in"),
    ("USER_SIGNED_OUT", "user_signed_out"),
    ("USER_SIGN_IN_FAILED", "user_sign_in_failed"),
    ("PASSWORD_RESET_REQUESTED", "password_reset_requested"),
    ("PASSWORD_RESET_COMPLETED", "password_reset_completed"),
    ("PASSWORD_CHANGED", "password_changed"),
    ("EMAIL_VERIFICATION_SENT", "email_verification_sent"),
    ("EMAIL_VERIFIED", "email_verified"),
    ("EMAIL_CHANGED", "email_changed"),
    ("PROFILE_UPDATED", "profile_updated"),
    ("PROFILE_IMAGE_UPDATED", "profile_image_updated"),
    ("SESSION_CREATED", "session_created"),
    ("SESSION_REVOKED", "session_revoked"),
    ("ALL_SESSIONS_REVOKED", "all_sessions_revoked"),
    ("TWO_FACTOR_ENABLED", "two_factor_enabled"),
    ("TWO_FACTOR_DISABLED", "two_factor_disabled"),
    ("TWO_FACTOR_VERIFIED", "two_factor_verified"),
    ("ACCOUNT_LINKED", "account_linked"),
    ("ACCOUNT_UNLINKED", "account_unlinked"),
    ("USER_BANNED", "user_banned"),
    ("USER_UNBANNED", "user_unbanned"),
    ("USER_DELETED", "user_deleted"),
    ("USER_IMPERSONATED", "user_impersonated"),
    ("USER_IMPERSONATED_STOPPED", "user_impersonated_stopped"),
];

/// Exact organization event constants exported by `@better-auth/infra@0.4.3`.
pub const ORGANIZATION_EVENT_TYPE_ENTRIES: &[(&str, &str)] = &[
    ("ORGANIZATION_CREATED", "organization_created"),
    ("ORGANIZATION_UPDATED", "organization_updated"),
    ("ORGANIZATION_MEMBER_ADDED", "organization_member_added"),
    (
        "ORGANIZATION_MEMBER_REMOVED",
        "organization_member_removed",
    ),
    (
        "ORGANIZATION_MEMBER_ROLE_UPDATED",
        "organization_member_role_updated",
    ),
    (
        "ORGANIZATION_MEMBER_INVITED",
        "organization_member_invited",
    ),
    (
        "ORGANIZATION_MEMBER_INVITE_CANCELED",
        "organization_member_invite_canceled",
    ),
    (
        "ORGANIZATION_MEMBER_INVITE_ACCEPTED",
        "organization_member_invite_accepted",
    ),
    (
        "ORGANIZATION_MEMBER_INVITE_REJECTED",
        "organization_member_invite_rejected",
    ),
    (
        "ORGANIZATION_TEAM_CREATED",
        "organization_team_created",
    ),
    (
        "ORGANIZATION_TEAM_UPDATED",
        "organization_team_updated",
    ),
    (
        "ORGANIZATION_TEAM_DELETED",
        "organization_team_deleted",
    ),
    (
        "ORGANIZATION_TEAM_MEMBER_ADDED",
        "organization_team_member_added",
    ),
    (
        "ORGANIZATION_TEAM_MEMBER_REMOVED",
        "organization_team_member_removed",
    ),
];

/// Better Auth's complete 39-entry `USER_EVENT_TYPES` root export.
pub fn user_event_types() -> Map<String, Value> {
    type_map(USER_EVENT_TYPE_ENTRIES)
}

/// Better Auth's 14-entry organization event map.
pub fn organization_event_types() -> Map<String, Value> {
    type_map(ORGANIZATION_EVENT_TYPE_ENTRIES)
}

/// Better Auth's complete 39-entry `USER_EVENT_TYPES` root export.
pub fn all_event_types() -> Map<String, Value> {
    USER_EVENT_TYPE_ENTRIES
        .iter()
        .chain(ORGANIZATION_EVENT_TYPE_ENTRIES)
        .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
        .collect()
}

fn type_map(entries: &[(&str, &str)]) -> Map<String, Value> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Value>,
    pub created_at: Value,
    pub updated_at: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_in_minutes: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Map<String, Value>>,
}

impl DashEvent {
    pub fn from_remote(raw: &Value) -> Self {
        let object = raw.as_object();
        Self {
            event_type: optional_field(object, "eventType"),
            event_data: optional_field(object, "eventData"),
            event_key: optional_field(object, "eventKey"),
            project_id: optional_field(object, "projectId"),
            created_at: js_date(field(object, "createdAt")),
            updated_at: js_date(field(object, "updatedAt")),
            age_in_minutes: optional_field(object, "ageInMinutes"),
            location: location(object),
        }
    }

    pub fn event_type_str(&self) -> Option<&str> {
        self.event_type.as_ref().and_then(Value::as_str)
    }
}

fn field(object: Option<&Map<String, Value>>, key: &str) -> Value {
    object
        .and_then(|object| object.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn optional_field(object: Option<&Map<String, Value>>, key: &str) -> Option<Value> {
    object.and_then(|object| object.get(key)).cloned()
}

fn js_date(value: Value) -> Value {
    let date = match &value {
        Value::String(value) => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|date| date.with_timezone(&Utc)),
        Value::Number(value) => value
            .as_i64()
            .and_then(|milliseconds| Utc.timestamp_millis_opt(milliseconds).single()),
        Value::Null => Utc.timestamp_millis_opt(0).single(),
        Value::Bool(value) => Utc.timestamp_millis_opt(i64::from(*value)).single(),
        _ => None,
    };
    date.map_or(Value::Null, |date| {
        Value::String(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    })
}

fn location(object: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    const FIELDS: [&str; 4] = ["ipAddress", "city", "country", "countryCode"];
    let object = object?;
    let has_truthy_value = FIELDS
        .iter()
        .filter_map(|field| object.get(*field))
        .any(js_truthy);
    has_truthy_value.then(|| {
        FIELDS
            .iter()
            .filter_map(|field| {
                object
                    .get(*field)
                    .cloned()
                    .map(|value| ((*field).to_owned(), value))
            })
            .collect()
    })
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn published_constant_maps_are_exact_and_disjoint() {
        assert_eq!(USER_EVENT_TYPE_ENTRIES.len(), 25);
        assert_eq!(ORGANIZATION_EVENT_TYPE_ENTRIES.len(), 14);
        assert_eq!(all_event_types().len(), 39);
        assert_eq!(all_event_types()["EMAIL_CHANGED"], "email_changed");
        assert_eq!(
            all_event_types()["ORGANIZATION_TEAM_MEMBER_REMOVED"],
            "organization_team_member_removed"
        );
    }

    #[test]
    fn transformation_normalizes_dates_and_omits_empty_location() {
        let event = DashEvent::from_remote(&json!({
            "eventType": "user_signed_in",
            "eventData": {"userId": "user-1", "secretExtra": true},
            "eventKey": "user-1",
            "projectId": "project-1",
            "createdAt": "2026-08-30T10:11:12Z",
            "updatedAt": 1_787_999_472_000_i64,
            "ageInMinutes": 4,
            "ipAddress": "",
            "city": null,
            "unknown": "stripped"
        }));
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["createdAt"], "2026-08-30T10:11:12.000Z");
        assert_eq!(value["updatedAt"], "2026-08-29T10:31:12.000Z");
        assert!(value.get("location").is_none());
        assert!(value.get("unknown").is_none());
        assert_eq!(value["eventData"]["secretExtra"], true);
    }

    #[test]
    fn location_preserves_null_and_omits_absent_fields_when_any_value_is_truthy() {
        let event = DashEvent::from_remote(&json!({
            "ipAddress": null,
            "country": "United Kingdom"
        }));
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(
            value["location"],
            json!({"ipAddress": null, "country": "United Kingdom"})
        );
    }
}
