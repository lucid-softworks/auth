use crate::{ApiKey, AuthError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredApiKey {
    id: String,
    #[serde(default, deserialize_with = "deserialize_config_id")]
    config_id: String,
    name: Option<String>,
    start: Option<String>,
    prefix: Option<String>,
    key: String,
    reference_id: String,
    refill_interval: Option<i64>,
    refill_amount: Option<i64>,
    last_refill_at: Option<String>,
    enabled: bool,
    rate_limit_enabled: bool,
    rate_limit_time_window: Option<i64>,
    rate_limit_max: Option<i64>,
    request_count: i64,
    remaining: Option<i64>,
    last_request: Option<String>,
    expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: String,
    updated_at: String,
}

pub(super) fn serialize(api_key: &ApiKey) -> Result<String, AuthError> {
    serde_json::to_string(&StoredApiKey {
        id: api_key.id.clone(),
        config_id: api_key.config_id.clone(),
        name: api_key.name.clone(),
        start: api_key.start.clone(),
        prefix: api_key.prefix.clone(),
        key: api_key.key_hash.clone(),
        reference_id: api_key.reference_id.clone(),
        refill_interval: api_key.refill_interval,
        refill_amount: api_key.refill_amount,
        last_refill_at: api_key.last_refill_at.map(format_date),
        enabled: api_key.enabled,
        rate_limit_enabled: api_key.rate_limit_enabled,
        rate_limit_time_window: api_key.rate_limit_time_window,
        rate_limit_max: api_key.rate_limit_max,
        request_count: api_key.request_count,
        remaining: api_key.remaining,
        last_request: api_key.last_request.map(format_date),
        expires_at: api_key.expires_at.map(format_date),
        permissions: api_key
            .permissions
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(storage_json)?,
        metadata: api_key.metadata.clone(),
        created_at: format_date(api_key.created_at),
        updated_at: format_date(api_key.updated_at),
    })
    .map_err(storage_json)
}

pub(super) fn deserialize(value: Option<&str>) -> Option<ApiKey> {
    let stored = serde_json::from_str::<StoredApiKey>(value?).ok()?;
    Some(ApiKey {
        id: stored.id,
        config_id: stored.config_id,
        name: stored.name,
        start: stored.start,
        prefix: stored.prefix,
        key_hash: stored.key,
        reference_id: stored.reference_id,
        refill_interval: stored.refill_interval,
        refill_amount: stored.refill_amount,
        last_refill_at: stored.last_refill_at.as_deref().and_then(parse_date),
        enabled: stored.enabled,
        rate_limit_enabled: stored.rate_limit_enabled,
        rate_limit_time_window: stored.rate_limit_time_window,
        rate_limit_max: stored.rate_limit_max,
        request_count: stored.request_count,
        remaining: stored.remaining,
        last_request: stored.last_request.as_deref().and_then(parse_date),
        expires_at: stored.expires_at.as_deref().and_then(parse_date),
        permissions: stored
            .permissions
            .as_deref()
            .and_then(|value| serde_json::from_str::<BTreeMap<String, Vec<String>>>(value).ok()),
        metadata: stored.metadata,
        created_at: parse_date(&stored.created_at)?,
        updated_at: parse_date(&stored.updated_at)?,
    })
}

pub(super) fn ttl_at(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<u64> {
    let seconds = expires_at?.signed_duration_since(now).num_seconds();
    u64::try_from(seconds).ok().filter(|seconds| *seconds > 0)
}

fn format_date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn deserialize_config_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn storage_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "failed to serialize API-key secondary record: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use serde_json::json;

    #[test]
    fn serializes_complete_better_auth_record_and_round_trips() {
        let api_key = fixture();
        let serialized = serialize(&api_key).unwrap();
        let value = serde_json::from_str::<serde_json::Value>(&serialized).unwrap();

        let mut fields = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "configId",
                "createdAt",
                "enabled",
                "expiresAt",
                "id",
                "key",
                "lastRefillAt",
                "lastRequest",
                "metadata",
                "name",
                "permissions",
                "prefix",
                "rateLimitEnabled",
                "rateLimitMax",
                "rateLimitTimeWindow",
                "referenceId",
                "refillAmount",
                "refillInterval",
                "remaining",
                "requestCount",
                "start",
                "updatedAt",
            ]
        );

        assert_eq!(value["id"], "key-id");
        assert_eq!(value["configId"], "config");
        assert_eq!(value["key"], "stored-hash");
        assert_eq!(value["referenceId"], "user-id");
        assert_eq!(value["createdAt"], "2026-08-27T10:11:12.123Z");
        assert_eq!(value["updatedAt"], "2026-08-27T10:11:13.123Z");
        assert_eq!(value["expiresAt"], "2026-08-28T10:11:12.123Z");
        assert_eq!(value["lastRefillAt"], serde_json::Value::Null);
        assert_eq!(value["lastRequest"], serde_json::Value::Null);
        assert_eq!(value["permissions"], r#"{"documents":["read"]}"#);
        assert_eq!(value["metadata"], json!({ "environment": "test" }));
        assert!(value.get("keyHash").is_none());
        assert_eq!(deserialize(Some(&serialized)), Some(api_key));
    }

    #[test]
    fn invalid_or_incomplete_json_is_a_cache_miss() {
        assert_eq!(deserialize(None), None);
        assert_eq!(deserialize(Some("not-json")), None);
        assert_eq!(deserialize(Some("{}")), None);

        let mut value =
            serde_json::from_str::<serde_json::Value>(&serialize(&fixture()).unwrap()).unwrap();
        value["createdAt"] = json!("invalid-date");
        assert_eq!(deserialize(Some(&value.to_string())), None);
    }

    #[test]
    fn null_and_missing_config_ids_restore_as_the_default_profile() {
        let mut value =
            serde_json::from_str::<serde_json::Value>(&serialize(&fixture()).unwrap()).unwrap();
        value["configId"] = serde_json::Value::Null;
        assert_eq!(deserialize(Some(&value.to_string())).unwrap().config_id, "");
        value.as_object_mut().unwrap().remove("configId");
        assert_eq!(deserialize(Some(&value.to_string())).unwrap().config_id, "");
    }

    #[test]
    fn ttl_is_a_positive_floor_in_seconds() {
        let now = Utc.with_ymd_and_hms(2026, 8, 27, 10, 0, 0).unwrap();
        assert_eq!(
            ttl_at(Some(now + Duration::milliseconds(2_999)), now),
            Some(2)
        );
        assert_eq!(ttl_at(Some(now + Duration::milliseconds(999)), now), None);
        assert_eq!(ttl_at(Some(now), now), None);
        assert_eq!(ttl_at(Some(now - Duration::seconds(1)), now), None);
        assert_eq!(ttl_at(None, now), None);
    }

    fn fixture() -> ApiKey {
        let created_at = DateTime::parse_from_rfc3339("2026-08-27T10:11:12.123Z")
            .unwrap()
            .with_timezone(&Utc);
        ApiKey {
            id: "key-id".into(),
            config_id: "config".into(),
            name: Some("oracle".into()),
            start: Some("prefix".into()),
            prefix: Some("prefix_".into()),
            key_hash: "stored-hash".into(),
            reference_id: "user-id".into(),
            refill_interval: Some(3_600_000),
            refill_amount: Some(100),
            last_refill_at: None,
            enabled: true,
            rate_limit_enabled: true,
            rate_limit_time_window: Some(86_400_000),
            rate_limit_max: Some(10),
            request_count: 2,
            remaining: Some(98),
            last_request: None,
            expires_at: Some(created_at + Duration::days(1)),
            permissions: Some(BTreeMap::from([("documents".into(), vec!["read".into()])])),
            metadata: Some(json!({ "environment": "test" })),
            created_at,
            updated_at: created_at + Duration::seconds(1),
        }
    }
}
