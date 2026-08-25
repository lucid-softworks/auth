use super::{
    common::{
        DodoInputError, error, expected, is_metadata_value, require_together,
        required_string_value, root_object,
    },
    query::{query_map, query_number, query_string},
};
use crate::dodo_payments::provider::{DodoUsageListRequest, DodoUsageMetadata};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DodoNullableMetadata {
    Absent,
    Null,
    Object(DodoUsageMetadata),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoUsageIngestInput {
    pub(crate) event_id: String,
    pub(crate) event_name: String,
    pub(crate) metadata: DodoNullableMetadata,
    pub(crate) timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoUsageMeterQuery {
    page_number: Option<f64>,
    page_size: Option<f64>,
    event_name: Option<String>,
    meter_id: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

impl DodoUsageMeterQuery {
    pub(crate) fn into_provider(self, customer_id: String) -> DodoUsageListRequest {
        DodoUsageListRequest {
            customer_id: Some(customer_id),
            page_number: self.page_number,
            page_size: self.page_size,
            event_name: self.event_name,
            meter_id: self.meter_id,
            start: self.start,
            end: self.end,
        }
    }
}

pub(crate) fn parse_usage_ingest(value: Value) -> Result<DodoUsageIngestInput, DodoInputError> {
    let body = root_object(value)?;
    require_together(&body, &["event_id", "event_name"])?;
    let event_id = required_string_value(&body, "event_id", "body.event_id")?;
    let event_name = required_string_value(&body, "event_name", "body.event_name")?;
    let metadata = match body.get("metadata") {
        None => DodoNullableMetadata::Absent,
        Some(Value::Null) => DodoNullableMetadata::Null,
        Some(Value::Object(values)) if values.values().all(is_metadata_value) => {
            DodoNullableMetadata::Object(values.clone())
        }
        Some(value) => return Err(expected("body.metadata", "object", value)),
    };
    let timestamp = body.get("timestamp").map(coerce_timestamp).transpose()?;
    Ok(DodoUsageIngestInput {
        event_id,
        event_name,
        metadata,
        timestamp,
    })
}

pub(crate) fn parse_usage_meter_query(
    raw: Option<&str>,
) -> Result<DodoUsageMeterQuery, DodoInputError> {
    let query = query_map(raw)?;
    Ok(DodoUsageMeterQuery {
        page_number: query_number(&query, "page_number")?,
        page_size: query_number(&query, "page_size")?,
        event_name: query_string(&query, "event_name"),
        meter_id: query_string(&query, "meter_id"),
        start: query_string(&query, "start"),
        end: query_string(&query, "end"),
    })
}

fn coerce_timestamp(value: &Value) -> Result<String, DodoInputError> {
    let date = match value {
        Value::Null => DateTime::<Utc>::from_timestamp_millis(0),
        Value::Bool(value) => DateTime::<Utc>::from_timestamp_millis(i64::from(*value)),
        Value::Number(value) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .and_then(|value| DateTime::<Utc>::from_timestamp_millis(value as i64)),
        Value::String(value) => parse_timestamp_string(value),
        Value::Array(values) => parse_timestamp_array(values),
        _ => None,
    }
    .ok_or_else(|| error("[body.timestamp] Invalid date".into()))?;
    Ok(date.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn parse_timestamp_string(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
        .or_else(|| {
            DateTime::parse_from_rfc2822(value)
                .ok()
                .map(|value| value.with_timezone(&Utc))
        })
        .or_else(|| parse_local_datetime(value, "%Y-%m-%dT%H:%M:%S%.f"))
        .or_else(|| parse_local_datetime(value, "%B %-d, %Y %H:%M:%S"))
        .or_else(|| parse_local_date(value, "%B %-d, %Y"))
        .or_else(|| parse_local_date(value, "%Y,%m,%d"))
        .or_else(|| parse_local_date(value, "%Y,%m"))
        .or_else(|| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .and_then(|value| value.and_hms_opt(0, 0, 0))
                .map(|value| value.and_utc())
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%B %-d, %Y %H:%M:%S GMT")
                .ok()
                .map(|value| value.and_utc())
        })
        .or_else(|| {
            value
                .parse::<i32>()
                .ok()
                .filter(|year| *year > 31)
                .and_then(|year| NaiveDate::from_ymd_opt(year, 1, 1))
                .and_then(|value| value.and_hms_opt(0, 0, 0))
                .map(|value| value.and_utc())
        })
        .or_else(|| javascript_numeric_month(value))
}

fn parse_local_datetime(value: &str, format: &str) -> Option<DateTime<Utc>> {
    let naive = NaiveDateTime::parse_from_str(value, format).ok()?;
    Local
        .from_local_datetime(&naive)
        .single()
        .or_else(|| Local.from_local_datetime(&naive).earliest())
        .map(|value| value.with_timezone(&Utc))
}

fn parse_local_date(value: &str, format: &str) -> Option<DateTime<Utc>> {
    let naive = NaiveDate::parse_from_str(value, format)
        .ok()?
        .and_hms_opt(0, 0, 0)?;
    Local
        .from_local_datetime(&naive)
        .single()
        .or_else(|| Local.from_local_datetime(&naive).earliest())
        .map(|value| value.with_timezone(&Utc))
}

fn parse_timestamp_array(values: &[Value]) -> Option<DateTime<Utc>> {
    match values {
        [Value::String(value)] => parse_timestamp_string(value),
        [Value::Number(value)] => parse_timestamp_string(&value.to_string()),
        [year, month] => parse_numeric_array_date(year, month, 1),
        [year, month, day] => parse_numeric_array_date(year, month, day.as_u64()?.try_into().ok()?),
        _ => None,
    }
}

fn parse_numeric_array_date(year: &Value, month: &Value, day: u32) -> Option<DateTime<Utc>> {
    let year = year.as_i64()?.try_into().ok()?;
    let month = month.as_u64()?.try_into().ok()?;
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(0, 0, 0)?;
    Local
        .from_local_datetime(&naive)
        .single()
        .or_else(|| Local.from_local_datetime(&naive).earliest())
        .map(|value| value.with_timezone(&Utc))
}

fn javascript_numeric_month(value: &str) -> Option<DateTime<Utc>> {
    let month = value.parse::<u32>().ok()?;
    let (year, month) = if month == 0 { (2000, 1) } else { (2001, month) };
    NaiveDate::from_ymd_opt(year, month, 1)
        .and_then(|value| value.and_hms_opt(0, 0, 0))
        .map(|value| value.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ingest_preserves_nullable_metadata_and_js_date_coercions() {
        let parsed = parse_usage_ingest(json!({
            "event_id":"event_1","event_name":"tokens","metadata":null,
            "timestamp":"2026-08-01T12:34:56+02:00","unknown":true
        }))
        .unwrap();
        assert_eq!(parsed.event_id, "event_1");
        assert_eq!(parsed.event_name, "tokens");
        assert_eq!(parsed.metadata, DodoNullableMetadata::Null);
        assert_eq!(
            parsed.timestamp.as_deref(),
            Some("2026-08-01T10:34:56.000Z")
        );
        for (input, expected) in [
            (Value::Null, "1970-01-01T00:00:00.000Z"),
            (Value::Bool(true), "1970-01-01T00:00:00.001Z"),
            (json!(1000), "1970-01-01T00:00:01.000Z"),
            (json!("0"), "2000-01-01T00:00:00.000Z"),
            (
                json!("Sat, 01 Aug 2026 12:34:56 GMT"),
                "2026-08-01T12:34:56.000Z",
            ),
            (
                json!("August 1, 2026 12:34:56 GMT"),
                "2026-08-01T12:34:56.000Z",
            ),
            (json!("2026"), "2026-01-01T00:00:00.000Z"),
            (json!([2026]), "2026-01-01T00:00:00.000Z"),
        ] {
            let parsed =
                parse_usage_ingest(json!({"event_id":"e","event_name":"n","timestamp":input}))
                    .unwrap();
            assert_eq!(parsed.timestamp.as_deref(), Some(expected));
        }
        let local = parse_usage_ingest(json!({
            "event_id":"e","event_name":"n","timestamp":"2026-08-01T12:34:56"
        }))
        .unwrap();
        assert_eq!(
            local.timestamp,
            parse_local_datetime("2026-08-01T12:34:56", "%Y-%m-%dT%H:%M:%S%.f")
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        );
        let locale = parse_usage_ingest(json!({
            "event_id":"e","event_name":"n","timestamp":"August 1, 2026"
        }))
        .unwrap();
        assert_eq!(
            locale.timestamp,
            parse_local_date("August 1, 2026", "%B %-d, %Y")
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        );
        let array = parse_usage_ingest(json!({
            "event_id":"e","event_name":"n","timestamp":[2026,8,1]
        }))
        .unwrap();
        assert_eq!(
            array.timestamp,
            parse_timestamp_array(&[json!(2026), json!(8), json!(1)])
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        );
        assert!(
            parse_usage_ingest(json!({
                "event_id":"e","event_name":"n","timestamp":{}
            }))
            .is_err()
        );
        assert!(
            parse_usage_ingest(json!({"event_id":"e","event_name":"n","metadata":{"nested":{}}}))
                .is_err()
        );
        assert_eq!(
            parse_usage_ingest(json!({})).unwrap_err().message(),
            "[body.event_id] Required; [body.event_name] Required"
        );
    }

    #[test]
    fn meter_query_strips_unknowns_and_maps_provider_names() {
        let query = parse_usage_meter_query(Some(
            "page_number=3&page_size=4&event_name=api+call&meter_id=m%2F1&start=a&end=b&customer_id=foreign&unknown=x",
        )).unwrap();
        let request = query.into_provider("customer_1".into());
        assert_eq!(request.customer_id.as_deref(), Some("customer_1"));
        assert_eq!(request.page_number, Some(3.0));
        assert_eq!(request.page_size, Some(4.0));
        assert_eq!(request.event_name.as_deref(), Some("api call"));
        assert_eq!(request.meter_id.as_deref(), Some("m/1"));
        assert_eq!(request.start.as_deref(), Some("a"));
        assert_eq!(request.end.as_deref(), Some("b"));
    }
}
