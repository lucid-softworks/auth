use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serializer;

pub(crate) fn now() -> DateTime<Utc> {
    milliseconds(Utc::now())
}

pub(crate) fn milliseconds(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(value.timestamp_millis())
        .expect("a valid chrono timestamp remains valid at millisecond precision")
}

pub(crate) fn serialize<S>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub(crate) fn serialize_optional<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serialize(value, serializer),
        None => serializer.serialize_none(),
    }
}
