use std::time::Duration;

trait ValueExt {
    fn date_time(&self) -> Option<chrono::DateTime<chrono::Utc>>;
}

impl ValueExt for serde_json::Value {
    fn date_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.as_str()?.parse().ok()
    }
}

pub(super) fn activity_was_recent(
    value: Option<&serde_json::Value>,
    interval: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    value
        .and_then(ValueExt::date_time)
        .is_some_and(|last_active| {
            now.signed_duration_since(last_active)
                < chrono::Duration::from_std(interval).unwrap_or(chrono::Duration::MAX)
        })
}
