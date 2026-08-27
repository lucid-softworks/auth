use crate::{ApiKey, ApiKeyConfiguration, ApiKeyError, AuthError};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub(super) struct ApiKeyUsageMutation {
    remaining: Option<i64>,
    last_refill_at: Option<DateTime<Utc>>,
    last_request: Option<DateTime<Utc>>,
    request_count: i64,
    updated_at: DateTime<Utc>,
}

impl ApiKeyUsageMutation {
    pub(super) fn apply(self, api_key: &mut ApiKey) {
        api_key.remaining = self.remaining;
        api_key.last_refill_at = self.last_refill_at;
        api_key.last_request = self.last_request;
        api_key.request_count = self.request_count;
        api_key.updated_at = self.updated_at;
    }
}

pub(super) fn evaluate(
    api_key: &ApiKey,
    config: &ApiKeyConfiguration,
    now: DateTime<Utc>,
) -> Result<ApiKeyUsageMutation, AuthError> {
    let (remaining, last_refill_at) = consume_remaining(api_key, now)?;
    let (last_request, request_count) = consume_rate_limit(api_key, config, now)?;
    Ok(ApiKeyUsageMutation {
        remaining,
        last_refill_at,
        last_request,
        request_count,
        updated_at: now,
    })
}

fn consume_remaining(
    api_key: &ApiKey,
    now: DateTime<Utc>,
) -> Result<(Option<i64>, Option<DateTime<Utc>>), AuthError> {
    let Some(mut remaining) = api_key.remaining else {
        return Ok((None, api_key.last_refill_at));
    };
    let mut last_refill_at = api_key.last_refill_at;
    if let (Some(interval), Some(amount)) = (api_key.refill_interval, api_key.refill_amount)
        && interval != 0
        && amount != 0
        && (now - last_refill_at.unwrap_or(api_key.created_at)).num_milliseconds() > interval
    {
        remaining = amount;
        last_refill_at = Some(now);
    }
    if remaining == 0 {
        return Err(ApiKeyError::UsageExceeded.into());
    }
    Ok((Some(remaining - 1), last_refill_at))
}

fn consume_rate_limit(
    api_key: &ApiKey,
    config: &ApiKeyConfiguration,
    now: DateTime<Utc>,
) -> Result<(Option<DateTime<Utc>>, i64), AuthError> {
    if !config.rate_limit.enabled || !api_key.rate_limit_enabled {
        return Ok((Some(now), api_key.request_count));
    }
    let (Some(window), Some(max)) = (api_key.rate_limit_time_window, api_key.rate_limit_max) else {
        return Ok((api_key.last_request, api_key.request_count));
    };
    let Some(last_request) = api_key.last_request else {
        return Ok((Some(now), 1));
    };
    let elapsed = (now - last_request).num_milliseconds();
    if elapsed > window {
        return Ok((Some(now), 1));
    }
    if api_key.request_count >= max {
        return Err(ApiKeyError::RateLimited {
            retry_after_milliseconds: (window - elapsed).max(0),
        }
        .into());
    }
    Ok((Some(now), api_key.request_count.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    #[test]
    fn applies_quota_refill_and_rate_window_rules() {
        let now = Utc.with_ymd_and_hms(2026, 8, 27, 12, 0, 0).unwrap();
        let mut api_key = fixture(now - Duration::hours(2));
        api_key.remaining = Some(1);
        api_key.refill_amount = Some(5);
        api_key.refill_interval = Some(3_600_000);
        let mutation = evaluate(&api_key, &ApiKeyConfiguration::default(), now).unwrap();
        mutation.apply(&mut api_key);
        assert_eq!(api_key.remaining, Some(4));
        assert_eq!(api_key.last_refill_at, Some(now));
        assert_eq!(api_key.request_count, 1);
        assert_eq!(api_key.last_request, Some(now));
    }

    #[test]
    fn rejects_exhausted_quota_and_full_active_window() {
        let now = Utc.with_ymd_and_hms(2026, 8, 27, 12, 0, 0).unwrap();
        let mut exhausted = fixture(now);
        exhausted.remaining = Some(0);
        assert!(matches!(
            evaluate(&exhausted, &ApiKeyConfiguration::default(), now),
            Err(AuthError::ApiKey(ApiKeyError::UsageExceeded))
        ));

        let mut limited = fixture(now);
        limited.last_request = Some(now - Duration::seconds(1));
        limited.request_count = 10;
        assert!(matches!(
            evaluate(&limited, &ApiKeyConfiguration::default(), now),
            Err(AuthError::ApiKey(ApiKeyError::RateLimited { .. }))
        ));
    }

    fn fixture(created_at: DateTime<Utc>) -> ApiKey {
        ApiKey {
            id: "key-id".into(),
            config_id: "default".into(),
            name: None,
            start: None,
            prefix: None,
            key_hash: "hash".into(),
            reference_id: "user-id".into(),
            refill_interval: None,
            refill_amount: None,
            last_refill_at: None,
            enabled: true,
            rate_limit_enabled: true,
            rate_limit_time_window: Some(86_400_000),
            rate_limit_max: Some(10),
            request_count: 0,
            remaining: None,
            last_request: None,
            expires_at: None,
            permissions: None,
            metadata: None,
            created_at,
            updated_at: created_at,
        }
    }
}
