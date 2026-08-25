use chrono::{DateTime, Utc};
use reqwest::{StatusCode, header::HeaderMap};
use std::time::Duration;

const INITIAL_RETRY_DELAY_SECONDS: f64 = 0.5;
const MAX_EXPONENTIAL_RETRY_DELAY_SECONDS: f64 = 8.0;
const MAX_SERVER_RETRY_DELAY: Duration = Duration::from_secs(60);

pub(super) fn should_retry(status: StatusCode, headers: &HeaderMap) -> bool {
    match text_header(headers, "x-should-retry") {
        Some("true") => return true,
        Some("false") => return false,
        _ => {}
    }
    matches!(status.as_u16(), 408 | 409 | 429) || status.is_server_error()
}

pub(super) fn delay(
    headers: Option<&HeaderMap>,
    retry_count: u32,
    random: f64,
    now: DateTime<Utc>,
) -> Duration {
    headers
        .and_then(|headers| server_delay(headers, now))
        .unwrap_or_else(|| exponential_delay(retry_count, random))
}

fn server_delay(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let retry_after_millis = text_header(headers, "retry-after-ms").and_then(parse_number);
    let mut millis = retry_after_millis;
    if (millis.is_none() || millis == Some(0.0))
        && let Some(value) = text_header(headers, "retry-after")
    {
        millis = Some(
            parse_number(value)
                .map(|seconds| seconds * 1_000.0)
                .or_else(|| {
                    DateTime::parse_from_rfc2822(value)
                        .ok()
                        .map(|date| (date.with_timezone(&Utc) - now).num_milliseconds() as f64)
                })
                .unwrap_or(0.0),
        );
    }
    millis.map(bounded_server_delay)
}

fn bounded_server_delay(millis: f64) -> Duration {
    if millis.is_nan() || millis <= 0.0 {
        return Duration::ZERO;
    }
    if millis.is_infinite() {
        return MAX_SERVER_RETRY_DELAY;
    }
    Duration::from_secs_f64((millis / 1_000.0).min(MAX_SERVER_RETRY_DELAY.as_secs_f64()))
}

fn exponential_delay(retry_count: u32, random: f64) -> Duration {
    let seconds = if retry_count >= 4 {
        MAX_EXPONENTIAL_RETRY_DELAY_SECONDS
    } else {
        INITIAL_RETRY_DELAY_SECONDS * f64::from(1_u8 << retry_count)
    };
    let jitter = 1.0 - random.clamp(0.0, 1.0) * 0.25;
    Duration::from_secs_f64(seconds * jitter)
}

fn text_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn parse_number(value: &str) -> Option<f64> {
    let value = value.trim_start();
    for infinity in ["Infinity", "+Infinity", "-Infinity"] {
        if value.starts_with(infinity) {
            return infinity.replace("Infinity", "inf").parse().ok();
        }
    }
    (1..=value.len()).rev().find_map(|end| {
        value
            .get(..end)
            .and_then(|prefix| prefix.parse::<f64>().ok())
            .filter(|number| !number.is_nan())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn retry_override_precedes_status_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert("x-should-retry", HeaderValue::from_static("false"));
        assert!(!should_retry(StatusCode::INTERNAL_SERVER_ERROR, &headers));
        headers.insert("x-should-retry", HeaderValue::from_static("true"));
        assert!(should_retry(StatusCode::BAD_REQUEST, &headers));

        let headers = HeaderMap::new();
        for status in [408, 409, 429, 500, 599] {
            assert!(should_retry(
                StatusCode::from_u16(status).unwrap(),
                &headers
            ));
        }
        assert!(!should_retry(StatusCode::BAD_REQUEST, &headers));
    }

    #[test]
    fn exponential_backoff_matches_sdk_jitter_bounds() {
        assert_eq!(exponential_delay(0, 0.0), Duration::from_millis(500));
        assert_eq!(exponential_delay(0, 1.0), Duration::from_millis(375));
        assert_eq!(exponential_delay(1, 0.0), Duration::from_secs(1));
        assert_eq!(exponential_delay(5, 0.0), Duration::from_secs(8));
    }

    #[test]
    fn server_delays_take_precedence_and_are_bounded() {
        let now = DateTime::parse_from_rfc3339("2026-08-25T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut headers = HeaderMap::new();
        headers.insert("retry-after-ms", HeaderValue::from_static("125"));
        headers.insert("retry-after", HeaderValue::from_static("2"));
        assert_eq!(
            server_delay(&headers, now),
            Some(Duration::from_millis(125))
        );

        headers.insert("retry-after-ms", HeaderValue::from_static("0"));
        assert_eq!(server_delay(&headers, now), Some(Duration::from_secs(2)));
        headers.insert("retry-after", HeaderValue::from_static("120"));
        assert_eq!(server_delay(&headers, now), Some(Duration::from_secs(60)));
        headers.insert(
            "retry-after",
            HeaderValue::from_static("Tue, 25 Aug 2026 12:00:03 GMT"),
        );
        assert_eq!(server_delay(&headers, now), Some(Duration::from_secs(3)));

        headers.insert("retry-after-ms", HeaderValue::from_static("250ms"));
        assert_eq!(
            server_delay(&headers, now),
            Some(Duration::from_millis(250))
        );
        headers.insert("retry-after-ms", HeaderValue::from_static("Infinity"));
        assert_eq!(server_delay(&headers, now), Some(Duration::from_secs(60)));
    }
}
