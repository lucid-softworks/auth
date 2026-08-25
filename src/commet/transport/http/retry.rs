use reqwest::{StatusCode, header::HeaderMap};
use std::time::Duration;

const BASE_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(8);
const RETRY_AFTER_CAP: Duration = Duration::from_secs(30);

pub(super) fn delay(status: StatusCode, headers: &HeaderMap, attempt: u32) -> Option<Duration> {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return positive_retry_after(headers);
    }
    matches!(status.as_u16(), 408 | 500 | 502 | 503 | 504).then(|| exponential_delay(attempt))
}

pub(super) fn network_delay(attempt: u32) -> Duration {
    exponential_delay(attempt)
}

fn positive_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let mut values = headers.get_all("retry-after").iter();
    let seconds = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() {
        return None;
    }
    let seconds = parse_js_number(seconds)?;
    (seconds.is_finite() && seconds > 0.0)
        .then(|| Duration::from_secs_f64(seconds.min(RETRY_AFTER_CAP.as_secs_f64())))
}

fn parse_js_number(value: &str) -> Option<f64> {
    if value.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = value.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix)
                .ok()
                .map(|value| value as f64);
        }
    }
    value.parse().ok()
}

fn exponential_delay(attempt: u32) -> Duration {
    let multiplier = 1_u64.checked_shl(attempt).unwrap_or(u64::MAX);
    BASE_DELAY
        .checked_mul(u32::try_from(multiplier).unwrap_or(u32::MAX))
        .unwrap_or(MAX_DELAY)
        .min(MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn exact_status_set_uses_one_two_four_second_backoff() {
        let headers = HeaderMap::new();
        for status in [408, 500, 502, 503, 504] {
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(delay(status, &headers, 0), Some(Duration::from_secs(1)));
            assert_eq!(delay(status, &headers, 1), Some(Duration::from_secs(2)));
            assert_eq!(delay(status, &headers, 2), Some(Duration::from_secs(4)));
        }
        for status in [409, 501, 505] {
            assert_eq!(
                delay(StatusCode::from_u16(status).unwrap(), &headers, 0),
                None
            );
        }
        assert_eq!(network_delay(7), Duration::from_secs(8));
    }

    #[test]
    fn rate_limits_require_positive_finite_retry_after_and_cap_it() {
        let mut headers = HeaderMap::new();
        for invalid in ["0", "-1", "NaN", "Infinity", "not-a-number"] {
            headers.insert("retry-after", HeaderValue::from_str(invalid).unwrap());
            assert_eq!(delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0), None);
        }
        headers.insert("retry-after", HeaderValue::from_static("0.001"));
        assert_eq!(
            delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0),
            Some(Duration::from_millis(1))
        );
        headers.insert("retry-after", HeaderValue::from_static("90"));
        assert_eq!(
            delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0),
            Some(Duration::from_secs(30))
        );
        headers.insert("retry-after", HeaderValue::from_static("0x2"));
        assert_eq!(
            delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0),
            Some(Duration::from_secs(2))
        );
        headers.append("retry-after", HeaderValue::from_static("3"));
        assert_eq!(delay(StatusCode::TOO_MANY_REQUESTS, &headers, 0), None);
    }
}
