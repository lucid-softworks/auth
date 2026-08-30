use super::CimdMetadata;
use std::{collections::BTreeMap, time::Duration};

#[derive(Debug, Clone, Default)]
pub(super) struct CacheHeaders {
    pub cache_control: Option<String>,
    pub vary: Option<String>,
    pub expires: Option<String>,
    pub date: Option<String>,
    pub age: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl CacheHeaders {
    pub fn from_headers(headers: &BTreeMap<String, String>) -> Self {
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        };
        Self {
            cache_control: get("cache-control"),
            vary: get("vary"),
            expires: get("expires"),
            date: get("date"),
            age: get("age"),
            etag: get("etag"),
            last_modified: get("last-modified"),
        }
    }

    pub fn merge(&self, newer: &Self) -> Self {
        macro_rules! newer_or_old {
            ($field:ident) => {
                newer.$field.clone().or_else(|| self.$field.clone())
            };
        }
        Self {
            cache_control: newer_or_old!(cache_control),
            vary: newer_or_old!(vary),
            expires: newer_or_old!(expires),
            date: newer_or_old!(date),
            age: newer_or_old!(age),
            etag: newer_or_old!(etag),
            last_modified: newer_or_old!(last_modified),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CacheEntry {
    pub metadata: CimdMetadata,
    pub expires_at_ms: i64,
    pub headers: CacheHeaders,
}

pub(super) fn cache_entry(
    metadata: CimdMetadata,
    headers: CacheHeaders,
    operator_lifetime: Duration,
    now_ms: i64,
) -> Option<CacheEntry> {
    let (cacheable, expires_at_ms) = freshness(&headers, operator_lifetime, now_ms);
    cacheable.then_some(CacheEntry {
        metadata,
        expires_at_ms,
        headers,
    })
}

fn freshness(headers: &CacheHeaders, operator_lifetime: Duration, now_ms: i64) -> (bool, i64) {
    let (directives, duplicates) = parse_cache_control(headers.cache_control.as_deref());
    let varies_all = headers
        .vary
        .as_deref()
        .is_some_and(|vary| vary.split(',').any(|field| field.trim() == "*"));
    if directives.contains_key("no-store") || directives.contains_key("private") || varies_all {
        return (false, now_ms);
    }
    if directives.contains_key("no-cache") {
        return (true, now_ms);
    }
    let operator_ms = operator_lifetime.as_millis().min(i64::MAX as u128) as i64;
    let age_ms = nonnegative_seconds(headers.age.as_deref())
        .unwrap_or(0)
        .saturating_mul(1_000);
    let date_ms = headers
        .date
        .as_deref()
        .and_then(http_date_ms)
        .unwrap_or(now_ms);
    let current_age = now_ms.saturating_sub(date_ms).max(0).max(age_ms);
    let name = if directives.contains_key("s-maxage") {
        "s-maxage"
    } else {
        "max-age"
    };
    let origin_lifetime = if directives.contains_key(name) {
        let parsed = directives
            .get(name)
            .and_then(|value| nonnegative_seconds(value.as_deref()));
        if parsed.is_none() || duplicates.contains(name) {
            Some(0)
        } else {
            parsed.map(|seconds| {
                seconds
                    .saturating_mul(1_000)
                    .saturating_sub(current_age)
            })
        }
    } else {
        headers
            .expires
            .as_deref()
            .and_then(http_date_ms)
            .map(|expires| {
                expires
                .saturating_sub(date_ms)
                .saturating_sub(current_age)
                .max(0)
            })
    };
    let lifetime = origin_lifetime.map_or(operator_ms, |value| value.min(operator_ms));
    (true, now_ms.saturating_add(lifetime))
}

fn parse_cache_control(
    value: Option<&str>,
) -> (
    BTreeMap<String, Option<String>>,
    std::collections::BTreeSet<String>,
) {
    let mut directives = BTreeMap::new();
    let mut duplicates = std::collections::BTreeSet::new();
    for raw in value.unwrap_or_default().split(',') {
        let mut parts = raw.trim().splitn(2, '=');
        let name = parts.next().unwrap_or_default().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if directives.contains_key(&name) {
            duplicates.insert(name.clone());
        }
        let value = parts
            .next()
            .map(|value| value.trim().trim_matches('"').to_owned());
        directives.insert(name, value);
    }
    (directives, duplicates)
}

fn nonnegative_seconds(value: Option<&str>) -> Option<i64> {
    value
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))?
        .parse::<i64>()
        .ok()
}

fn http_date_ms(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|date| date.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    #[test]
    fn applies_cache_precedence_and_storage_prohibitions() {
        let entry = cache_entry(
            Map::new(),
            CacheHeaders {
                cache_control: Some("max-age=90, s-maxage=30".into()),
                age: Some("5".into()),
                ..Default::default()
            },
            Duration::from_secs(60),
            1_000,
        )
        .unwrap();
        assert_eq!(entry.expires_at_ms, 26_000);
        for value in ["no-store", "private"] {
            assert!(
                cache_entry(
                    Map::new(),
                    CacheHeaders {
                        cache_control: Some(value.into()),
                        ..Default::default()
                    },
                    Duration::from_secs(60),
                    0,
                )
                .is_none()
            );
        }
        assert!(
            cache_entry(
                Map::new(),
                CacheHeaders {
                    vary: Some("accept, *".into()),
                    ..Default::default()
                },
                Duration::from_secs(60),
                0,
            )
            .is_none()
        );
        for value in ["no-cache", "max-age=10, max-age=20", "s-maxage=invalid"] {
            let entry = cache_entry(
                Map::new(),
                CacheHeaders {
                    cache_control: Some(value.into()),
                    ..Default::default()
                },
                Duration::from_secs(60),
                1_000,
            )
            .unwrap();
            assert_eq!(entry.expires_at_ms, 1_000, "{value}");
        }
    }
}
