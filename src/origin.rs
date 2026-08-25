use crate::AuthError;
use std::{fmt::Write, str::FromStr};
use url::{Host, Url};

/// A trusted-origin pattern using Better Auth's matching semantics.
///
/// Patterns may be exact HTTP(S) origins, custom-scheme URLs, or globs using
/// `*` and `?`. A pattern without a scheme is matched against the URL host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedOrigin {
    pattern: String,
}

impl TrustedOrigin {
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        value.parse()
    }

    pub fn matches(&self, candidate: &str) -> bool {
        matches_origin_pattern(candidate, &self.pattern)
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }
}

impl FromStr for TrustedOrigin {
    type Err = AuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(AuthError::InvalidConfiguration(
                "trusted origins must be non-empty Better Auth origin patterns".into(),
            ));
        }
        Ok(Self {
            pattern: value.to_owned(),
        })
    }
}

#[cfg(any(feature = "axum", test))]
pub(crate) fn safe_relative_callback(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('/') else {
        return false;
    };
    if rest.starts_with('/')
        || rest.starts_with('\\')
        || rest.starts_with("%2f")
        || rest.starts_with("%5c")
    {
        return false;
    }
    let (path, query) = rest
        .split_once('?')
        .map_or((rest, None), |(path, query)| (path, Some(query)));
    valid_relative_path(path) && query.is_none_or(valid_relative_query)
}

#[cfg(any(feature = "axum", test))]
fn valid_relative_path(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'/' | b'@' | b'{' | b'}')
    })
}

#[cfg(any(feature = "axum", test))]
fn valid_relative_query(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b'&' | b'%' | b'@' | b'{' | b'}'
            )
    })
}

fn matches_origin_pattern(candidate: &str, pattern: &str) -> bool {
    if pattern.contains(['*', '?']) {
        let canonical_origin = http_origin(candidate);
        let sample = if pattern.contains("://") {
            canonical_origin.as_deref().unwrap_or(candidate)
        } else {
            let Some(host) = url_host(candidate) else {
                return false;
            };
            return wildcard_matches(pattern, &host);
        };
        return wildcard_matches(pattern, sample);
    }

    let Ok(parsed_candidate) = Url::parse(candidate) else {
        return false;
    };
    if matches!(parsed_candidate.scheme(), "http" | "https") {
        return http_origin(candidate).is_some_and(|origin| pattern == origin);
    }

    let Some(candidate) = CustomSchemeOrigin::parse(candidate) else {
        return false;
    };
    let Some(pattern) = CustomSchemeOrigin::parse(pattern) else {
        return false;
    };
    candidate.matches(&pattern)
}

fn http_origin(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    // URL serialization normalizes case, IDNs, and default ports just as
    // JavaScript's URL.origin does.
    Some(parsed.origin().ascii_serialization())
}

fn url_host(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    let mut result = String::new();
    match parsed.host()? {
        Host::Domain(host) => result.push_str(host),
        Host::Ipv4(host) => write!(result, "{host}").ok()?,
        Host::Ipv6(host) => write!(result, "[{host}]").ok()?,
    }
    if let Some(port) = parsed.port() {
        write!(result, ":{port}").ok()?;
    }
    Some(result)
}

#[derive(Debug, PartialEq, Eq)]
struct CustomSchemeOrigin {
    scheme: String,
    authority: String,
    path: String,
}

impl CustomSchemeOrigin {
    fn parse(value: &str) -> Option<Self> {
        let scheme_end = value.find(':')?;
        if scheme_end == 0 {
            return None;
        }
        let scheme = value[..scheme_end].to_ascii_lowercase();
        let mut rest = &value[scheme_end + 1..];
        let mut authority = "";
        if let Some(after_slashes) = rest.strip_prefix("//") {
            let authority_end = after_slashes
                .find(['/', '?', '#'])
                .unwrap_or(after_slashes.len());
            authority = &after_slashes[..authority_end];
            rest = &after_slashes[authority_end..];
        }
        let raw_path = rest.split(['?', '#']).next().unwrap_or_default();
        Some(Self {
            scheme,
            authority: authority.to_ascii_lowercase(),
            path: normalize_custom_path(raw_path),
        })
    }

    fn matches(&self, pattern: &Self) -> bool {
        self.scheme == pattern.scheme
            && (pattern.authority.is_empty() || self.authority == pattern.authority)
            && (pattern.path.is_empty()
                || self.path == pattern.path
                || self
                    .path
                    .strip_prefix(&pattern.path)
                    .is_some_and(|suffix| suffix.starts_with('/')))
    }
}

fn normalize_custom_path(path: &str) -> String {
    let decoded = percent_decode(path).unwrap_or_else(|| path.to_owned());
    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            ".." => {
                segments.pop();
            }
            "." | "" => {}
            value => segments.push(value),
        }
    }
    if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn wildcard_matches(pattern: &str, sample: &str) -> bool {
    let pattern = pattern.as_bytes();
    let sample = sample.as_bytes();
    let mut reachable = vec![false; sample.len() + 1];
    reachable[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let token = match pattern[index] {
            b'\\' if index + 1 < pattern.len() => {
                index += 1;
                PatternToken::Literal(pattern[index])
            }
            b'\\' => {
                index += 1;
                continue;
            }
            b'?' => PatternToken::One,
            b'*' => PatternToken::Many,
            byte => PatternToken::Literal(byte),
        };
        index += 1;
        match token {
            PatternToken::Many => {
                for sample_index in 1..=sample.len() {
                    reachable[sample_index] |= reachable[sample_index - 1];
                }
            }
            PatternToken::One => {
                for sample_index in (1..=sample.len()).rev() {
                    reachable[sample_index] = reachable[sample_index - 1];
                }
                reachable[0] = false;
            }
            PatternToken::Literal(expected) => {
                for sample_index in (1..=sample.len()).rev() {
                    reachable[sample_index] =
                        reachable[sample_index - 1] && sample[sample_index - 1] == expected;
                }
                reachable[0] = false;
            }
        }
    }
    reachable[sample.len()]
}

enum PatternToken {
    Literal(u8),
    One,
    Many,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_http_origins_use_url_origin_normalization() {
        let origin = TrustedOrigin::parse("https://app.example.com").unwrap();
        assert!(origin.matches("https://app.example.com/path"));
        assert!(origin.matches("https://app.example.com:443/path"));
        assert!(!origin.matches("http://app.example.com"));
        assert!(!origin.matches("https://app.example.com:8443"));
    }

    #[test]
    fn better_auth_wildcards_match_origins_or_hosts() {
        let origin = TrustedOrigin::parse("https://*.example.com").unwrap();
        assert!(origin.matches("https://preview.example.com/callback"));
        assert!(origin.matches("https://deep.preview.example.com"));
        assert!(!origin.matches("https://example.com"));
        assert!(!origin.matches("https://evil-example.com"));

        let origin = TrustedOrigin::parse("preview-?.example.com").unwrap();
        assert!(origin.matches("https://preview-a.example.com/path"));
        assert!(!origin.matches("https://preview-ab.example.com/path"));

        let origin = TrustedOrigin::parse("http://localhost:*").unwrap();
        assert!(origin.matches("http://localhost:5173/path"));
        assert!(!origin.matches("http://localhost.evil.test:5173"));
    }

    #[test]
    fn custom_scheme_paths_are_normalized_and_pinned() {
        let origin = TrustedOrigin::parse("myapp://auth/callback").unwrap();
        assert!(origin.matches("myapp://auth/callback"));
        assert!(origin.matches("myapp://auth/callback/complete"));
        assert!(!origin.matches("myapp://auth/other"));
        assert!(!origin.matches("myapp://evil/callback"));
        assert!(!origin.matches("myapp://auth/callback/%2e%2e/other"));
    }

    #[test]
    fn relative_callbacks_follow_better_auths_exact_grammar() {
        for value in [
            "/dashboard",
            "/a/b?next=%2Fhome",
            "/done/{CHECKOUT_SESSION_ID}",
        ] {
            assert!(safe_relative_callback(value), "rejected {value}");
        }
        for value in [
            "//evil.test",
            "/\\evil.test",
            "/%2fevil.test",
            "/%2Fevil.test",
            "/%5cevil.test",
            "/safe%2f..%2f%2fevil.test",
            "/path#fragment",
            "https://evil.test",
        ] {
            assert!(!safe_relative_callback(value), "accepted {value}");
        }
    }
}
