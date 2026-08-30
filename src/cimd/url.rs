use regex::Regex;
use std::sync::OnceLock;
use url::Url;

pub fn is_cimd_client_id_url_candidate(client_id: &str) -> bool {
    Url::parse(client_id).is_ok_and(|url| url.scheme() == "https")
}

/// Validates the draft-02 fetch boundary. `None` means the URL is valid.
pub fn validate_client_id_url(value: &str) -> Option<String> {
    static DOT_SEGMENT: OnceLock<Regex> = OnceLock::new();
    let dot_segment = DOT_SEGMENT.get_or_init(|| {
        Regex::new(r"(?i)/(?:\.|%2e)(?:\.|%2e)?(?:/|$|#|\?)")
            .expect("the static CIMD dot-segment expression is valid")
    });
    if dot_segment.is_match(value) {
        return Some("client_id URL MUST NOT contain dot segments".into());
    }
    if value.contains('#') {
        return Some("client_id URL MUST NOT contain a fragment".into());
    }
    let Ok(parsed) = Url::parse(value) else {
        return Some("client_id is not a valid URL".into());
    };
    if parsed.scheme() != "https" {
        return Some("client_id URL must use HTTPS".into());
    }
    let Some(authority_start) = case_insensitive_https_authority(value) else {
        return Some("client_id URL MUST use an explicit HTTPS authority form".into());
    };
    if value.contains('\\') {
        return Some("client_id URL MUST use an explicit HTTPS authority form".into());
    }
    let suffix = &value[authority_start..];
    let first_delimiter = suffix.find(['/', '?', '#']);
    if suffix.is_empty()
        || first_delimiter.is_none()
        || !matches!(first_delimiter.and_then(|index| suffix.as_bytes().get(index)), Some(b'/'))
    {
        return Some("client_id URL MUST contain an explicit path component".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("client_id URL MUST NOT contain credentials".into());
    }
    if parsed
        .host_str()
        .is_none_or(|host| !crate::network_address::is_public_routable_host(host))
    {
        return Some("client_id URL must not target a private or reserved address".into());
    }
    None
}

fn case_insensitive_https_authority(value: &str) -> Option<usize> {
    value
        .get(..8)
        .filter(|prefix| prefix.eq_ignore_ascii_case("https://"))
        .map(|_| 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_is_only_a_parsed_https_routing_predicate() {
        assert!(is_cimd_client_id_url_candidate("https://127.0.0.1"));
        assert!(is_cimd_client_id_url_candidate("HTTPS://client.example"));
        assert!(!is_cimd_client_id_url_candidate("http://client.example/doc"));
        assert!(!is_cimd_client_id_url_candidate("not a url"));
    }

    #[test]
    fn fetchable_identifier_preserves_the_stricter_security_boundary() {
        assert_eq!(validate_client_id_url("https://client.example/doc"), None);
        assert_eq!(validate_client_id_url("https://client.example/"), None);
        assert_eq!(validate_client_id_url("https://client.example/doc?q=1"), None);
        for value in [
            "http://client.example/doc",
            "https://client.example",
            "https://client.example?q=1",
            "https://user@client.example/doc",
            "https://client.example/doc#fragment",
            "https://client.example/a/../doc",
            "https://client.example/a/%2e%2e/doc",
            "https:\\client.example\\doc",
            "https://127.0.0.1/doc",
            "https://169.254.169.254/doc",
            "https://metadata.google.internal/doc",
        ] {
            assert!(validate_client_id_url(value).is_some(), "{value}");
        }
    }
}
