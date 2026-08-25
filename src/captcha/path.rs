use regex::Regex;

const DEFAULT_ENDPOINTS: [&str; 3] = [
    "/sign-up/email",
    "/sign-in/email",
    "/request-password-reset",
];

pub(crate) struct ProtectedEndpoints(Vec<EndpointMatcher>);

enum EndpointMatcher {
    Exact(String),
    Wildcard(Regex),
}

impl ProtectedEndpoints {
    pub(crate) fn new(configured: Option<&[String]>) -> Self {
        let configured = configured.filter(|endpoints| !endpoints.is_empty());
        let endpoints: Vec<_> = configured
            .map(|endpoints| endpoints.iter().map(String::as_str).collect())
            .unwrap_or_else(|| DEFAULT_ENDPOINTS.to_vec());
        Self(endpoints.into_iter().map(EndpointMatcher::new).collect())
    }

    pub(crate) fn matches(&self, pathname: &str, base_path: &str) -> bool {
        let normalized = normalize_endpoint_path(pathname, base_path);
        self.0.iter().any(|matcher| matcher.matches(&normalized))
    }
}

impl EndpointMatcher {
    fn new(endpoint: &str) -> Self {
        if endpoint.contains('*') {
            Self::Wildcard(wildcard_regex(endpoint))
        } else {
            Self::Exact(endpoint.to_owned())
        }
    }

    fn matches(&self, pathname: &str) -> bool {
        match self {
            Self::Exact(endpoint) => endpoint == pathname,
            Self::Wildcard(regex) => regex.is_match(pathname),
        }
    }
}

fn normalize_endpoint_path(pathname: &str, base_path: &str) -> String {
    let without_base = pathname.strip_prefix(base_path).unwrap_or(pathname);
    let mut normalized = String::with_capacity(without_base.len() + 1);
    let mut previous_slash = false;
    for character in without_base.chars() {
        if character == '/' && previous_slash {
            continue;
        }
        previous_slash = character == '/';
        normalized.push(character);
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn wildcard_regex(pattern: &str) -> Regex {
    const REQUIRED_SEPARATOR: &str = r"[/\\]+?";
    const OPTIONAL_SEPARATOR: &str = r"[/\\]*?";
    const WILDCARD: &str = r"[^/\\]";
    let segments: Vec<_> = pattern.split('/').collect();
    let mut output = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() && index > 0 {
            continue;
        }
        let separator = if index == segments.len() - 1 {
            OPTIONAL_SEPARATOR
        } else if segments.get(index + 1) == Some(&"**") {
            ""
        } else {
            REQUIRED_SEPARATOR
        };
        if *segment == "**" {
            if !separator.is_empty() {
                if index > 0 {
                    output.push_str(separator);
                }
                output.push_str("(?:");
                output.push_str(WILDCARD);
                output.push_str("*?");
                output.push_str(separator);
                output.push_str(")*?");
            }
            continue;
        }
        append_segment(&mut output, segment, WILDCARD);
        output.push_str(separator);
    }
    output.push('$');
    Regex::new(&output).expect("escaped wildcard patterns always compile")
}

fn append_segment(output: &mut String, segment: &str, wildcard: &str) {
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                if let Some(literal) = characters.next() {
                    output.push_str(&regex::escape(&literal.to_string()));
                }
            }
            '?' => output.push_str(wildcard),
            '*' => {
                output.push_str(wildcard);
                output.push_str("*?");
            }
            literal => output.push_str(&regex::escape(&literal.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_base_duplicate_and_trailing_slashes() {
        assert_eq!(
            normalize_endpoint_path("/api/auth/sign-in//email/", "/api/auth"),
            "/sign-in/email"
        );
        assert_eq!(normalize_endpoint_path("/outside", "/api/auth"), "/outside");
        assert_eq!(normalize_endpoint_path("/api/auth", "/api/auth"), "/");
        assert_eq!(
            normalize_endpoint_path("/api/authentic", "/api/auth"),
            "/entic"
        );
    }

    #[test]
    fn defaults_empty_replacement_and_exact_matching_are_compatible() {
        for configured in [None, Some(Vec::<String>::new())] {
            let endpoints = ProtectedEndpoints::new(configured.as_deref());
            assert!(endpoints.matches("/api/auth/sign-in/email", "/api/auth"));
            assert!(!endpoints.matches("/api/auth/sign-in/email-otp", "/api/auth"));
        }
        let configured = vec!["/sign-in/email-otp".into()];
        let endpoints = ProtectedEndpoints::new(Some(&configured));
        assert!(!endpoints.matches("/api/auth/sign-in/email", "/api/auth"));
        assert!(endpoints.matches("/api/auth/sign-in/email-otp", "/api/auth"));
    }

    #[test]
    fn single_and_nested_wildcards_match_the_pinned_utility() {
        let single = ProtectedEndpoints::new(Some(&["/sign-in/*".into()]));
        assert!(single.matches("/api/auth/sign-in/email", "/api/auth"));
        assert!(!single.matches("/api/auth/sign-in/social/google", "/api/auth"));
        assert!(!single.matches("/api/auth/sign-in", "/api/auth"));

        let nested = ProtectedEndpoints::new(Some(&["/sign-in/**".into()]));
        assert!(nested.matches("/api/auth/sign-in", "/api/auth"));
        assert!(nested.matches("/api/auth/sign-in/social/google", "/api/auth"));
    }

    #[test]
    fn question_mark_is_special_only_when_a_star_selects_wildcard_mode() {
        let literal = ProtectedEndpoints::new(Some(&["/sign-in/?".into()]));
        assert!(!literal.matches("/api/auth/sign-in/a", "/api/auth"));
        let wildcard = ProtectedEndpoints::new(Some(&["/sign-in/?*".into()]));
        assert!(wildcard.matches("/api/auth/sign-in/ab", "/api/auth"));
    }
}
