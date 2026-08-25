pub(crate) fn capability_covers(granted: &str, required: &str) -> bool {
    if granted == required || granted == "*" {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix('*')
        && granted.ends_with(".*")
        && required.starts_with(prefix)
    {
        return true;
    }
    let Some((_, unprefixed)) = required.split_once('.') else {
        return false;
    };
    if granted == unprefixed {
        return true;
    }
    granted
        .strip_suffix('*')
        .is_some_and(|prefix| granted.ends_with(".*") && unprefixed.starts_with(prefix))
}

#[cfg(feature = "axum")]
pub(crate) fn has_capability(granted: &[String], required: &str) -> bool {
    granted
        .iter()
        .any(|capability| capability_covers(capability, required))
}

#[cfg(feature = "axum")]
pub(crate) fn find_blocked_capabilities(requested: &[String], blocked: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|requested| {
            blocked
                .iter()
                .any(|blocked| capability_covers(blocked, requested))
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_global_trailing_wildcard_and_provider_stripping() {
        assert!(capability_covers("mail.send", "mail.send"));
        assert!(capability_covers("*", "mail.send"));
        assert!(capability_covers("github.*", "github.issues.read"));
        assert!(capability_covers("issues.read", "github.issues.read"));
        assert!(!capability_covers("github.issue", "github.issues.read"));
        assert!(!capability_covers("mail.*", "email.send"));
    }
}
