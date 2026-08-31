use crate::AuthError;
use url::Url;

pub(crate) fn append_query_params(
    input: &str,
    params: &[(&str, &str)],
) -> Result<String, AuthError> {
    let relative = input.starts_with('/');
    if input.starts_with("//") || input.starts_with("/\\") {
        return Err(AuthError::InvalidCallbackUrl);
    }
    if relative {
        let reference = Url::parse("https://better-auth.invalid").expect("static URL is valid");
        let parsed = reference
            .join(input)
            .map_err(|_| AuthError::InvalidCallbackUrl)?;
        if parsed.origin() != reference.origin() {
            return Err(AuthError::InvalidCallbackUrl);
        }
    } else {
        Url::parse(input).map_err(|_| AuthError::InvalidCallbackUrl)?;
    }
    if params.is_empty() {
        return Ok(input.to_owned());
    }

    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.extend_pairs(params.iter().copied());
    let query = query.finish();
    let (before_fragment, fragment) = input
        .split_once('#')
        .map_or((input, None), |(before, fragment)| (before, Some(fragment)));
    let separator = if before_fragment.ends_with(['?', '&']) {
        ""
    } else if before_fragment.contains('?') {
        "&"
    } else {
        "?"
    };
    let mut result = format!("{before_fragment}{separator}{query}");
    if let Some(fragment) = fragment {
        result.push('#');
        result.push_str(fragment);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::append_query_params;

    #[test]
    fn parameters_are_inserted_before_fragments_without_reencoding() {
        let params = &[("error", "access denied")];
        assert_eq!(
            append_query_params("/login#step2", params).unwrap(),
            "/login?error=access+denied#step2"
        );
        assert_eq!(
            append_query_params(
                "https://example.com/login?lang=ko#step2",
                params
            )
            .unwrap(),
            "https://example.com/login?lang=ko&error=access+denied#step2"
        );
        assert_eq!(
            append_query_params("myapp://callback#step2", params).unwrap(),
            "myapp://callback?error=access+denied#step2"
        );
        assert_eq!(
            append_query_params("/search?q=hello%20world&next=~#results", params).unwrap(),
            "/search?q=hello%20world&next=~&error=access+denied#results"
        );
        assert_eq!(
            append_query_params("/login?source=oauth&#retry", params).unwrap(),
            "/login?source=oauth&error=access+denied#retry"
        );
        assert_eq!(
            append_query_params("/login#", params).unwrap(),
            "/login?error=access+denied#"
        );
        assert_eq!(
            append_query_params("/callback?next=\\foo#\\bar", params).unwrap(),
            "/callback?next=\\foo&error=access+denied#\\bar"
        );
        assert_eq!(
            append_query_params("/login?#step2", &[]).unwrap(),
            "/login?#step2"
        );
    }

    #[test]
    fn ambiguous_relative_authorities_are_rejected() {
        for input in [
            "//evil.example.com",
            "//better-auth.invalid/path",
            "/\\better-auth.invalid/path",
        ] {
            assert!(append_query_params(input, &[("error", "denied")]).is_err());
            assert!(append_query_params(input, &[]).is_err());
        }
    }
}
