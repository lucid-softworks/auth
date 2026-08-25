use crate::oauth_provider::authorization::OAuthAuthorizationQuery;

const SUPPORTED: [&str; 5] = ["none", "consent", "login", "create", "select_account"];

pub(super) fn parse(value: Option<&str>) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let tokens = value
        .split(' ')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err("prompt: prompt must include at least one value".into());
    }
    let mut unique = Vec::new();
    for token in tokens {
        if !SUPPORTED.contains(&token) {
            return Err(format!("prompt: unsupported prompt value: {token}"));
        }
        if !unique.contains(&token) {
            unique.push(token);
        }
    }
    if unique.contains(&"none") && unique.len() > 1 {
        return Err("prompt: prompt=none cannot be combined with other prompt values".into());
    }
    Ok(unique.into_iter().map(str::to_owned).collect())
}

pub(super) fn remove(query: &mut OAuthAuthorizationQuery, value: &str) {
    let Some(prompt) = query.prompt.as_deref() else {
        return;
    };
    let mut prompts = prompt.split(' ').map(str::to_owned).collect::<Vec<_>>();
    if let Some(index) = prompts.iter().position(|candidate| candidate == value) {
        prompts.remove(index);
        query.prompt = (!prompts.is_empty()).then(|| prompts.join(" "));
    }
}

pub(super) fn satisfy_fresh_authentication(
    query: &mut OAuthAuthorizationQuery,
    session_created_at_ms: i64,
    signed_query_issued_at_ms: Option<i64>,
) {
    if signed_query_issued_at_ms.is_some_and(|issued_at| session_created_at_ms >= issued_at) {
        remove(query, "login");
        query.max_age = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_grammar_matches_the_pinned_provider() {
        assert_eq!(
            parse(Some("login consent login")).unwrap(),
            ["login", "consent"]
        );
        assert!(parse(Some(" ")).unwrap_err().contains("at least one"));
        assert!(
            parse(Some("login unknown"))
                .unwrap_err()
                .contains("unknown")
        );
        assert!(
            parse(Some("none login"))
                .unwrap_err()
                .contains("cannot be combined")
        );
    }
}
