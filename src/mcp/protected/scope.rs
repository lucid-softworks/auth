use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::{McpProtectedRequestError, McpScopeMatcher, VerificationFailure};

pub(super) fn validate_required_scopes(
    scopes: Option<&[String]>,
) -> Result<(), McpProtectedRequestError> {
    if let Some(scopes) = scopes {
        validate_scope_tokens(scopes, "required scope")?;
    }
    Ok(())
}

pub(super) fn validate_nonempty_scopes(scopes: &[String]) -> Result<(), McpProtectedRequestError> {
    if scopes.is_empty() {
        return Err(McpProtectedRequestError::InvalidConfiguration(
            "requiredScopes must contain at least one scope".into(),
        ));
    }
    validate_scope_tokens(scopes, "required scope")
}

fn validate_scope_tokens(scopes: &[String], label: &str) -> Result<(), McpProtectedRequestError> {
    for scope in scopes {
        if !valid_scope(scope) {
            return Err(McpProtectedRequestError::InvalidConfiguration(format!(
                "invalid {label}: {scope:?}"
            )));
        }
    }
    Ok(())
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

pub(super) fn enforce_scopes(
    payload: &Map<String, Value>,
    required: Option<&[String]>,
    matcher: Option<&McpScopeMatcher>,
) -> Result<(), VerificationFailure> {
    let granted = parse_granted_scopes(payload.get("scope"))?;
    let Some(required) = required else {
        return Ok(());
    };
    let missing: Vec<String> = required
        .iter()
        .filter(|required| {
            !matcher.map_or_else(
                || granted.contains(required.as_str()),
                |matcher| matcher(required, &granted),
            )
        })
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut unique = Vec::new();
    for scope in missing {
        if !unique.contains(&scope) {
            unique.push(scope);
        }
    }
    Err(VerificationFailure::Challenge(
        crate::OAuthProviderError::InsufficientScope {
            description: format!(
                "access token is missing required scope: {}",
                unique.join(" ")
            ),
            required_scopes: unique,
        },
    ))
}

fn parse_granted_scopes(scope: Option<&Value>) -> Result<BTreeSet<String>, VerificationFailure> {
    let Some(scope) = scope else {
        return Ok(BTreeSet::new());
    };
    let Some(scope) = scope.as_str() else {
        return Err(invalid_scope_claim());
    };
    let values: Vec<_> = scope.split(' ').collect();
    if scope.is_empty() || values.iter().any(|value| !valid_scope(value)) {
        return Err(invalid_scope_claim());
    }
    Ok(values.into_iter().map(str::to_owned).collect())
}

fn invalid_scope_claim() -> VerificationFailure {
    VerificationFailure::Challenge(crate::OAuthProviderError::InvalidToken(
        "access token scope claim is invalid".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_malformed_claims_and_reports_every_missing_scope() {
        let malformed = Map::from_iter([("scope".into(), json!(["read"]))]);
        assert!(parse_granted_scopes(malformed.get("scope")).is_err());
        let payload = Map::from_iter([("scope".into(), json!("read"))]);
        let failure = enforce_scopes(
            &payload,
            Some(&["read".into(), "write".into(), "delete".into()]),
            None,
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            VerificationFailure::Challenge(crate::OAuthProviderError::InsufficientScope {
                required_scopes,
                ..
            }) if required_scopes == ["write", "delete"]
        ));
    }
}
