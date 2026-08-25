use super::super::{OAuthProviderConfig, OAuthProviderError};
use std::collections::BTreeSet;

const USER_DELEGATED_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

pub(super) fn normalize(scopes: &mut Vec<String>) -> Result<(), OAuthProviderError> {
    if scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(OAuthProviderError::InvalidRequest(
            "client_credentials_scopes must not contain empty values".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    *scopes = scopes
        .drain(..)
        .map(|scope| scope.trim().to_owned())
        .filter(|scope| seen.insert(scope.clone()))
        .collect();
    Ok(())
}

pub(super) fn validate(
    config: &OAuthProviderConfig,
    scopes: &[String],
    grant_types: &[String],
    token_endpoint_auth_method: Option<&str>,
) -> Result<(), OAuthProviderError> {
    if scopes.is_empty() {
        return Ok(());
    }
    if !grant_types
        .iter()
        .any(|grant| grant == "client_credentials")
    {
        return Err(OAuthProviderError::InvalidRequest(
            "client_credentials_scopes requires the client_credentials grant".into(),
        ));
    }
    if token_endpoint_auth_method == Some("none") {
        return Err(OAuthProviderError::InvalidRequest(
            "public clients cannot be assigned client_credentials scopes".into(),
        ));
    }
    let invalid = scopes
        .iter()
        .filter(|scope| {
            !config.scopes.contains(scope) || USER_DELEGATED_SCOPES.contains(&scope.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Err(OAuthProviderError::InvalidScope(format!(
            "The following client_credentials scopes are invalid: {}",
            invalid.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects_user_delegated_or_public_scopes() {
        let mut scopes = vec![" api.read ".into(), "api.read".into()];
        normalize(&mut scopes).unwrap();
        assert_eq!(scopes, ["api.read"]);
        assert_eq!(
            normalize(&mut vec!["  ".into()]),
            Err(OAuthProviderError::InvalidRequest(
                "client_credentials_scopes must not contain empty values".into()
            ))
        );

        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.scopes.push("api.read".into());
        assert!(
            validate(
                &config,
                &scopes,
                &["client_credentials".into()],
                Some("client_secret_basic")
            )
            .is_ok()
        );
        assert_eq!(
            validate(
                &config,
                &["openid".into(), "missing".into()],
                &["client_credentials".into()],
                Some("client_secret_basic")
            ),
            Err(OAuthProviderError::InvalidScope(
                "The following client_credentials scopes are invalid: openid, missing".into()
            ))
        );
        assert_eq!(
            validate(
                &config,
                &scopes,
                &["client_credentials".into()],
                Some("none")
            ),
            Err(OAuthProviderError::InvalidRequest(
                "public clients cannot be assigned client_credentials scopes".into()
            ))
        );
    }
}
