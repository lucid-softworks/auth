use std::collections::BTreeMap;

use super::{DEFAULT_DPOP_ALGORITHMS, OAuthProviderError};

/// Options accepted by [`create_oauth_resource_server_challenge`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthResourceServerChallengeOptions {
    /// Metadata URLs for resource identifiers such as URNs that have no URL origin.
    pub resource_metadata_mappings: BTreeMap<String, String>,
    /// DPoP algorithms to advertise. `None` uses Better Auth's pinned defaults.
    pub dpop_signing_algorithms: Option<Vec<String>>,
    /// Scopes advertised for a missing or otherwise invalid bearer token.
    pub challenge_scopes: Option<Vec<String>>,
}

/// A challenge response suitable for conversion into an HTTP error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthResourceServerChallenge {
    pub status_code: u16,
    pub message: String,
    pub www_authenticate: String,
}

/// Invalid resource-server challenge input, matching upstream's fail-closed behavior.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthResourceServerChallengeError {
    #[error("missing resource_metadata mapping for {0}")]
    MissingResourceMetadataMapping(String),
    #[error("invalid challenge scope: {0:?}")]
    InvalidScope(String),
    #[error("required_scopes must contain at least one scope")]
    MissingRequiredScopes,
    #[error("invalid error_description")]
    InvalidErrorDescription,
    #[error("invalid WWW-Authenticate parameter")]
    InvalidAuthenticationParameter,
}

/// Native equivalent of Better Auth's exported `createResourceServerChallenge`.
///
/// Returns no challenge for errors that authorization cannot repair, including
/// ordinary permission denials and deliberately unchallenged invalid tokens.
pub fn create_oauth_resource_server_challenge(
    error: &OAuthProviderError,
    resources: &[impl AsRef<str>],
    options: &OAuthResourceServerChallengeOptions,
) -> Result<Option<OAuthResourceServerChallenge>, OAuthResourceServerChallengeError> {
    let scopes = serialize_scopes(options.challenge_scopes.as_deref())?;
    let result =
        match error {
            OAuthProviderError::InvalidDpopProof(description) => {
                Some(dpop_challenge("invalid_dpop_proof", description, options)?)
            }
            OAuthProviderError::InvalidToken(description) if description.contains("DPoP") => {
                Some(dpop_challenge("invalid_token", description, options)?)
            }
            OAuthProviderError::InvalidToken(description)
            | OAuthProviderError::UnauthorizedInvalidRequest(description)
            | OAuthProviderError::UnauthorizedInvalidClient(description)
            | OAuthProviderError::BasicInvalidClient(description) => Some(bearer_challenge(
                description,
                resources,
                options,
                scopes.as_deref(),
            )?),
            OAuthProviderError::ChallengedInvalidClient { description, .. } => Some(
                bearer_challenge(description, resources, options, scopes.as_deref())?,
            ),
            OAuthProviderError::InsufficientScope {
                description,
                required_scopes,
            } => {
                validate_description(description)?;
                if required_scopes.is_empty() {
                    return Err(OAuthResourceServerChallengeError::MissingRequiredScopes);
                }
                let required_scope = serialize_scopes(Some(required_scopes))?;
                Some(OAuthResourceServerChallenge {
                    status_code: 403,
                    message: description.clone(),
                    www_authenticate: bearer_challenges(resources, options, |metadata| {
                        let mut parameters = vec!["error=\"insufficient_scope\"".to_owned()];
                        if let Some(required_scope) = &required_scope {
                            parameters
                                .push(format!("scope=\"{}\"", quote_parameter(required_scope)?));
                        }
                        parameters.push(format!(
                            "resource_metadata=\"{}\"",
                            quote_parameter(&metadata)?
                        ));
                        parameters.push(format!("error_description=\"{description}\""));
                        Ok(parameters)
                    })?,
                })
            }
            _ => None,
        };
    Ok(result)
}

fn bearer_challenge(
    description: &str,
    resources: &[impl AsRef<str>],
    options: &OAuthResourceServerChallengeOptions,
    scopes: Option<&str>,
) -> Result<OAuthResourceServerChallenge, OAuthResourceServerChallengeError> {
    Ok(OAuthResourceServerChallenge {
        status_code: 401,
        message: description.to_owned(),
        www_authenticate: bearer_challenges(resources, options, |metadata| {
            let mut parameters = vec![format!(
                "resource_metadata=\"{}\"",
                quote_parameter(&metadata)?
            )];
            if let Some(scopes) = scopes {
                parameters.push(format!("scope=\"{}\"", quote_parameter(scopes)?));
            }
            Ok(parameters)
        })?,
    })
}

fn dpop_challenge(
    code: &str,
    description: &str,
    options: &OAuthResourceServerChallengeOptions,
) -> Result<OAuthResourceServerChallenge, OAuthResourceServerChallengeError> {
    validate_description(description)?;
    let algorithms = options
        .dpop_signing_algorithms
        .as_ref()
        .map(|algorithms| algorithms.join(" "))
        .unwrap_or_else(|| DEFAULT_DPOP_ALGORITHMS.join(" "));
    Ok(OAuthResourceServerChallenge {
        status_code: 401,
        message: description.to_owned(),
        www_authenticate: format!(
            "DPoP error=\"{}\", error_description=\"{}\", algs=\"{}\"",
            quote_parameter(code)?,
            quote_parameter(description)?,
            quote_parameter(&algorithms)?
        ),
    })
}

fn bearer_challenges(
    resources: &[impl AsRef<str>],
    options: &OAuthResourceServerChallengeOptions,
    parameters: impl Fn(String) -> Result<Vec<String>, OAuthResourceServerChallengeError>,
) -> Result<String, OAuthResourceServerChallengeError> {
    resources
        .iter()
        .map(|resource| {
            let metadata = resource_metadata_url(resource.as_ref(), options)?;
            Ok(format!("Bearer {}", parameters(metadata)?.join(", ")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|challenges| challenges.join(", "))
}

fn resource_metadata_url(
    resource: &str,
    options: &OAuthResourceServerChallengeOptions,
) -> Result<String, OAuthResourceServerChallengeError> {
    if let Ok(url) = url::Url::parse(resource)
        && url.origin().ascii_serialization() != "null"
    {
        let path = url.path().strip_suffix('/').unwrap_or(url.path());
        return Ok(format!(
            "{}/.well-known/oauth-protected-resource{}{}",
            url.origin().ascii_serialization(),
            path,
            url.query()
                .map_or_else(String::new, |query| format!("?{query}"))
        ));
    }
    options
        .resource_metadata_mappings
        .get(resource)
        .cloned()
        .ok_or_else(|| {
            OAuthResourceServerChallengeError::MissingResourceMetadataMapping(resource.into())
        })
}

fn serialize_scopes(
    scopes: Option<&[String]>,
) -> Result<Option<String>, OAuthResourceServerChallengeError> {
    let Some(scopes) = scopes else {
        return Ok(None);
    };
    let mut unique = Vec::new();
    for scope in scopes {
        if !scope.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        }) {
            return Err(OAuthResourceServerChallengeError::InvalidScope(
                scope.clone(),
            ));
        }
        if !unique.contains(scope) {
            unique.push(scope.clone());
        }
    }
    Ok((!unique.is_empty()).then(|| unique.join(" ")))
}

fn validate_description(value: &str) -> Result<(), OAuthResourceServerChallengeError> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte == 0x20
                || byte == 0x21
                || (0x23..=0x5b).contains(&byte)
                || (0x5d..=0x7e).contains(&byte)
        })
    {
        return Err(OAuthResourceServerChallengeError::InvalidErrorDescription);
    }
    Ok(())
}

fn quote_parameter(value: &str) -> Result<String, OAuthResourceServerChallengeError> {
    if value.bytes().any(|byte| byte <= 0x1f || byte == 0x7f) {
        return Err(OAuthResourceServerChallengeError::InvalidAuthenticationParameter);
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenge_maps_url_resources_and_deduplicates_scopes() {
        let challenge = create_oauth_resource_server_challenge(
            &OAuthProviderError::InvalidToken("expired".into()),
            &["https://api.example.test/orders/?tenant=one"],
            &OAuthResourceServerChallengeOptions {
                challenge_scopes: Some(vec!["read".into(), "read".into(), "write".into()]),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(challenge.status_code, 401);
        assert_eq!(
            challenge.www_authenticate,
            "Bearer resource_metadata=\"https://api.example.test/.well-known/oauth-protected-resource/orders?tenant=one\", scope=\"read write\""
        );
    }

    #[test]
    fn non_url_resources_require_an_explicit_metadata_mapping() {
        let error = OAuthProviderError::InvalidToken("missing".into());
        let missing = create_oauth_resource_server_challenge(
            &error,
            &["urn:example:resource"],
            &OAuthResourceServerChallengeOptions::default(),
        );
        assert_eq!(
            missing,
            Err(
                OAuthResourceServerChallengeError::MissingResourceMetadataMapping(
                    "urn:example:resource".into()
                )
            )
        );

        let mut options = OAuthResourceServerChallengeOptions::default();
        options.resource_metadata_mappings.insert(
            "urn:example:resource".into(),
            "https://api.example.test/.well-known/oauth-protected-resource".into(),
        );
        let challenge =
            create_oauth_resource_server_challenge(&error, &["urn:example:resource"], &options)
                .unwrap()
                .unwrap();
        assert!(
            challenge
                .www_authenticate
                .contains("https://api.example.test/")
        );
    }

    #[test]
    fn insufficient_scope_and_dpop_challenges_match_their_protocols() {
        let options = OAuthResourceServerChallengeOptions::default();
        let insufficient = create_oauth_resource_server_challenge(
            &OAuthProviderError::InsufficientScope {
                description: "access token is missing required scope: orders:write".into(),
                required_scopes: vec!["orders:write".into()],
            },
            &["https://api.example.test"],
            &options,
        )
        .unwrap()
        .unwrap();
        assert_eq!(insufficient.status_code, 403);
        assert_eq!(
            insufficient.www_authenticate,
            "Bearer error=\"insufficient_scope\", scope=\"orders:write\", resource_metadata=\"https://api.example.test/.well-known/oauth-protected-resource\", error_description=\"access token is missing required scope: orders:write\""
        );

        let dpop = create_oauth_resource_server_challenge(
            &OAuthProviderError::InvalidDpopProof("proof rejected".into()),
            &["https://api.example.test"],
            &options,
        )
        .unwrap()
        .unwrap();
        assert_eq!(dpop.status_code, 401);
        assert_eq!(
            dpop.www_authenticate,
            "DPoP error=\"invalid_dpop_proof\", error_description=\"proof rejected\", algs=\"EdDSA ES256 ES512 PS256 RS256\""
        );
    }

    #[test]
    fn unrelated_failures_do_not_invite_reauthorization() {
        for error in [
            OAuthProviderError::AccessDenied("not permitted".into()),
            OAuthProviderError::UnchallengedInvalidToken("missing token".into()),
        ] {
            let result = create_oauth_resource_server_challenge(
                &error,
                &["https://api.example.test"],
                &OAuthResourceServerChallengeOptions::default(),
            )
            .unwrap();
            assert_eq!(result, None);
        }
    }

    #[test]
    fn every_non_dpop_unauthorized_error_gets_a_bearer_challenge() {
        let challenge = create_oauth_resource_server_challenge(
            &OAuthProviderError::UnauthorizedInvalidRequest("missing credentials".into()),
            &["https://api.example.test"],
            &OAuthResourceServerChallengeOptions::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(challenge.status_code, 401);
        assert!(challenge.www_authenticate.starts_with("Bearer "));
    }

    #[test]
    fn unsafe_header_values_fail_closed() {
        let options = OAuthResourceServerChallengeOptions {
            challenge_scopes: Some(vec!["read write".into()]),
            ..Default::default()
        };
        assert!(matches!(
            create_oauth_resource_server_challenge(
                &OAuthProviderError::InvalidToken("missing".into()),
                &["https://api.example.test"],
                &options
            ),
            Err(OAuthResourceServerChallengeError::InvalidScope(_))
        ));
    }

    #[test]
    fn an_empty_scope_list_omits_the_scope_parameter() {
        let challenge = create_oauth_resource_server_challenge(
            &OAuthProviderError::InvalidToken("missing".into()),
            &["https://api.example.test"],
            &OAuthResourceServerChallengeOptions {
                challenge_scopes: Some(Vec::new()),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(!challenge.www_authenticate.contains("scope="));
    }
}
