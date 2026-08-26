async fn resolve_resource_policy(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    client: &OAuthProviderClient,
    requested_scopes: &[String],
    resources: Option<&[String]>,
    headers: &HeaderMap,
) -> Result<ResourcePolicy, OAuthProviderError> {
    let Some(resources) = resources else {
        return Ok(ResourcePolicy {
            audience: None,
            scopes: requested_scopes.to_vec(),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            custom_claims: Map::new(),
            dpop_required: false,
        });
    };
    let userinfo = format!("{}/oauth2/userinfo", issuer(service, headers));
    let resolved = resolve_requested_resources(store, resources, &userinfo).await?;
    enforce_client_resource_links(config, store, client, &resolved).await?;
    let scopes = resource_scopes(requested_scopes, &resolved)?;
    let (signing_algorithm, signing_key_id) = resource_signing_pins(&resolved)?;
    let mut audience = resources.to_vec();
    if scopes.iter().any(|scope| scope == "openid") && !audience.contains(&userinfo) {
        audience.push(userinfo);
    }
    Ok(resource_policy(audience, scopes, resolved, signing_algorithm, signing_key_id))
}

async fn resolve_requested_resources(
    store: &dyn OAuthProviderStore,
    resources: &[String],
    userinfo: &str,
) -> Result<Vec<OAuthProviderResource>, OAuthProviderError> {
    let mut resolved = Vec::<OAuthProviderResource>::new();
    for identifier in resources {
        if identifier == userinfo {
            continue;
        }
        let resource = store
            .find_oauth_resource(identifier)
            .await
            .map_err(server)?
            .ok_or_else(|| {
                OAuthProviderError::InvalidTarget(format!(
                    "requested resource {identifier} is not configured"
                ))
            })?;
        if resource.disabled {
            return Err(OAuthProviderError::InvalidTarget(format!(
                "requested resource {identifier} is disabled"
            )));
        }
        resolved.push(resource);
    }
    Ok(resolved)
}

async fn enforce_client_resource_links(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    client: &OAuthProviderClient,
    resolved: &[OAuthProviderResource],
) -> Result<(), OAuthProviderError> {
    if config.enforce_per_client_resources && !resolved.is_empty() {
        let linked: BTreeSet<String> = store
            .list_oauth_client_resources(&client.client_id)
            .await
            .map_err(server)?
            .into_iter()
            .map(|link| link.resource_id)
            .collect();
        let missing = resolved
            .iter()
            .filter(|resource| !linked.contains(&resource.identifier))
            .map(|resource| resource.identifier.clone())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(OAuthProviderError::InvalidTarget(format!(
                "client {} is not linked to resource(s) {}",
                client.client_id,
                missing.join(", ")
            )));
        }
    }
    Ok(())
}

fn resource_scopes(
    requested_scopes: &[String],
    resolved: &[OAuthProviderResource],
) -> Result<Vec<String>, OAuthProviderError> {
    let mut scopes = requested_scopes.to_vec();
    for resource in resolved {
        if let Some(allowed) = &resource.allowed_scopes {
            let intersection = scopes
                .iter()
                .filter(|scope| allowed.contains(scope))
                .cloned()
                .collect::<Vec<_>>();
            if intersection.is_empty() {
                return Err(OAuthProviderError::InvalidScope(format!(
                    "none of the requested scopes are allowed for resource {}",
                    resource.identifier
                )));
            }
            scopes = intersection;
        }
    }
    Ok(scopes)
}

fn resource_signing_pins(
    resolved: &[OAuthProviderResource],
) -> Result<(Option<String>, Option<String>), OAuthProviderError> {
    let unique_algorithms = resolved
        .iter()
        .filter_map(|resource| resource.signing_algorithm.clone())
        .collect::<BTreeSet<_>>();
    let unique_keys = resolved
        .iter()
        .filter_map(|resource| resource.signing_key_id.clone())
        .collect::<BTreeSet<_>>();
    if unique_algorithms.len() > 1 {
        return Err(OAuthProviderError::InvalidRequest("multi-resource request has conflicting signingAlgorithm pins; a single JWS signature cannot satisfy multiple algorithms".into()));
    }
    if unique_keys.len() > 1 {
        return Err(OAuthProviderError::InvalidRequest("multi-resource request has conflicting signingKeyId pins; a single JWS signature cannot satisfy multiple key ids".into()));
    }
    Ok((unique_algorithms.into_iter().next(), unique_keys.into_iter().next()))
}

fn resource_policy(
    audience: Vec<String>,
    scopes: Vec<String>,
    resolved: Vec<OAuthProviderResource>,
    signing_algorithm: Option<String>,
    signing_key_id: Option<String>,
) -> ResourcePolicy {
    let mut custom_claims = Map::new();
    for resource in &resolved {
        if let Some(Value::Object(claims)) = &resource.custom_claims {
            custom_claims.extend(claims.clone());
        }
    }
    ResourcePolicy {
        audience: Some(audience),
        scopes,
        access_token_ttl: resolved
            .iter()
            .filter_map(|resource| resource.access_token_ttl)
            .filter_map(|ttl| u64::try_from(ttl).ok())
            .min(),
        refresh_token_ttl: resolved
            .iter()
            .filter_map(|resource| resource.refresh_token_ttl)
            .filter_map(|ttl| u64::try_from(ttl).ok())
            .min(),
        signing_algorithm,
        signing_key_id,
        custom_claims,
        dpop_required: resolved
            .iter()
            .any(|resource| resource.dpop_bound_access_tokens_required),
    }
}

async fn generate_opaque(
    config: &OAuthProviderConfig,
) -> Result<(String, String), OAuthProviderError> {
    let plain = match &config.callbacks.generate_opaque_access_token {
        Some(generator) => generator.generate().await.map_err(server)?,
        None => random_letters(32),
    };
    let stored = store_token(config, &plain, OAuthStoredTokenType::AccessToken)
        .await
        .map_err(server)?;
    Ok((plain, stored))
}

async fn generate_refresh(
    config: &OAuthProviderConfig,
) -> Result<(String, String), OAuthProviderError> {
    let plain = match &config.callbacks.generate_refresh_token {
        Some(generator) => generator.generate().await.map_err(server)?,
        None => random_letters(32),
    };
    let stored = store_token(config, &plain, OAuthStoredTokenType::RefreshToken)
        .await
        .map_err(server)?;
    Ok((plain, stored))
}

async fn encode_refresh_token(
    config: &OAuthProviderConfig,
    token: &str,
    session_id: Option<&str>,
) -> Result<String, OAuthProviderError> {
    let encoded = match &config.callbacks.format_refresh_token {
        Some(codec) => codec
            .encrypt(token, session_id)
            .await
            .map_err(server)?,
        None => token.to_owned(),
    };
    Ok(apply_token_prefix(
        config,
        encoded,
        OAuthStoredTokenType::RefreshToken,
    ))
}

async fn decode_refresh_token(
    config: &OAuthProviderConfig,
    token: &str,
) -> Result<String, OAuthProviderError> {
    let stripped = strip_token_prefix(config, token, OAuthStoredTokenType::RefreshToken)
        .ok_or_else(|| OAuthProviderError::InvalidToken("refresh token not found".into()))?;
    match &config.callbacks.format_refresh_token {
        Some(codec) => Ok(codec.decrypt(stripped).await.map_err(server)?.token),
        None => Ok(stripped.to_owned()),
    }
}

#[cfg(test)]
mod resource_policy_tests {
    use super::*;

    fn resource(identifier: &str, scopes: &[&str]) -> OAuthProviderResource {
        OAuthProviderResource {
            id: Uuid::new_v4(), identifier: identifier.into(), name: identifier.into(),
            access_token_ttl: Some(900), refresh_token_ttl: Some(1_800),
            signing_algorithm: Some("RS256".into()), signing_key_id: Some("resource-key".into()),
            allowed_scopes: Some(scopes.iter().map(|value| (*value).into()).collect()),
            custom_claims: Some(json!({"tenant":"one"})),
            dpop_bound_access_tokens_required: true, disabled: false,
            created_at: None, updated_at: None, policy_version: 1, metadata: None,
        }
    }

    #[test]
    fn resource_policy_intersects_scopes_ttls_pins_claims_and_dpop() {
        let resources = vec![resource("https://api.example", &["read"] )];
        let scopes = resource_scopes(&["read".into(), "write".into()], &resources).unwrap();
        assert_eq!(scopes, ["read"]);
        let (algorithm, key) = resource_signing_pins(&resources).unwrap();
        let policy = resource_policy(vec!["https://api.example".into()], scopes, resources, algorithm, key);
        assert_eq!(policy.access_token_ttl, Some(900));
        assert_eq!(policy.refresh_token_ttl, Some(1_800));
        assert_eq!(policy.signing_algorithm.as_deref(), Some("RS256"));
        assert_eq!(policy.signing_key_id.as_deref(), Some("resource-key"));
        assert_eq!(policy.custom_claims["tenant"], "one");
        assert!(policy.dpop_required);
    }

    #[test]
    fn conflicting_resource_signing_pins_are_rejected() {
        let mut second = resource("https://other.example", &["read"]);
        second.signing_algorithm = Some("EdDSA".into());
        assert!(matches!(resource_signing_pins(&[resource("https://api.example", &["read"]), second]), Err(OAuthProviderError::InvalidRequest(_))));
    }
}
