async fn client_credentials_grant(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
) -> Result<Value, OAuthProviderError> {
    let endpoint = format!("{}/oauth2/token", issuer(service, headers));
    let authenticated = authenticate_client(
        service,
        config,
        store,
        headers,
        params,
        &endpoint,
        Some("client_credentials"),
        true,
    )
    .await?;
    if authenticated.client.token_endpoint_auth_method.as_deref() == Some("none") {
        return Err(OAuthProviderError::UnauthorizedClient(
            "public clients cannot use the client_credentials grant".into(),
        ));
    }
    if authenticated.client.client_credentials_scopes.is_empty() {
        return Err(OAuthProviderError::UnauthorizedClient(
            "client has no authorized client_credentials scopes".into(),
        ));
    }
    let scopes = params
        .first("scope")
        .map(split_scopes)
        .unwrap_or_else(|| authenticated.client.client_credentials_scopes.clone());
    let allowed: BTreeSet<&str> = authenticated
        .client
        .client_credentials_scopes
        .iter()
        .map(String::as_str)
        .collect();
    let invalid = scopes
        .iter()
        .filter(|scope| !allowed.contains(scope.as_str()) || is_user_scope(scope))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Err(OAuthProviderError::InvalidScope(format!(
            "The following scopes are invalid: {}",
            invalid.join(", ")
        )));
    }
    issue_tokens(
        service,
        config,
        store,
        headers,
        IssueRequest {
            grant_type: "client_credentials".into(),
            endpoint,
            client: authenticated.client,
            user: None,
            session_id: None,
            scopes,
            resources: resources(params)?,
            original_resources: None,
            reference_id: None,
            authorization_code_id: None,
            nonce: None,
            auth_time: None,
            requested_userinfo_claims: Vec::new(),
            verification_value: None,
            previous_refresh: None,
            expected_dpop_jkt: None,
            extension_confirmation: authenticated.confirmation,
            access_token_claims: Map::new(),
            id_token_claims: Map::new(),
            token_response: Map::new(),
        },
    )
    .await
}

async fn refresh_token_grant(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
) -> Result<Value, OAuthProviderError> {
    let client_id = presented_client_id(headers, params)?
        .ok_or_else(|| OAuthProviderError::InvalidRequest("client_id is required".into()))?;
    let refresh = presented_refresh_token(config, store, params).await?;
    if refresh.client_id != client_id || refresh.expires_at <= Utc::now() {
        return Err(OAuthProviderError::InvalidGrant(
            "invalid refresh token".into(),
        ));
    }
    let (requested_resources, scopes) = refresh_narrowing(&refresh, params)?;
    let endpoint = format!("{}/oauth2/token", issuer(service, headers));
    let authenticated = authenticate_client(
        service,
        config,
        store,
        headers,
        params,
        &endpoint,
        Some("refresh_token"),
        true,
    )
    .await?;
    let effective_resources = requested_resources.or_else(|| refresh.resources.clone());
    let replay_fingerprint = rotation_request_fingerprint(
        &client_id,
        &scopes,
        effective_resources.as_deref(),
        refresh.confirmation.as_ref(),
    );
    if refresh.revoked.is_some() {
        validate_refresh_replay_dpop(config, store, headers, &endpoint, &refresh).await?;
        return reused_refresh_response(service, config, store, &client_id, &refresh, &replay_fingerprint).await;
    }
    issue_refreshed_tokens(
        service,
        config,
        store,
        headers,
        authenticated,
        refresh,
        scopes,
        effective_resources,
        endpoint,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn issue_refreshed_tokens(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    authenticated: AuthenticatedClient,
    refresh: OAuthProviderRefreshToken,
    scopes: Vec<String>,
    effective_resources: Option<Vec<String>>,
    endpoint: String,
) -> Result<Value, OAuthProviderError> {
    let user = service
        .auth_user_by_id(refresh.user_id)
        .await
        .map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidRequest("user not found".into()))?;
    issue_tokens(
        service,
        config,
        store,
        headers,
        IssueRequest {
            grant_type: "refresh_token".into(),
            endpoint,
            client: authenticated.client,
            user: Some(user),
            session_id: refresh.session_id,
            scopes,
            resources: effective_resources,
            original_resources: refresh.resources.clone(),
            reference_id: refresh.reference_id.clone(),
            authorization_code_id: refresh.authorization_code_id.clone(),
            nonce: None,
            auth_time: refresh.auth_time.map(|value| value.timestamp()),
            requested_userinfo_claims: refresh
                .requested_user_info_claims
                .clone()
                .unwrap_or_default(),
            verification_value: None,
            expected_dpop_jkt: refresh
                .confirmation
                .as_ref()
                .and_then(|value| value.get("jkt"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            previous_refresh: Some(refresh),
            extension_confirmation: authenticated.confirmation,
            access_token_claims: Map::new(),
            id_token_claims: Map::new(),
            token_response: Map::new(),
        },
    )
    .await
}

async fn validate_refresh_replay_dpop(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    endpoint: &str,
    refresh: &OAuthProviderRefreshToken,
) -> Result<(), OAuthProviderError> {
    let Some(expected) = refresh.confirmation.as_ref().and_then(|value| value.get("jkt")).and_then(Value::as_str) else {
        return Ok(());
    };
    let proof = headers.get("dpop").and_then(|value| value.to_str().ok())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP proof header is required".into()))?;
    verify_dpop(config, store, proof, "POST", endpoint, Some(expected), None).await?;
    Ok(())
}

async fn presented_refresh_token(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    params: &Parameters,
) -> Result<OAuthProviderRefreshToken, OAuthProviderError> {
    let presented = params.first("refresh_token").ok_or_else(|| OAuthProviderError::InvalidRequest(
        "Missing a required refresh_token for refresh_token grant".into(),
    ))?;
    let decoded = decode_refresh_token(config, presented).await?;
    let stored = store_token(config, &decoded, OAuthStoredTokenType::RefreshToken).await.map_err(server)?;
    store.find_oauth_refresh_token(&stored).await.map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidGrant("session not found".into()))
}

fn refresh_narrowing(
    refresh: &OAuthProviderRefreshToken,
    params: &Parameters,
) -> Result<(Option<Vec<String>>, Vec<String>), OAuthProviderError> {
    let requested_resources = resources(params)?;
    if let (Some(requested), Some(authorized)) = (&requested_resources, &refresh.resources)
        && requested.iter().any(|resource| !authorized.contains(resource))
    {
        return Err(OAuthProviderError::InvalidTarget("requested resource invalid".into()));
    }
    let scopes = params.first("scope").map(split_scopes).unwrap_or_else(|| refresh.scopes.clone());
    if let Some(scope) = scopes.iter().find(|scope| !refresh.scopes.contains(scope)) {
        return Err(OAuthProviderError::InvalidScope(format!("unable to issue scope {scope}")));
    }
    Ok((requested_resources, scopes))
}

async fn reused_refresh_response(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    client_id: &str,
    refresh: &OAuthProviderRefreshToken,
    fingerprint: &str,
) -> Result<Value, OAuthProviderError> {
    if config.refresh_token_reuse_interval > 0
        && refresh.rotation_replay_expires_at.is_some_and(|expires| expires >= Utc::now())
        && refresh.rotated_at == refresh.revoked
    {
        return replay_response(service, refresh, fingerprint)?.ok_or_else(|| {
            OAuthProviderError::InvalidGrant("invalid refresh token".into())
        });
    }
    store.revoke_oauth_refresh_family(client_id, refresh.user_id).await.map_err(server)?;
    Err(OAuthProviderError::InvalidGrant("invalid refresh token".into()))
}

fn presented_client_id(
    headers: &HeaderMap,
    params: &Parameters,
) -> Result<Option<String>, OAuthProviderError> {
    Ok(basic_credentials(headers)?
        .map(|value| value.0)
        .or_else(|| params.first("client_id").map(str::to_owned)))
}

fn split_scopes(value: &str) -> Vec<String> {
    value.split(' ').map(str::to_owned).collect()
}

fn is_user_scope(scope: &str) -> bool {
    matches!(scope, "openid" | "profile" | "email" | "offline_access")
}

fn validate_client_scopes(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    scopes: &[String],
) -> Result<(), OAuthProviderError> {
    let allowed = client.scopes.as_ref().unwrap_or(&config.scopes);
    if let Some(scope) = scopes.iter().find(|scope| !allowed.contains(scope)) {
        return Err(OAuthProviderError::InvalidScope(format!(
            "client is not authorized for scope {scope}"
        )));
    }
    Ok(())
}

fn resources(params: &Parameters) -> Result<Option<Vec<String>>, OAuthProviderError> {
    let Some(resources) = params.all("resource") else {
        return Ok(None);
    };
    let mut unique = Vec::new();
    for resource in resources {
        let uri = Url::parse(&resource).map_err(|_| {
            OAuthProviderError::InvalidTarget("resource must be an absolute URI".into())
        })?;
        if uri.fragment().is_some() {
            return Err(OAuthProviderError::InvalidTarget(
                "resource must not contain a fragment".into(),
            ));
        }
        if !unique.contains(&resource) {
            unique.push(resource);
        }
    }
    (!unique.is_empty())
        .then_some(unique)
        .ok_or_else(|| OAuthProviderError::InvalidTarget("resource must not be empty".into()))
        .map(Some)
}

fn requested_userinfo_claims(claims: Option<&Value>, config: &OAuthProviderConfig) -> Vec<String> {
    let supported = config
        .advertised_metadata
        .claims_supported
        .clone()
        .unwrap_or_else(|| {
            let mut values = Vec::new();
            if config.scopes.iter().any(|scope| scope == "profile") {
                values.extend(["name", "picture", "given_name", "family_name"].map(str::to_owned));
            }
            if config.scopes.iter().any(|scope| scope == "email") {
                values.extend(["email", "email_verified"].map(str::to_owned));
            }
            values
        });
    claims
        .and_then(|claims| claims.get("userinfo"))
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .keys()
                .filter(|name| supported.contains(name))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod grant_other_tests {
    use super::*;

    #[test]
    fn repeated_resources_and_literal_space_scope_splitting_match_upstream() {
        let mut parameters = Parameters::default();
        parameters.0.insert(
            "resource".into(),
            vec!["https://one.example".into(), "https://two.example".into()],
        );
        assert_eq!(resources(&parameters).unwrap().unwrap().len(), 2);
        assert_eq!(
            split_scopes("openid  email openid"),
            vec!["openid", "", "email", "openid"]
        );
    }
}
