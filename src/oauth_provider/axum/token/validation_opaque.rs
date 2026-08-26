async fn validate_opaque_access(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token: &str,
    introspecting_client: Option<&str>,
) -> Result<AccessValidation, OAuthProviderError> {
    let access = find_opaque_access(config, store, token).await?;
    let resources = access.resources.clone().unwrap_or_default();
    let userinfo = format!("{}/oauth2/userinfo", issuer(service, headers));
    if !opaque_access_is_active(
        service, config, store, headers, &access, introspecting_client, &resources, &userinfo,
    )
    .await?
    {
        return Ok(inactive_access());
    }
    let payload = opaque_access_payload(
        service, config, store, headers, &access, resources, &userinfo,
    )
    .await?;
    Ok(AccessValidation {
        requested_claims: access.requested_user_info_claims.clone().unwrap_or_default(),
        opaque: Some(access),
        payload,
    })
}

async fn find_opaque_access(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    token: &str,
) -> Result<OAuthProviderAccessToken, OAuthProviderError> {
    let stripped = strip_token_prefix(config, token, OAuthStoredTokenType::AccessToken)
        .ok_or_else(|| OAuthProviderError::InvalidToken("opaque access token not found".into()))?;
    let stored = store_token(config, stripped, OAuthStoredTokenType::AccessToken)
        .await
        .map_err(server)?;
    store
        .find_oauth_access_token(&stored)
        .await
        .map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidToken("opaque access token not found".into()))
}

#[allow(clippy::too_many_arguments)]
async fn opaque_access_is_active(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    access: &OAuthProviderAccessToken,
    caller: Option<&str>,
    resources: &[String],
    userinfo: &str,
) -> Result<bool, OAuthProviderError> {
    if access.expires_at <= Utc::now() || access.revoked.is_some() {
        return Ok(false);
    }
    let Some(client) = resolve_client(config, store, headers, &access.client_id).await? else {
        return Ok(false);
    };
    if client.disabled {
        return Ok(false);
    }
    if let Some(session_id) = access.session_id.as_deref()
        && service
            .oauth_provider_session_by_id(session_id)
            .await
            .map_err(server)?
            .is_none()
    {
        return Ok(false);
    }
    for resource in resources.iter().filter(|resource| *resource != userinfo) {
        if store
            .find_oauth_resource(resource)
            .await
            .map_err(server)?
            .is_none()
        {
            return Ok(false);
        }
    }
    introspection_authorized(store, caller, &access.client_id, resources, userinfo).await
}

async fn opaque_access_payload(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    access: &OAuthProviderAccessToken,
    resources: Vec<String>,
    userinfo: &str,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let mut audience = resources.clone();
    if !audience.is_empty()
        && access.scopes.iter().any(|scope| scope == "openid")
        && !audience.iter().any(|value| value == userinfo)
    {
        audience.push(userinfo.to_owned());
    }
    let mut payload = opaque_base_payload(service, config, headers, access, &audience);
    let user = match access.user_id.as_deref() {
        Some(id) => service.auth_user_by_id(id).await.map_err(server)?,
        None => None,
    };
    let mut enriched = provider_claims(
        config,
        OAuthClaimTarget::AccessToken,
        &callback_context(headers, user.as_ref(), &access.scopes),
        &json!({"clientId": access.client_id, "resources": access.resources, "referenceId": access.reference_id}),
    )
    .await?;
    enriched.extend(opaque_resource_claims(store, &resources, userinfo).await?);
    strip_reserved_access_claims(&mut enriched);
    for (name, value) in enriched {
        payload.entry(name).or_insert(value);
    }
    Ok(payload)
}

fn opaque_base_payload(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    access: &OAuthProviderAccessToken,
    audience: &[String],
) -> Map<String, Value> {
    let token_type = if access
        .confirmation
        .as_ref()
        .and_then(|value| value.get("jkt"))
        .is_some()
    {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut payload = Map::from_iter([
        ("active".into(), Value::Bool(true)),
        ("iss".into(), Value::String(provider_issuer(service, headers, config))),
        ("client_id".into(), Value::String(access.client_id.clone())),
        ("azp".into(), Value::String(access.client_id.clone())),
        ("exp".into(), Value::from(access.expires_at.timestamp())),
        ("iat".into(), Value::from(access.created_at.timestamp())),
        ("scope".into(), Value::String(access.scopes.join(" "))),
        ("token_type".into(), Value::String(token_type.into())),
    ]);
    if !audience.is_empty() {
        payload.insert("aud".into(), audience_value(audience));
    }
    if let Some(user_id) = access.user_id.as_ref() {
        payload.insert("sub".into(), Value::String(user_id.clone()));
    }
    if let Some(session_id) = access.session_id.as_ref() {
        payload.insert("sid".into(), Value::String(session_id.clone()));
    }
    if let Some(confirmation) = &access.confirmation {
        payload.insert("cnf".into(), confirmation.clone());
    }
    payload
}

async fn opaque_resource_claims(
    store: &dyn OAuthProviderStore,
    resources: &[String],
    userinfo: &str,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let mut claims = Map::new();
    for identifier in resources.iter().filter(|value| value.as_str() != userinfo) {
        let Some(resource) = store.find_oauth_resource(identifier).await.map_err(server)? else {
            continue;
        };
        if let Some(Value::Object(custom)) = resource.custom_claims {
            claims.extend(custom);
        }
    }
    Ok(claims)
}
