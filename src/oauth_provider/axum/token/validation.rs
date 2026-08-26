async fn validate_access_token(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token: &str,
    introspecting_client: Option<&str>,
) -> Result<AccessValidation, OAuthProviderError> {
    if token.split('.').count() == 3
        && !config.disable_jwt_plugin
        && let Some(validation) =
            validate_jwt_access(
                service,
                config,
                store,
                headers,
                token,
                introspecting_client,
            )
            .await?
    {
        return Ok(validation);
    }
    validate_opaque_access(service, config, store, headers, token, introspecting_client).await
}

async fn validate_jwt_access(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token: &str,
    introspecting_client: Option<&str>,
) -> Result<Option<AccessValidation>, OAuthProviderError> {
    let Some(unverified) = unverified_payload(token) else {
        return Ok(None);
    };
    let audience = audience_values(unverified.get("aud"));
    if audience.is_empty() {
        return Ok(None);
    }
    let issuer_value = provider_issuer(service, headers, config);
    let userinfo = format!("{}/oauth2/userinfo", issuer(service, headers));
    for resource in audience.iter().filter(|resource| *resource != &userinfo) {
        if store
            .find_oauth_resource(resource)
            .await
            .map_err(server)?
            .is_none()
        {
            return Ok(None);
        }
    }
    let jwt = service
        .jwt()
        .ok_or_else(|| OAuthProviderError::ServerError("JWT plugin is required".into()))?;
    let Some(mut payload) = jwt
        .verify_jwt_for_audiences(
            &jwt_context("POST", "/oauth2/introspect", headers),
            token,
            &issuer_value,
            &audience,
        )
        .await
        .map_err(server)?
    else {
        return Ok(None);
    };
    let Some(issuing_id) = jwt_issuing_client(&payload) else { return Ok(None); };
    let parties = JwtAccessParties {
        introspecting_client,
        issuing_id: &issuing_id,
        audience: &audience,
        userinfo: &userinfo,
    };
    if !jwt_access_is_active(
        service,
        config,
        store,
        headers,
        &payload,
        parties,
    )
    .await?
    {
        return Ok(Some(inactive_access()));
    }
    payload.insert("active".into(), Value::Bool(true));
    payload.insert("client_id".into(), Value::String(issuing_id));
    let token_type = if payload.get("cnf").and_then(|value| value.get("jkt")).is_some() { "DPoP" } else { "Bearer" };
    payload.insert("token_type".into(), Value::String(token_type.into()));
    Ok(Some(AccessValidation { payload, requested_claims: Vec::new(), opaque: None }))
}

fn jwt_issuing_client(payload: &Map<String, Value>) -> Option<String> {
    payload
        .get("azp")
        .and_then(Value::as_str)
        .or_else(|| payload.get("client_id").and_then(Value::as_str))
        .map(str::to_owned)
}

struct JwtAccessParties<'a> {
    introspecting_client: Option<&'a str>,
    issuing_id: &'a str,
    audience: &'a [String],
    userinfo: &'a str,
}

async fn jwt_access_is_active(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    payload: &Map<String, Value>,
    parties: JwtAccessParties<'_>,
) -> Result<bool, OAuthProviderError> {
    let Some(client) = resolve_client(config, store, headers, parties.issuing_id).await? else {
        return Ok(false);
    };
    if client.disabled
        || !introspection_authorized(
            store,
            parties.introspecting_client,
            parties.issuing_id,
            parties.audience,
            parties.userinfo,
        )
        .await?
    {
        return Ok(false);
    }
    if let Some(session_id) = payload
        .get("sid")
        .and_then(Value::as_str)
        && service
            .oauth_provider_session_by_id(session_id)
            .await
            .map_err(server)?
            .is_none()
    {
        return Ok(false);
    }
    Ok(true)
}

fn inactive_access() -> AccessValidation {
    AccessValidation {
        payload: Map::from_iter([("active".into(), Value::Bool(false))]),
        requested_claims: Vec::new(),
        opaque: None,
    }
}

async fn introspection_authorized(
    store: &dyn OAuthProviderStore,
    caller: Option<&str>,
    issuer_client: &str,
    audiences: &[String],
    userinfo: &str,
) -> Result<bool, OAuthProviderError> {
    let Some(caller) = caller else {
        return Ok(true);
    };
    if caller == issuer_client {
        return Ok(true);
    }
    let resources = audiences
        .iter()
        .filter(|audience| audience.as_str() != userinfo)
        .collect::<Vec<_>>();
    if resources.is_empty() {
        return Ok(false);
    }
    let linked = store
        .list_oauth_client_resources(caller)
        .await
        .map_err(server)?
        .into_iter()
        .map(|link| link.resource_id)
        .collect::<BTreeSet<_>>();
    Ok(resources
        .iter()
        .any(|resource| linked.contains(resource.as_str())))
}

async fn validate_refresh_for_introspection(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token: &str,
    client_id: &str,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let decoded = decode_refresh_token(config, token).await?;
    let stored = store_token(config, &decoded, OAuthStoredTokenType::RefreshToken)
        .await
        .map_err(server)?;
    let refresh = store
        .find_oauth_refresh_token(&stored)
        .await
        .map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidToken("token not found".into()))?;
    if refresh.client_id != client_id
        || refresh.expires_at <= Utc::now()
        || refresh.revoked.is_some()
    {
        return Ok(Map::from_iter([("active".into(), Value::Bool(false))]));
    }
    let mut payload = Map::from_iter([
        ("active".into(), Value::Bool(true)),
        ("client_id".into(), Value::String(client_id.into())),
        (
            "iss".into(),
            Value::String(provider_issuer(service, headers, config)),
        ),
        ("exp".into(), Value::from(refresh.expires_at.timestamp())),
        ("iat".into(), Value::from(refresh.created_at.timestamp())),
        ("scope".into(), Value::String(refresh.scopes.join(" "))),
        (
            "token_type".into(),
            Value::String(
                if refresh
                    .confirmation
                    .as_ref()
                    .and_then(|value| value.get("jkt"))
                    .is_some()
                {
                    "DPoP"
                } else {
                    "Bearer"
                }
                .into(),
            ),
        ),
    ]);
    if service
        .auth_user_by_id(&refresh.user_id)
        .await
        .map_err(server)?
        .is_some()
    {
        payload.insert("sub".into(), Value::String(refresh.user_id.to_string()));
    }
    if let Some(session_id) = refresh.session_id.as_deref()
        && service
            .oauth_provider_session_by_id(session_id)
            .await
            .map_err(server)?
            .is_some()
    {
        payload.insert("sid".into(), Value::String(session_id.to_string()));
    }
    if let Some(confirmation) = refresh.confirmation {
        payload.insert("cnf".into(), confirmation);
    }
    Ok(payload)
}
