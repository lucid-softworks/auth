async fn revoke_access(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token: &str,
    client_id: &str,
) -> Result<bool, OAuthProviderError> {
    match validate_access_token(service, config, store, headers, token, None).await {
        Ok(validation) if validation.payload.get("active") == Some(&Value::Bool(true)) => {
            if validation.opaque.is_none() {
                return Err(OAuthProviderError::UnsupportedTokenType(
                    "JWT access tokens cannot be revoked".into(),
                ));
            }
            let access = validation.opaque.expect("checked opaque token");
            if access.client_id != client_id {
                return Ok(false);
            }
            store
                .delete_oauth_access_token(access.id)
                .await
                .map_err(server)?;
            Ok(true)
        }
        Ok(_) | Err(OAuthProviderError::InvalidToken(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn revoke_refresh(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    token: &str,
    client_id: &str,
) -> Result<bool, OAuthProviderError> {
    let decoded = decode_refresh_token(config, token).await?;
    let stored = store_token(config, &decoded, OAuthStoredTokenType::RefreshToken)
        .await
        .map_err(server)?;
    let Some(refresh) = store
        .find_oauth_refresh_token(&stored)
        .await
        .map_err(server)?
    else {
        return Ok(false);
    };
    if refresh.client_id != client_id {
        return Ok(false);
    }
    if refresh.revoked.is_some() {
        store
            .revoke_oauth_refresh_family(client_id, &refresh.user_id)
            .await
            .map_err(server)?;
        return Ok(true);
    }
    store
        .revoke_oauth_refresh_token(refresh.id, Utc::now())
        .await
        .map_err(server)
}

fn userinfo_claims(
    user: &crate::AuthUser,
    scopes: &[String],
    requested: &[String],
) -> Map<String, Value> {
    let includes = |claim: &str, scope: &str| {
        scopes.iter().any(|value| value == scope) || requested.iter().any(|value| value == claim)
    };
    let mut claims = Map::from_iter([("sub".into(), Value::String(user.id.to_string()))]);
    if includes("name", "profile") {
        claims.insert("name".into(), Value::String(user.name.clone()));
    }
    if includes("picture", "profile")
        && let Some(image) = &user.image
    {
        claims.insert("picture".into(), Value::String(image.clone()));
    }
    let parts = user
        .name
        .split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        if includes("given_name", "profile") {
            claims.insert(
                "given_name".into(),
                Value::String(parts[..parts.len() - 1].join(" ")),
            );
        }
        if includes("family_name", "profile") {
            claims.insert(
                "family_name".into(),
                Value::String(parts[parts.len() - 1].into()),
            );
        }
    }
    if includes("email", "email") {
        claims.insert("email".into(), Value::String(user.email.clone()));
    }
    if includes("email_verified", "email") {
        claims.insert("email_verified".into(), Value::Bool(user.email_verified));
    }
    claims
}

fn access_authorization(
    headers: &HeaderMap,
) -> Result<Option<(String, String)>, OAuthProviderError> {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let Some((scheme, token)) = value.split_once(char::is_whitespace) else {
        return Ok(Some(("Unknown".into(), value.into())));
    };
    let token = token.trim();
    match scheme.to_ascii_lowercase().as_str() {
        "bearer" => Ok(Some(("Bearer".into(), token.into()))),
        "dpop" => Ok(Some(("DPoP".into(), token.into()))),
        _ => Ok(Some(("Unknown".into(), value.into()))),
    }
}

fn normalized_token(token: Option<&str>) -> Result<&str, OAuthProviderError> {
    let token = token.ok_or_else(|| {
        OAuthProviderError::InvalidRequest("missing a required token for introspection".into())
    })?;
    let token = token
        .split_once(' ')
        .filter(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop")
        })
        .map_or(token, |(_, token)| token);
    if token.is_empty() {
        Err(OAuthProviderError::InvalidRequest(
            "missing a required token for introspection".into(),
        ))
    } else {
        Ok(token)
    }
}

fn recognized_hint(hint: Option<&str>) -> Option<&str> {
    hint.filter(|hint| matches!(*hint, "access_token" | "refresh_token"))
}

fn unverified_payload(token: &str) -> Option<Map<String, Value>> {
    let encoded = token.split('.').nth(1)?;
    serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(encoded).ok()?)
        .ok()?
        .as_object()
        .cloned()
}

fn audience_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

async fn provider_claims(
    config: &OAuthProviderConfig,
    target: OAuthClaimTarget,
    context: &OAuthCallbackContext,
    protocol: &Value,
) -> Result<Map<String, Value>, OAuthProviderError> {
    provider_claims_with_request(config, target, context, protocol, &Map::new()).await
}

async fn provider_claims_with_request(
    config: &OAuthProviderConfig,
    target: OAuthClaimTarget,
    context: &OAuthCallbackContext,
    protocol: &Value,
    per_request: &Map<String, Value>,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let mut claims = Map::new();
    for extension in &config.extensions {
        for (name, value) in extension
            .claims(target, context, protocol)
            .await
            .map_err(server)?
        {
            claims.entry(name).or_insert(value);
        }
    }
    claims.extend(per_request.clone());
    if let Some(provider) = &config.callbacks.claims {
        claims.extend(
            provider
                .claims(target, context, protocol)
                .await
                .map_err(server)?,
        );
    }
    Ok(claims)
}

fn strip_reserved_access_claims(claims: &mut Map<String, Value>) {
    for name in [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "jti",
        "client_id",
        "scope",
        "auth_time",
        "acr",
        "amr",
        "cnf",
    ] {
        claims.remove(name);
    }
}

fn server(error: AuthError) -> OAuthProviderError {
    tracing::error!(error = %error, "OAuth Provider operation failed");
    OAuthProviderError::ServerError("unexpected server error".into())
}

fn json_server(error: serde_json::Error) -> OAuthProviderError {
    tracing::error!(error = %error, "OAuth Provider JSON operation failed");
    OAuthProviderError::ServerError("unexpected server error".into())
}
