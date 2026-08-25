struct IssuedAccess {
    token: String,
    row: Option<OAuthProviderAccessToken>,
}

struct IssuedRefresh {
    plain: String,
    row: OAuthProviderRefreshToken,
}

struct TokenIssueContext<'a> {
    service: &'a AuthService,
    config: &'a OAuthProviderConfig,
    store: &'a dyn OAuthProviderStore,
    headers: &'a HeaderMap,
}

async fn issue_tokens(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    request: IssueRequest,
) -> Result<Value, OAuthProviderError> {
    let context = TokenIssueContext {
        service,
        config,
        store,
        headers,
    };
    let now = Utc::now();
    let policy = resolve_resource_policy(
        service, config, store, &request.client, &request.scopes,
        request.resources.as_deref(), headers,
    ).await?;
    let (access_expires_at, refresh_expires_at) =
        token_expirations(config, &request, &policy, now.timestamp())?;
    let proof = dpop_for_token_endpoint(
        config, store, &request.client, &policy,
        request.expected_dpop_jkt.as_deref(), headers,
        &request.endpoint,
    ).await?;
    let confirmation = proof
        .map(|jkt| json!({ "jkt": jkt }))
        .or_else(|| request.extension_confirmation.clone());
    let dpop = confirmation
        .as_ref()
        .and_then(|value| value.get("jkt"))
        .is_some();
    let replay_fingerprint = rotation_request_fingerprint(
        &request.client.client_id,
        &policy.scopes,
        request.resources.as_deref(),
        confirmation.as_ref(),
    );
    let refresh = new_refresh(
        config,
        &request,
        &policy,
        confirmation.clone(),
        refresh_expires_at,
        now,
    )
    .await?;
    let access = new_access(
        &context, &request, &policy, confirmation.clone(),
        refresh.as_ref().map(|value| value.row.id), access_expires_at, now,
    ).await?;
    if let Some(replayed) = persist_issuance(
        &context, &request, &access, refresh.as_ref(), &replay_fingerprint, now,
    ).await? {
        return Ok(replayed);
    }
    let id_token = if request.user.is_some() && policy.scopes.iter().any(|scope| scope == "openid") {
        sign_id_token(service, config, headers, &request, &access.token, now.timestamp()).await?
    } else {
        None
    };
    let response = token_response(
        service, config, headers, &request, &policy, &access.token,
        refresh.as_ref(), id_token, dpop, access_expires_at, now.timestamp(),
    ).await?;
    store_rotation_replay(service, config, store, request.previous_refresh.as_ref(), &replay_fingerprint, &response).await?;
    Ok(response)
}

fn token_expirations(
    config: &OAuthProviderConfig,
    request: &IssueRequest,
    policy: &ResourcePolicy,
    now: i64,
) -> Result<(i64, i64), OAuthProviderError> {
    let default_access_ttl = if request.user.is_some() {
        config.access_token_expires_in
    } else {
        config.m2m_access_token_expires_in
    };
    let default_access = add_ttl(now, default_access_ttl)?;
    let mut scope_access = default_access;
    for scope in &request.scopes {
        let expires_at = match config.scope_expirations.get(scope) {
            Some(configured) => expiration::expiration_timestamp(configured, now)
                .map_err(OAuthProviderError::ServerError)?,
            None => default_access,
        };
        scope_access = scope_access.min(expires_at);
    }
    let access = match policy.access_token_ttl {
        Some(ttl) => scope_access.min(add_ttl(now, ttl)?),
        None => scope_access,
    };
    let refresh_ttl = policy.refresh_token_ttl.map_or(config.refresh_token_expires_in, |ttl| {
        ttl.min(config.refresh_token_expires_in)
    });
    Ok((access, add_ttl(now, refresh_ttl)?))
}

fn add_ttl(now: i64, ttl: u64) -> Result<i64, OAuthProviderError> {
    let ttl = i64::try_from(ttl)
        .map_err(|_| OAuthProviderError::ServerError("token expiration is out of range".into()))?;
    now.checked_add(ttl)
        .ok_or_else(|| OAuthProviderError::ServerError("token expiration is out of range".into()))
}

async fn new_refresh(
    config: &OAuthProviderConfig,
    request: &IssueRequest,
    policy: &ResourcePolicy,
    confirmation: Option<Value>,
    expires_at: i64,
    now: DateTime<Utc>,
) -> Result<Option<IssuedRefresh>, OAuthProviderError> {
    let offline = request.scopes.iter().any(|scope| scope == "offline_access")
        || request.previous_refresh.as_ref().is_some_and(|token| token.scopes.iter().any(|scope| scope == "offline_access"));
    if request.user.is_none()
        || !client_allows_grant_type(&request.client, "refresh_token")
        || !offline
    {
        return Ok(None);
    }
    let (plain, stored) = generate_refresh(config).await?;
    let user = request.user.as_ref().expect("refresh requires a user");
    let row = OAuthProviderRefreshToken {
        id: Uuid::new_v4(), token: stored, client_id: request.client.client_id.clone(),
        session_id: request.session_id, user_id: user.id, reference_id: request.reference_id.clone(),
        authorization_code_id: request.authorization_code_id.clone(),
        resources: request.previous_refresh.as_ref().and_then(|token| token.resources.clone())
            .or_else(|| request.original_resources.clone()).or_else(|| request.resources.clone()),
        requested_user_info_claims: (!request.requested_userinfo_claims.is_empty()).then_some(request.requested_userinfo_claims.clone()),
        expires_at: DateTime::from_timestamp(expires_at, 0)
            .ok_or_else(|| OAuthProviderError::ServerError("refresh-token expiration is out of range".into()))?,
        created_at: now, revoked: None,
        rotated_at: None, rotation_replay_response: None, rotation_replay_expires_at: None,
        auth_time: request.auth_time.and_then(|value| DateTime::from_timestamp(value, 0)),
        confirmation, scopes: policy.scopes.clone(),
    };
    Ok(Some(IssuedRefresh { plain, row }))
}

async fn new_access(
    context: &TokenIssueContext<'_>,
    request: &IssueRequest,
    policy: &ResourcePolicy,
    confirmation: Option<Value>,
    refresh_id: Option<Uuid>,
    expires_at: i64,
    now: DateTime<Utc>,
) -> Result<IssuedAccess, OAuthProviderError> {
    if policy.audience.is_some() && !context.config.disable_jwt_plugin {
        let token = sign_access_token(
            context,
            request,
            policy,
            confirmation,
            now.timestamp(),
            expires_at,
        ).await?;
        return Ok(IssuedAccess { token, row: None });
    }
    let (plain, stored) = generate_opaque(context.config).await?;
    let row = OAuthProviderAccessToken {
        id: Uuid::new_v4(), token: stored, client_id: request.client.client_id.clone(),
        session_id: request.session_id, user_id: request.user.as_ref().map(|user| user.id),
        reference_id: request.reference_id.clone(), authorization_code_id: request.authorization_code_id.clone(),
        resources: request.resources.clone(),
        requested_user_info_claims: (!request.requested_userinfo_claims.is_empty()).then_some(request.requested_userinfo_claims.clone()),
        refresh_id,
        expires_at: DateTime::from_timestamp(expires_at, 0)
            .ok_or_else(|| OAuthProviderError::ServerError("access-token expiration is out of range".into()))?,
        created_at: now,
        revoked: None, confirmation, scopes: policy.scopes.clone(),
    };
    Ok(IssuedAccess {
        token: apply_token_prefix(context.config, plain, OAuthStoredTokenType::AccessToken),
        row: Some(row),
    })
}

async fn persist_issuance(
    context: &TokenIssueContext<'_>,
    request: &IssueRequest,
    access: &IssuedAccess,
    refresh: Option<&IssuedRefresh>,
    fingerprint: &str,
    now: DateTime<Utc>,
) -> Result<Option<Value>, OAuthProviderError> {
    if let Some(previous) = &request.previous_refresh {
        let rotation = OAuthRefreshRotation {
            previous_refresh_id: previous.id, rotated_at: now,
            replay_expires_at: (context.config.refresh_token_reuse_interval > 0)
                .then_some(now + Duration::seconds(context.config.refresh_token_reuse_interval as i64)),
            next_refresh_token: refresh.map(|value| value.row.clone())
                .ok_or_else(|| OAuthProviderError::InvalidGrant("invalid refresh token".into()))?,
            access_token: access.row.clone(),
        };
        return handle_rotation_outcome(
            context.service,
            context.config,
            context.store,
            request,
            fingerprint,
            context.store
                .rotate_oauth_refresh_token(rotation)
                .await
                .map_err(server)?,
        )
        .await;
    }
    context.store.issue_oauth_tokens(OAuthTokenIssuance {
        access_token: access.row.clone(), refresh_token: refresh.map(|value| value.row.clone()),
    }).await.map_err(server)?;
    Ok(None)
}

async fn handle_rotation_outcome(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    request: &IssueRequest,
    fingerprint: &str,
    outcome: OAuthRefreshRotationOutcome,
) -> Result<Option<Value>, OAuthProviderError> {
    match outcome {
        OAuthRefreshRotationOutcome::Rotated(_) => Ok(None),
        OAuthRefreshRotationOutcome::AlreadyConsumed(token) => {
            if let Some(response) = replay_response(service, &token, fingerprint)? {
                return Ok(Some(response));
            }
            if config.refresh_token_reuse_interval > 0
                && token
                    .rotation_replay_expires_at
                    .is_some_and(|expires| expires >= Utc::now())
                && token.rotated_at == token.revoked
            {
                return Err(OAuthProviderError::InvalidGrant(
                    "invalid refresh token".into(),
                ));
            }
            store.revoke_oauth_refresh_family(&request.client.client_id, token.user_id).await.map_err(server)?;
            Err(OAuthProviderError::InvalidGrant("invalid refresh token".into()))
        }
        OAuthRefreshRotationOutcome::NotFound => Err(OAuthProviderError::InvalidGrant("invalid refresh token".into())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn token_response(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    request: &IssueRequest,
    policy: &ResourcePolicy,
    access_token: &str,
    refresh: Option<&IssuedRefresh>,
    id_token: Option<String>,
    dpop: bool,
    access_expires_at: i64,
    now: i64,
) -> Result<Value, OAuthProviderError> {
    let mut body = token_response_extensions(config, headers, request, policy).await?;
    body.extend(request.token_response.clone());
    for reserved in ["access_token", "token_type", "expires_in", "expires_at", "refresh_token", "scope", "id_token"] {
        body.remove(reserved);
    }
    body.insert("access_token".into(), Value::String(access_token.into()));
    body.insert("token_type".into(), Value::String(if dpop { "DPoP" } else { "Bearer" }.into()));
    body.insert("expires_in".into(), Value::from(access_expires_at - now));
    body.insert("expires_at".into(), Value::from(access_expires_at));
    body.insert("scope".into(), Value::String(policy.scopes.join(" ")));
    if let Some(refresh) = refresh {
        body.insert("refresh_token".into(), Value::String(encode_refresh_token(config, &refresh.plain, request.session_id).await?));
    }
    if let Some(id_token) = id_token {
        body.insert("id_token".into(), Value::String(id_token));
    }
    let _ = service;
    Ok(Value::Object(body))
}

async fn token_response_extensions(
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    request: &IssueRequest,
    policy: &ResourcePolicy,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let context = callback_context(headers, request.user.as_ref(), &policy.scopes);
    provider_claims(
        config,
        OAuthClaimTarget::TokenResponse,
        &context,
        &json!({
            "grantType": request.grant_type,
            "verificationValue": request.verification_value,
        }),
    )
    .await
}

async fn store_rotation_replay(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    previous: Option<&OAuthProviderRefreshToken>,
    fingerprint: &str,
    response: &Value,
) -> Result<(), OAuthProviderError> {
    let Some(previous) = previous.filter(|_| config.refresh_token_reuse_interval > 0) else {
        return Ok(());
    };
    let envelope = RotationReplayEnvelope { fingerprint: fingerprint.into(), response: response.clone() };
    let encoded = service.encrypt_oauth_provider_secret(
        serde_json::to_string(&envelope).map_err(json_server)?.as_bytes(),
    ).map_err(|_| OAuthProviderError::ServerError("failed to protect refresh replay response".into()))?;
    store.store_oauth_refresh_rotation_replay(previous.id, encoded).await.map_err(server)?;
    Ok(())
}
