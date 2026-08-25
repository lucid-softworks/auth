async fn token_endpoint(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    request: Request,
) -> Response {
    let result = async {
        let (headers, _, params) = parameters(request).await?;
        let grant_type = params
            .first("grant_type")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| OAuthProviderError::InvalidRequest("grant_type is required".into()))?;
        if !supports_grant(&config, grant_type)
        {
            return Err(OAuthProviderError::UnsupportedGrantType(format!(
                "unsupported grant_type {grant_type}"
            )));
        }
        match grant_type {
            "authorization_code" => {
                authorization_code_grant(&service, &config, store.as_ref(), &headers, &params).await
            }
            "client_credentials" => {
                client_credentials_grant(&service, &config, store.as_ref(), &headers, &params).await
            }
            "refresh_token" => {
                refresh_token_grant(&service, &config, store.as_ref(), &headers, &params).await
            }
            _ => extension_grant(
                service.clone(), config.clone(), store.clone(), &headers, &params, grant_type,
            ).await,
        }
    }
    .await;
    match result {
        Ok(body) => no_store(Json(body).into_response()),
        Err(error) => oauth_error(&error),
    }
}

fn supports_grant(config: &OAuthProviderConfig, grant_type: &str) -> bool {
    config.grant_types.iter().any(|supported| supported == grant_type)
        || config.extensions.iter().any(|extension| extension.grant_types().iter().any(|supported| supported == grant_type))
}

async fn extension_grant(
    service: Arc<AuthService>,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
    headers: &HeaderMap,
    params: &Parameters,
    grant_type: &str,
) -> Result<Value, OAuthProviderError> {
    let extension = config.extensions.iter().find(|extension| extension.grant_types().iter().any(|value| value == grant_type))
        .ok_or_else(|| OAuthProviderError::UnsupportedGrantType(format!("unsupported grant_type {grant_type}")))?;
    let endpoint = format!("{}/oauth2/token", issuer(&service, headers));
    let provider = super::provider_api::OAuthProviderApi::new(
        service,
        config.clone(),
        store,
        super::provider_api::OAuthProviderApiRequest {
            endpoint: endpoint.clone(),
            headers: header_context(headers),
            parameters: params.0.clone(),
        },
        Some(grant_type.into()),
    )?;
    let input = OAuthExtensionGrantInput {
        grant_type: grant_type.into(), endpoint, headers: header_context(headers),
        parameters: params.0.clone(), provider,
    };
    extension.token_grant(&input).await
}

async fn authorization_code_grant(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
) -> Result<Value, OAuthProviderError> {
    let client_id = presented_client_id(headers, params)?
        .ok_or_else(|| OAuthProviderError::InvalidRequest("client_id is required".into()))?;
    let (code_id, payload) = consume_authorization_code(service, config, store, params).await?;
    validate_authorization_binding(&payload, &client_id, params)?;
    let requested_resources = resources(params)?;
    let authorized_resources = authorized_code_resources(&payload, requested_resources.as_deref())?;
    let endpoint = format!("{}/oauth2/token", issuer(service, headers));
    let authenticated = authenticate_client(
        service,
        config,
        store,
        headers,
        params,
        &endpoint,
        Some("authorization_code"),
        false,
    )
    .await?;
    let scopes =
        split_scopes(
            payload.query.scope.as_deref().ok_or_else(|| {
                OAuthProviderError::InvalidScope("verification scope unset".into())
            })?,
        );
    validate_client_scopes(config, &authenticated.client, &scopes)?;
    validate_code_pkce(&authenticated.client, &payload, &scopes, params)?;
    let (user, session_id) = code_principal(service, &payload).await?;
    let effective_resources = requested_resources
        .or_else(|| (!authorized_resources.is_empty()).then_some(authorized_resources.clone()));
    let verification_value = serde_json::to_value(&payload).ok();
    issue_tokens(
        service,
        config,
        store,
        headers,
        IssueRequest {
            grant_type: "authorization_code".into(),
            endpoint,
            client: authenticated.client,
            user: Some(user),
            session_id: Some(session_id),
            scopes,
            resources: effective_resources,
            original_resources: (!authorized_resources.is_empty()).then_some(authorized_resources),
            reference_id: payload.reference_id,
            authorization_code_id: Some(code_id),
            nonce: payload.query.nonce,
            auth_time: payload.auth_time.map(normalize_auth_time),
            requested_userinfo_claims: requested_userinfo_claims(
                payload.query.claims.as_ref(),
                config,
            ),
            verification_value,
            previous_refresh: None,
            expected_dpop_jkt: payload.query.dpop_jkt,
            extension_confirmation: authenticated.confirmation,
            access_token_claims: Map::new(),
            id_token_claims: Map::new(),
            token_response: Map::new(),
        },
    )
    .await
}

async fn consume_authorization_code(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    params: &Parameters,
) -> Result<(String, OAuthAuthorizationCodePayload), OAuthProviderError> {
    let code = params
        .first("code")
        .ok_or_else(|| OAuthProviderError::InvalidRequest("code is required".into()))?;
    let code_id = store_token(config, code, OAuthStoredTokenType::AuthorizationCode)
        .await
        .map_err(server)?;
    let verification = service
        .consume_verification_value(AUTHORIZATION_CODE_PURPOSE, &code_id, Utc::now())
        .await
        .map_err(server)?;
    let Some(verification) = verification else {
        let _ = store.revoke_oauth_tokens_for_authorization_code(&code_id).await;
        return Err(OAuthProviderError::InvalidGrant("invalid code".into()));
    };
    let payload = serde_json::from_value(verification.payload)
        .map_err(|_| OAuthProviderError::InvalidGrant("malformed verification value".into()))?;
    Ok((code_id, payload))
}

fn validate_authorization_binding(
    payload: &OAuthAuthorizationCodePayload,
    client_id: &str,
    params: &Parameters,
) -> Result<(), OAuthProviderError> {
    if payload.kind != "authorization_code" || payload.query.client_id.as_deref() != Some(client_id) {
        return Err(OAuthProviderError::InvalidGrant("invalid client_id".into()));
    }
    match (payload.query.redirect_uri.as_deref(), params.first("redirect_uri")) {
        (Some(_), None) => Err(OAuthProviderError::InvalidRequest("redirect_uri is required".into())),
        (Some(bound), Some(presented)) if bound != presented => Err(OAuthProviderError::InvalidGrant("redirect_uri mismatch".into())),
        (None, Some(_)) => Err(OAuthProviderError::InvalidGrant("redirect_uri mismatch".into())),
        _ => Ok(()),
    }
}

fn authorized_code_resources(
    payload: &OAuthAuthorizationCodePayload,
    requested: Option<&[String]>,
) -> Result<Vec<String>, OAuthProviderError> {
    let authorized = if payload.resource.is_empty() { payload.query.resource.clone() } else { payload.resource.clone() };
    if requested.is_some_and(|values| values.iter().any(|value| !authorized.contains(value))) {
        return Err(OAuthProviderError::InvalidTarget("requested resource not authorized".into()));
    }
    Ok(authorized)
}

fn validate_code_pkce(
    client: &OAuthProviderClient,
    payload: &OAuthAuthorizationCodePayload,
    scopes: &[String],
    params: &Parameters,
) -> Result<(), OAuthProviderError> {
    let confidential = client.token_endpoint_auth_method.as_deref().unwrap_or("client_secret_basic") != "none";
    let openid_nonce = scopes.iter().any(|scope| scope == "openid")
        && payload.query.nonce.as_deref().is_some_and(|nonce| !nonce.is_empty());
    let required = !confidential || if scopes.iter().any(|scope| scope == "offline_access") {
        !openid_nonce
    } else {
        client.require_pkce.unwrap_or(true)
    };
    let verifier = params.first("code_verifier");
    let challenge = payload.query.code_challenge.as_deref();
    if required && verifier.is_none() {
        return Err(OAuthProviderError::InvalidRequest("PKCE is required for this client".into()));
    }
    match (challenge, verifier) {
        (Some(_), None) => Err(OAuthProviderError::UnauthorizedInvalidRequest("code_verifier required because PKCE was used in authorization".into())),
        (None, Some(_)) => Err(OAuthProviderError::UnauthorizedInvalidRequest("code_verifier provided but PKCE was not used in authorization".into())),
        (Some(challenge), Some(verifier)) if payload.query.code_challenge_method.as_deref() != Some("S256") || !verify_s256_pkce(verifier, challenge) => Err(OAuthProviderError::UnauthorizedInvalidRequest("code verification failed".into())),
        _ => Ok(()),
    }
}

async fn code_principal(
    service: &AuthService,
    payload: &OAuthAuthorizationCodePayload,
) -> Result<(crate::AuthUser, Uuid), OAuthProviderError> {
    let user = service.auth_user_by_id(payload.user_id).await.map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidUser("missing user, user may have been deleted".into()))?;
    let session = service.oauth_provider_session_by_id(payload.session_id).await.map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidRequest("session no longer exists".into()))?;
    Ok((user, session.id))
}

fn normalize_auth_time(value: i64) -> i64 {
    if value > 10_000_000_000 { value / 1_000 } else { value }
}
