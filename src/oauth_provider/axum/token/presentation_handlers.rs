struct AccessValidation {
    payload: Map<String, Value>,
    requested_claims: Vec<String>,
    opaque: Option<OAuthProviderAccessToken>,
}

async fn introspection_endpoint(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    request: Request,
) -> Response {
    let result = async {
        let (headers, _, params) = parameters(request).await?;
        let endpoint = format!("{}/oauth2/introspect", issuer(&service, &headers));
        let client = authenticate_client(
            &service,
            &config,
            store.as_ref(),
            &headers,
            &params,
            &endpoint,
            None,
            true,
        )
        .await?
        .client;
        let mut payload = introspect_token(&service, &config, store.as_ref(), &headers, &params, &client.client_id).await?;
        if payload.get("active") != Some(&Value::Bool(true)) {
            return Ok(json!({"active": false}));
        }
        pairwise_introspection_subject(
            &config,
            store.as_ref(),
            &headers,
            &client.client_id,
            &mut payload,
        )
        .await?;
        Ok(Value::Object(payload))
    }
    .await;
    match result {
        Ok(body) => no_store(Json(body).into_response()),
        Err(OAuthProviderError::InvalidToken(_)) => {
            no_store(Json(json!({"active": false})).into_response())
        }
        Err(error) => oauth_error(&error),
    }
}

async fn introspect_token(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
    client_id: &str,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let token = normalized_token(params.first("token"))?;
    match recognized_hint(params.first("token_type_hint")) {
        Some("access_token") => Ok(validate_access_token(service, config, store, headers, token, Some(client_id)).await?.payload),
        Some("refresh_token") => {
            validate_refresh_for_introspection(service, config, store, headers, token, client_id)
                .await
        }
        _ => match validate_access_token(service, config, store, headers, token, Some(client_id)).await {
            Ok(validation) => Ok(validation.payload),
            Err(_) => {
                validate_refresh_for_introspection(
                    service, config, store, headers, token, client_id,
                )
                .await
            }
        },
    }
}

async fn pairwise_introspection_subject(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    caller_id: &str,
    payload: &mut Map<String, Value>,
) -> Result<(), OAuthProviderError> {
    let Some(subject) = payload.get("sub").and_then(Value::as_str) else { return Ok(()); };
    let issuing_id = payload.get("client_id").and_then(Value::as_str).unwrap_or(caller_id);
    if let Some(issuing) = resolve_client(config, store, headers, issuing_id).await? {
        payload.insert("sub".into(), Value::String(subject_identifier(subject, &issuing, config)?));
    }
    Ok(())
}

async fn revocation_endpoint(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    request: Request,
) -> Response {
    let result = async {
        let (headers, _, params) = parameters(request).await?;
        let endpoint = format!("{}/oauth2/revoke", issuer(&service, &headers));
        let client = authenticate_client(
            &service,
            &config,
            store.as_ref(),
            &headers,
            &params,
            &endpoint,
            None,
            false,
        )
        .await?
        .client;
        let token = normalized_token(params.first("token"))?;
        let hint = recognized_hint(params.first("token_type_hint"));
        if hint != Some("refresh_token") {
            match revoke_access(
                &service,
                &config,
                store.as_ref(),
                &headers,
                token,
                &client.client_id,
            )
            .await
            {
                Ok(true) => return Ok(()),
                Err(error @ OAuthProviderError::UnsupportedTokenType(_)) => return Err(error),
                Err(error) if hint == Some("access_token") => return Err(error),
                _ => {}
            }
        }
        if hint != Some("access_token") {
            match revoke_refresh(&config, store.as_ref(), token, &client.client_id).await {
                Ok(_) => return Ok(()),
                Err(error) if hint == Some("refresh_token") => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => empty_no_store(),
        Err(error) => oauth_error(&error),
    }
}

async fn userinfo_get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    request: Request,
) -> Response {
    userinfo(service, config, store, request).await
}

async fn userinfo_post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    request: Request,
) -> Response {
    userinfo(service, config, store, request).await
}

async fn userinfo(
    service: Arc<AuthService>,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
    request: Request,
) -> Response {
    let result = async {
        let (headers, method, params) = parameters(request).await?;
        let (scheme, token) = userinfo_token(&headers, method == Method::POST, &params)?;
        let validation =
            validate_access_token(&service, &config, store.as_ref(), &headers, &token, None)
                .await?;
        if validation.payload.get("active") != Some(&Value::Bool(true)) {
            return Err(OAuthProviderError::InvalidToken(
                "Invalid access token".into(),
            ));
        }
        validate_userinfo_dpop(&service, &config, store.as_ref(), &headers, method.as_str(), &scheme, &token, &validation.payload).await?;
        userinfo_payload(&service, &config, store.as_ref(), &headers, validation).await
    }
    .await;
    match result {
        Ok(body) => no_store(Json(body).into_response()),
        Err(error) => userinfo_oauth_error(&error, &config),
    }
}

fn userinfo_oauth_error(error: &OAuthProviderError, config: &OAuthProviderConfig) -> Response {
    let userinfo_unauthorized = matches!(error, OAuthProviderError::InvalidDpopProof(_))
        || matches!(error, OAuthProviderError::InvalidRequest(message) if message == "access token not found");
    let normalized;
    let error = if matches!(error, OAuthProviderError::InvalidToken(_)) {
        normalized = OAuthProviderError::InvalidToken("Invalid access token".into());
        &normalized
    } else {
        error
    };
    let mut response = oauth_error(error);
    if matches!(error, OAuthProviderError::InvalidToken(_)) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "Bearer error=\"invalid_token\", error_description=\"Invalid access token\"",
            ),
        );
    }
    if !userinfo_unauthorized {
        return response;
    }
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    if let OAuthProviderError::InvalidDpopProof(description) = error {
        let algorithms = if config.dpop.signing_algorithms.is_empty() {
            DEFAULT_DPOP_ALGORITHMS.to_vec().join(" ")
        } else {
            config.dpop.signing_algorithms.join(" ")
        };
        let challenge = format!(
            "DPoP error=\"invalid_dpop_proof\", error_description=\"{}\", algs=\"{}\"",
            description.replace(['\\', '"'], ""),
            algorithms,
        );
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

#[cfg(test)]
mod userinfo_response_tests {
    use super::*;

    #[tokio::test]
    async fn userinfo_dpop_failures_are_unauthorized_with_dpop_challenge() {
        let config = OAuthProviderConfig::new("/login", "/consent");
        let response = userinfo_oauth_error(
            &OAuthProviderError::InvalidDpopProof("DPoP htu mismatch".into()),
            &config,
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.starts_with("DPoP error=\"invalid_dpop_proof\""));
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"], "invalid_dpop_proof");
    }

    #[test]
    fn userinfo_missing_token_is_unauthorized_without_a_challenge() {
        let response = userinfo_oauth_error(
            &OAuthProviderError::InvalidRequest("access token not found".into()),
            &OAuthProviderConfig::new("/login", "/consent"),
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }
}

fn userinfo_token(
    headers: &HeaderMap,
    allow_body: bool,
    params: &Parameters,
) -> Result<(String, String), OAuthProviderError> {
    let header_token = access_authorization(headers)?;
    let body_token = allow_body.then(|| params.first("access_token")).flatten();
    if header_token.is_some() && body_token.is_some() {
        return Err(OAuthProviderError::InvalidRequest("Multiple access token transport methods are not allowed".into()));
    }
    header_token.or_else(|| body_token.map(|value| ("Bearer".to_owned(), value.to_owned())))
        .ok_or_else(|| OAuthProviderError::InvalidRequest("access token not found".into()))
}

#[allow(clippy::too_many_arguments)]
async fn validate_userinfo_dpop(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    method: &str,
    scheme: &str,
    token: &str,
    payload: &Map<String, Value>,
) -> Result<(), OAuthProviderError> {
    let expected = payload.get("cnf").and_then(|value| value.get("jkt")).and_then(Value::as_str);
    let Some(expected) = expected else {
        return if scheme != "DPoP" {
            Ok(())
        } else {
            Err(OAuthProviderError::UnchallengedInvalidToken(
                "DPoP authorization requires a DPoP-bound access token".into(),
            ))
        };
    };
    if scheme != "DPoP" {
        return Err(OAuthProviderError::UnchallengedInvalidToken(
            "DPoP-bound access token requires the DPoP authorization scheme".into(),
        ));
    }
    let proof = headers.get("dpop").and_then(|value| value.to_str().ok())
        .ok_or_else(|| OAuthProviderError::InvalidDpopProof("DPoP proof header is required".into()))?;
    verify_dpop(config, store, proof, method, &format!("{}/oauth2/userinfo", issuer(service, headers)), Some(expected), Some(token)).await?;
    Ok(())
}

async fn userinfo_payload(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    validation: AccessValidation,
) -> Result<Value, OAuthProviderError> {
        let scopes = validation
            .payload
            .get("scope")
            .and_then(Value::as_str)
            .map(split_scopes)
            .unwrap_or_default();
        if !scopes.iter().any(|scope| scope == "openid") {
            return Err(OAuthProviderError::InvalidScope(
                "Missing required scope".into(),
            ));
        }
        let user_id = validation
            .payload
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| OAuthProviderError::InvalidRequest("user not found".into()))?;
        let user = service
            .auth_user_by_id(user_id)
            .await
            .map_err(server)?
            .ok_or_else(|| OAuthProviderError::InvalidRequest("user not found".into()))?;
        let client_id = validation
            .payload
            .get("client_id")
            .or_else(|| validation.payload.get("azp"))
            .and_then(Value::as_str);
        let client = match client_id {
            Some(id) => resolve_client(config, store, headers, id).await?,
            None => None,
        };
        let subject = match &client {
            Some(client) => subject_identifier(&user.id, client, config)?,
            None => user.id.to_string(),
        };
        let requested = validation.requested_claims;
        let mut claims = userinfo_claims(&user, &scopes, &requested);
        claims.extend(provider_claims(config, OAuthClaimTarget::UserInfo,
            &callback_context(headers, Some(&user), &scopes),
            &Value::Object(validation.payload.clone())).await?);
        claims.insert("sub".into(), Value::String(subject));
    Ok(Value::Object(claims))
}
