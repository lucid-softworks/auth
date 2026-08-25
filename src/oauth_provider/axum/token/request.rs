#[derive(Debug)]
struct AuthenticatedClient {
    client: OAuthProviderClient,
    method: Option<String>,
    confirmation: Option<Value>,
}

struct PresentedClientCredentials {
    client_id: Option<String>,
    secret: Option<String>,
    assertion: Option<String>,
    method: String,
}

struct IssueRequest {
    grant_type: String,
    endpoint: String,
    client: OAuthProviderClient,
    user: Option<crate::AuthUser>,
    session_id: Option<Uuid>,
    scopes: Vec<String>,
    resources: Option<Vec<String>>,
    original_resources: Option<Vec<String>>,
    reference_id: Option<String>,
    authorization_code_id: Option<String>,
    nonce: Option<String>,
    auth_time: Option<i64>,
    requested_userinfo_claims: Vec<String>,
    verification_value: Option<Value>,
    previous_refresh: Option<OAuthProviderRefreshToken>,
    expected_dpop_jkt: Option<String>,
    extension_confirmation: Option<Value>,
    access_token_claims: Map<String, Value>,
    id_token_claims: Map<String, Value>,
    token_response: Map<String, Value>,
}

struct ResourcePolicy {
    audience: Option<Vec<String>>,
    scopes: Vec<String>,
    access_token_ttl: Option<u64>,
    refresh_token_ttl: Option<u64>,
    signing_algorithm: Option<String>,
    signing_key_id: Option<String>,
    custom_claims: Map<String, Value>,
    dpop_required: bool,
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_client(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
    endpoint: &str,
    grant_type: Option<&str>,
    credentials_required: bool,
) -> Result<AuthenticatedClient, OAuthProviderError> {
    let presented = presented_client_credentials(headers, params)?;
    if let Some((extension, method)) =
        assertion_extension(config, params.first("client_assertion_type"))
    {
        let authenticated = authenticate_extension(
            extension,
            &method,
            endpoint,
            headers,
            params,
            presented.client_id.as_deref(),
        )
        .await?;
        if presented
            .client_id
            .as_deref()
            .is_some_and(|value| value != authenticated.client_id)
        {
            return Err(OAuthProviderError::InvalidClient(
                "authenticated client_id mismatch".into(),
            ));
        }
        let client =
            load_token_client(config, store, headers, &authenticated.client_id, grant_type).await?;
        if client.token_endpoint_auth_method.as_deref() != Some(method.as_str()) {
            return Err(OAuthProviderError::InvalidClient(format!(
                "client requires {} authentication",
                client
                    .token_endpoint_auth_method
                    .as_deref()
                    .unwrap_or("client_secret_basic")
            )));
        }
        return Ok(AuthenticatedClient {
            client,
            method: Some(method),
            confirmation: authenticated.confirmation,
        });
    }
    let derived_client_id = match presented.assertion.as_deref() {
        Some(assertion) => client_assertion_client_id(assertion, presented.client_id.as_deref())?,
        None => presented
            .client_id
            .clone()
            .ok_or_else(|| OAuthProviderError::InvalidRequest("client_id is required".into()))?,
    };
    let client_id = derived_client_id.as_str();
    let client = load_token_client(config, store, headers, client_id, grant_type)
        .await
        .map_err(|error| client_auth_error(error, &presented.method))?;
    let confirmation = authenticate_configured_method(
        service,
        config,
        store,
        headers,
        params,
        endpoint,
        credentials_required,
        &client,
        &presented,
    )
    .await?;
    Ok(AuthenticatedClient {
        client,
        method: Some(presented.method),
        confirmation,
    })
}

fn assertion_extension<'a>(
    config: &'a OAuthProviderConfig,
    assertion_type: Option<&str>,
) -> Option<(&'a Arc<dyn OAuthProviderExtension>, String)> {
    let assertion_type = assertion_type?;
    config.extensions.iter().find_map(|extension| {
        extension
            .client_authentication_methods()
            .into_iter()
            .find(|strategy| {
                strategy
                    .assertion_types
                    .iter()
                    .any(|value| value == assertion_type)
            })
            .map(|strategy| (extension, strategy.method))
    })
}

fn presented_client_credentials(
    headers: &HeaderMap,
    params: &Parameters,
) -> Result<PresentedClientCredentials, OAuthProviderError> {
    let client_id = singleton_parameter(params, "client_id")?;
    let secret = singleton_parameter(params, "client_secret")?;
    let assertion = singleton_parameter(params, "client_assertion")?;
    let assertion_type = singleton_parameter(params, "client_assertion_type")?;
    let has_assertion = assertion.is_some() || assertion_type.is_some();
    if headers.contains_key(header::AUTHORIZATION) && (secret.is_some() || has_assertion) {
        return Err(OAuthProviderError::InvalidRequest(
            "A request must use only one client authentication method".into(),
        ));
    }
    if has_assertion && secret.is_some() {
        return Err(OAuthProviderError::InvalidRequest(
            "A request must use only one client authentication method".into(),
        ));
    }
    if assertion.is_some() != assertion_type.is_some() {
        return Err(OAuthProviderError::InvalidClient(
            "client_assertion and client_assertion_type must both be provided".into(),
        ));
    }
    let basic = basic_credentials(headers)?;
    let (client_id, secret, method) = if let Some((id, secret)) = basic {
        (Some(id), Some(secret), "client_secret_basic")
    } else if assertion.is_some() {
        (client_id.map(str::to_owned), None, "private_key_jwt")
    } else if let Some(secret) = secret {
        (
            client_id.map(str::to_owned),
            Some(secret.to_owned()),
            "client_secret_post",
        )
    } else {
        (client_id.map(str::to_owned), None, "none")
    };
    Ok(PresentedClientCredentials {
        client_id,
        secret,
        assertion: assertion.map(str::to_owned),
        method: method.into(),
    })
}

fn singleton_parameter<'a>(
    params: &'a Parameters,
    name: &str,
) -> Result<Option<&'a str>, OAuthProviderError> {
    let values = params
        .0
        .get(name)
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(OAuthProviderError::InvalidRequest(format!(
            "{name} must not be repeated"
        )));
    }
    Ok(values.first().map(|value| value.as_str()))
}

async fn load_token_client(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    client_id: &str,
    grant_type: Option<&str>,
) -> Result<OAuthProviderClient, OAuthProviderError> {
    let client = resolve_client(config, store, headers, client_id)
        .await?
        .ok_or_else(|| OAuthProviderError::InvalidClient("client not found".into()))?;
    if client.disabled
        || client
            .expires_at
            .is_some_and(|expires| expires <= Utc::now())
    {
        return Err(OAuthProviderError::InvalidClient(
            "client is disabled or expired".into(),
        ));
    }
    if let Some(grant_type) = grant_type
        && !client_allows_grant_type(&client, grant_type)
    {
        return Err(OAuthProviderError::UnauthorizedClient(format!(
            "client is not authorized to use the {grant_type} grant"
        )));
    }
    Ok(client)
}

fn client_allows_grant_type(client: &OAuthProviderClient, grant_type: &str) -> bool {
    let Some(allowed) = client
        .grant_types
        .as_deref()
        .filter(|grants| !grants.is_empty())
    else {
        return matches!(grant_type, "authorization_code" | "refresh_token");
    };
    (grant_type == "refresh_token"
        && allowed.iter().any(|grant| grant == "authorization_code"))
        || allowed.iter().any(|grant| grant == grant_type)
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_configured_method(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    params: &Parameters,
    endpoint: &str,
    credentials_required: bool,
    client: &OAuthProviderClient,
    presented: &PresentedClientCredentials,
) -> Result<Option<Value>, OAuthProviderError> {
    let configured = client
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let extension = config.extensions.iter().find(|extension| {
        extension
            .client_authentication_methods()
            .iter()
            .any(|method| method.method == configured)
    });
    if extension.is_none() && configured != presented.method {
        return Err(OAuthProviderError::InvalidClient(format!(
            "client requires {configured} authentication"
        )));
    }
    match configured {
        "none" if credentials_required => {
            return Err(OAuthProviderError::UnauthorizedInvalidClient(
                "missing required credentials".into(),
            ));
        }
        "none" => {}
        "private_key_jwt" => {
            let issuer = provider_issuer(service, headers, config);
            validate_client_assertion(
                ClientAssertionValidation {
                    service,
                    config,
                    store,
                    client,
                    endpoint,
                    provider_issuer: &issuer,
                },
                presented.assertion.as_deref().ok_or_else(|| {
                    OAuthProviderError::InvalidClient("missing required credentials".into())
                })?,
                params.first("client_assertion_type"),
            )
            .await?
        }
        method if extension.is_some() => {
            let authenticated = authenticate_extension(
                extension.expect("extension was selected"),
                method,
                endpoint,
                headers,
                params,
                Some(&client.client_id),
            )
            .await?;
            return Ok(authenticated.confirmation);
        }
        _ => {
            authenticate_client_secret(service, config, client, presented.secret.as_deref())
                .await
                .map_err(|error| client_auth_error(error, &presented.method))?;
        }
    }
    Ok(None)
}

fn client_auth_error(error: OAuthProviderError, method: &str) -> OAuthProviderError {
    match (error, method) {
        (OAuthProviderError::InvalidClient(description), "client_secret_basic") => {
            OAuthProviderError::BasicInvalidClient(description)
        }
        (error, _) => error,
    }
}

async fn authenticate_extension(
    extension: &Arc<dyn OAuthProviderExtension>,
    method: &str,
    endpoint: &str,
    headers: &HeaderMap,
    params: &Parameters,
    client_id: Option<&str>,
) -> Result<OAuthExtensionClientAuthentication, OAuthProviderError> {
    let input = OAuthExtensionClientAuthenticationInput {
        method: method.into(),
        endpoint: endpoint.into(),
        headers: header_context(headers),
        client_id: client_id.map(str::to_owned),
        parameters: params.0.clone(),
    };
    let authenticated: OAuthExtensionClientAuthentication = extension
        .authenticate_client(&input)
        .await
        .map_err(server)?
        .ok_or_else(|| OAuthProviderError::InvalidClient("client authentication failed".into()))?;
    if client_id.is_some_and(|expected| authenticated.client_id != expected) {
        return Err(OAuthProviderError::InvalidClient(
            "authenticated client_id mismatch".into(),
        ));
    }
    Ok(authenticated)
}

async fn authenticate_client_secret(
    service: &AuthService,
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    supplied: Option<&str>,
) -> Result<(), OAuthProviderError> {
    let supplied = supplied
        .ok_or_else(|| OAuthProviderError::InvalidClient("missing required credentials".into()))?;
    let stored = client
        .client_secret
        .as_deref()
        .ok_or_else(|| OAuthProviderError::InvalidClient("client has no secret".into()))?;
    if verify_client_secret(service, config, supplied, stored)
        .await
        .map_err(server)?
    {
        Ok(())
    } else {
        Err(OAuthProviderError::InvalidClient(
            "invalid client_secret".into(),
        ))
    }
}

fn header_context(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}
