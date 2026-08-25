async fn sign_access_token(
    context: &TokenIssueContext<'_>,
    request: &IssueRequest,
    policy: &ResourcePolicy,
    confirmation: Option<Value>,
    iat: i64,
    exp: i64,
) -> Result<String, OAuthProviderError> {
    let user_id = request.user.as_ref().map(|user| user.id.to_string());
    let mut claims = provider_claims_with_request(context.config, OAuthClaimTarget::AccessToken,
        &callback_context(context.headers, request.user.as_ref(), &policy.scopes),
        &json!({"clientId": request.client.client_id, "resources": request.resources, "referenceId": request.reference_id, "grantType": request.grant_type}),
        &request.access_token_claims).await?;
    claims.extend(policy.custom_claims.clone());
    strip_reserved_access_claims(&mut claims);
    let subject = user_id.unwrap_or_else(|| request.client.client_id.clone());
    claims.extend(Map::from_iter([
        ("sub".into(), Value::String(subject)),
        (
            "aud".into(),
            audience_value(policy.audience.as_deref().unwrap_or_default()),
        ),
        (
            "client_id".into(),
            Value::String(request.client.client_id.clone()),
        ),
        (
            "azp".into(),
            Value::String(request.client.client_id.clone()),
        ),
        ("scope".into(), Value::String(policy.scopes.join(" "))),
        (
            "iss".into(),
            Value::String(provider_issuer(context.service, context.headers, context.config)),
        ),
        ("iat".into(), Value::from(iat)),
        ("exp".into(), Value::from(exp)),
        ("jti".into(), Value::String(random_letters(32))),
    ]));
    if let Some(session_id) = request.session_id {
        claims.insert("sid".into(), Value::String(session_id.to_string()));
    }
    if let Some(confirmation) = confirmation {
        claims.insert("cnf".into(), confirmation);
    }
    let jwt = context.service.jwt().ok_or_else(|| {
        OAuthProviderError::ServerError("JWT plugin is required for resource access tokens".into())
    })?;
    jwt.sign_jwt(
        &jwt_context("POST", "/oauth2/token", context.headers),
        claims,
        Some(JwtProtectedHeader {
            typ: Some("at+jwt".into()),
            cty: None,
        }),
        JwtSigningOverrides {
            signing_key_id: policy.signing_key_id.clone(),
            signing_algorithm: policy.signing_algorithm.as_deref().and_then(jwk_algorithm),
        },
    )
    .await
    .map_err(server)
}

async fn sign_id_token(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    request: &IssueRequest,
    access_token: &str,
    iat: i64,
) -> Result<Option<String>, OAuthProviderError> {
    if request.user.is_none() {
        return Ok(None);
    }
    let algorithm = if config.disable_jwt_plugin {
        "HS256"
    } else {
        service
            .jwt_plugin()
            .and_then(|plugin| plugin.config().jwks.key_pair_config)
            .unwrap_or_default()
            .name()
    };
    let claims = id_token_claims(service, config, headers, request, access_token, iat, algorithm).await?;
    sign_id_token_claims(service, config, headers, request, claims).await
}

async fn id_token_claims(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    request: &IssueRequest,
    access_token: &str,
    iat: i64,
    algorithm: &str,
) -> Result<Map<String, Value>, OAuthProviderError> {
    let user = request.user.as_ref().expect("ID token requires a user");
    let mut claims = provider_claims_with_request(config, OAuthClaimTarget::IdToken,
        &callback_context(headers, Some(user), &request.scopes),
        &json!({"clientId": request.client.client_id, "metadata": request.client.metadata, "grantType": request.grant_type}),
        &request.id_token_claims).await?;
    for reserved in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "sid", "at_hash", "c_hash", "s_hash", "auth_time", "acr", "amr", "azp"] {
        claims.remove(reserved);
    }
    claims.extend(Map::from_iter([
        (
            "iss".into(),
            Value::String(provider_issuer(service, headers, config)),
        ),
        ("sub".into(), Value::String(subject_identifier(user.id, &request.client, config)?)),
        (
            "aud".into(),
            Value::String(request.client.client_id.clone()),
        ),
        ("iat".into(), Value::from(iat)),
        (
            "exp".into(),
            Value::from(iat + config.id_token_expires_in as i64),
        ),
        ("acr".into(), Value::String("0".into())),
        (
            "at_hash".into(),
            Value::String(oidc_hash(access_token, algorithm)),
        ),
    ]));
    if let Some(auth_time) = request.auth_time {
        claims.insert("auth_time".into(), Value::from(auth_time));
    }
    if let Some(nonce) = &request.nonce {
        claims.insert("nonce".into(), Value::String(nonce.clone()));
    }
    let emit_sid = request.client.enable_end_session.unwrap_or(false) || request.client.backchannel_logout_uri.is_some();
    if emit_sid && let Some(session_id) = request.session_id {
        claims.insert("sid".into(), Value::String(session_id.to_string()));
    }
    Ok(claims)
}

async fn sign_id_token_claims(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    request: &IssueRequest,
    claims: Map<String, Value>,
) -> Result<Option<String>, OAuthProviderError> {
    if config.disable_jwt_plugin {
        let Some(stored) = request.client.client_secret.as_deref() else {
            return Ok(None);
        };
        let secret = decrypt_client_secret(service, config, stored)
            .await
            .map_err(server)?;
        encode(
            &Header::new(Algorithm::HS256),
            &Value::Object(claims),
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map(Some)
        .map_err(|_| OAuthProviderError::ServerError("ID token signing failed".into()))
    } else {
        let jwt = service.jwt().ok_or_else(|| {
            OAuthProviderError::ServerError("JWT plugin is required for ID tokens".into())
        })?;
        jwt.sign_jwt(
            &jwt_context("POST", "/oauth2/token", headers),
            claims,
            None,
            JwtSigningOverrides::default(),
        )
        .await
        .map(Some)
        .map_err(server)
    }
}

fn jwt_context(method: &str, path: &str, headers: &HeaderMap) -> JwtAdapterContext {
    JwtAdapterContext {
        method: Some(method.into()),
        path: Some(path.into()),
        query: None,
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
    }
}

fn jwk_algorithm(value: &str) -> Option<crate::JwkAlgorithm> {
    match value {
        "EdDSA" => Some(crate::JwkAlgorithm::EdDsa),
        "ES256" => Some(crate::JwkAlgorithm::Es256),
        "ES512" => Some(crate::JwkAlgorithm::Es512),
        "PS256" => Some(crate::JwkAlgorithm::Ps256 {
            modulus_length: None,
        }),
        "RS256" => Some(crate::JwkAlgorithm::Rs256 {
            modulus_length: None,
        }),
        _ => None,
    }
}

fn audience_value(audience: &[String]) -> Value {
    match audience {
        [only] => Value::String(only.clone()),
        values => Value::Array(values.iter().cloned().map(Value::String).collect()),
    }
}

fn oidc_hash(value: &str, algorithm: &str) -> String {
    let digest = if algorithm == "EdDSA" || algorithm.ends_with("512") {
        Sha512::digest(value.as_bytes()).to_vec()
    } else {
        Sha256::digest(value.as_bytes()).to_vec()
    };
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

fn subject_identifier(
    user_id: Uuid,
    client: &OAuthProviderClient,
    config: &OAuthProviderConfig,
) -> Result<String, OAuthProviderError> {
    if client.subject_type.as_deref() != Some("pairwise") {
        return Ok(user_id.to_string());
    }
    let secret = config.pairwise_secret.as_deref().ok_or_else(|| {
        OAuthProviderError::ServerError("pairwise client requires pairwiseSecret".into())
    })?;
    let redirect = client.redirect_uris.first().ok_or_else(|| {
        OAuthProviderError::ServerError("pairwise client has no redirect URIs".into())
    })?;
    let sector = Url::parse(redirect)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
        })
        .ok_or_else(|| {
            OAuthProviderError::ServerError("pairwise client redirect URI is invalid".into())
        })?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    hmac.update(format!("{sector}.{user_id}").as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hmac.finalize().into_bytes()))
}

fn callback_context(
    headers: &HeaderMap,
    user: Option<&crate::AuthUser>,
    scopes: &[String],
) -> OAuthCallbackContext {
    OAuthCallbackContext {
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
        user: user.and_then(|user| serde_json::to_value(user).ok()),
        session: None,
        scopes: scopes.to_vec(),
    }
}

#[cfg(test)]
mod sign_tests {
    use super::*;

    #[test]
    fn oidc_hash_uses_the_signing_algorithms_hash_family() {
        assert_ne!(oidc_hash("token", "RS256"), oidc_hash("token", "EdDSA"));
        assert_eq!(oidc_hash("token", "ES512"), oidc_hash("token", "EdDSA"));
    }

    #[test]
    fn pairwise_subjects_are_stable_and_sector_specific() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.pairwise_secret = Some("12345678901234567890123456789012".into());
        let mut client = test_client();
        let user_id = Uuid::nil();
        let first = subject_identifier(user_id, &client, &config).unwrap();
        assert_eq!(first, subject_identifier(user_id, &client, &config).unwrap());
        client.redirect_uris[0] = "https://other.example/callback".into();
        assert_ne!(first, subject_identifier(user_id, &client, &config).unwrap());
        client.redirect_uris[0] = "https://example.com:8443/callback".into();
        assert_ne!(first, subject_identifier(user_id, &client, &config).unwrap());
    }

    fn test_client() -> OAuthProviderClient {
        OAuthProviderClient {
            id: Uuid::nil(), client_id: "client".into(), client_secret: None,
            client_discovery_id: None, disabled: false, skip_consent: None,
            enable_end_session: None, subject_type: Some("pairwise".into()), scopes: None,
            client_credentials_scopes: Vec::new(), user_id: None, created_at: None,
            updated_at: None, expires_at: None, name: None, uri: None, icon: None,
            contacts: None, tos: None, policy: None, software_id: None,
            software_version: None, software_statement: None,
            redirect_uris: vec!["https://example.com/callback".into()],
            post_logout_redirect_uris: None, backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            token_endpoint_auth_method: Some("none".into()), application_type: None,
            jwks: None, jwks_uri: None, grant_types: None, response_types: None,
            require_pkce: None, dpop_bound_access_tokens: false,
            reference_id: None, metadata: None,
        }
    }
}
