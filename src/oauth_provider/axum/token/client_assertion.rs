fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthProviderError> {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let trimmed = value.trim();
    let scheme = trimmed.split_whitespace().next().ok_or_else(|| {
        OAuthProviderError::InvalidRequest("Invalid authorization header format".into())
    })?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(OAuthProviderError::ChallengedInvalidClient {
            description: "unsupported authorization scheme".into(),
            scheme: scheme.into(),
        });
    }
    let encoded = trimmed[scheme.len()..].trim_start();
    let decoded = STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            OAuthProviderError::BasicInvalidClient("malformed basic credentials".into())
        })?;
    let (client_id, secret) = decoded.split_once(':').ok_or_else(|| {
        OAuthProviderError::BasicInvalidClient("malformed basic credentials".into())
    })?;
    let decode = |value: &str| {
        percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .map(|value| value.into_owned())
            .map_err(|_| {
                OAuthProviderError::BasicInvalidClient("malformed basic credentials".into())
            })
    };
    Ok(Some((decode(client_id)?, decode(secret)?)))
}

const PRIVATE_KEY_JWT_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
    "EdDSA",
];

#[derive(Deserialize)]
struct ClientAssertionHeader {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct UnverifiedClientAssertion {
    iss: Option<String>,
    sub: Option<String>,
}

struct ClientAssertionValidation<'a> {
    service: &'a AuthService,
    config: &'a OAuthProviderConfig,
    store: &'a dyn OAuthProviderStore,
    client: &'a OAuthProviderClient,
    endpoint: &'a str,
    provider_issuer: &'a str,
}

fn client_assertion_client_id(
    assertion: &str,
    hint: Option<&str>,
) -> Result<String, OAuthProviderError> {
    let unverified: UnverifiedClientAssertion = decode_assertion_part(assertion, 1).map_err(|_| {
        OAuthProviderError::InvalidClient(
            "malformed client assertion: invalid JWT payload".into(),
        )
    })?;
    let client_id = unverified.sub.or(unverified.iss).ok_or_else(|| {
        OAuthProviderError::InvalidClient(
            "client assertion must contain sub or iss claim identifying the client".into(),
        )
    })?;
    if hint.is_some_and(|hint| hint != client_id) {
        return Err(OAuthProviderError::InvalidClient(
            "client_id in body does not match assertion sub/iss".into(),
        ));
    }
    Ok(client_id)
}

async fn validate_client_assertion(
    context: ClientAssertionValidation<'_>,
    assertion: &str,
    assertion_type: Option<&str>,
) -> Result<(), OAuthProviderError> {
    if assertion_type != Some(PRIVATE_KEY_JWT_ASSERTION_TYPE) {
        return Err(OAuthProviderError::InvalidClient(
            "unsupported client_assertion_type".into(),
        ));
    }
    let header: ClientAssertionHeader = decode_assertion_part(assertion, 0).map_err(|_| {
        OAuthProviderError::InvalidClient(
            "malformed client assertion: invalid JWT header".into(),
        )
    })?;
    if !PRIVATE_KEY_JWT_ALGORITHMS.contains(&header.alg.as_str()) {
        return Err(OAuthProviderError::InvalidClient(format!(
            "unsupported assertion signing algorithm: {}",
            header.alg
        )));
    }
    let mut jwks = client_jwks(context.service, context.config, context.client, false).await?;
    let claims = match verify_client_assertion_signature(assertion, &header, &jwks) {
        Some(claims) => claims,
        None if context.client.jwks_uri.is_some() => {
            jwks = client_jwks(context.service, context.config, context.client, true)
                .await
                .map_err(|_| {
                    OAuthProviderError::UnauthorizedInvalidClient(
                        "client assertion signature verification failed".into(),
                    )
                })?;
            verify_client_assertion_signature(assertion, &header, &jwks).ok_or_else(|| {
                OAuthProviderError::UnauthorizedInvalidClient(
                    "client assertion signature verification failed".into(),
                )
            })?
        }
        None => {
            return Err(OAuthProviderError::UnauthorizedInvalidClient(
                "client assertion signature verification failed".into(),
            ));
        }
    };
    validate_client_assertion_claims(
        context.config,
        context.store,
        context.client,
        &claims,
        context.endpoint,
        context.provider_issuer,
    )
    .await
}

fn decode_assertion_part<T: serde::de::DeserializeOwned>(
    assertion: &str,
    index: usize,
) -> Result<T, ()> {
    let encoded = assertion.split('.').nth(index).ok_or(())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn verify_client_assertion_signature(
    assertion: &str,
    header: &ClientAssertionHeader,
    jwks: &JoseJwkSet,
) -> Option<Map<String, Value>> {
    for jwk in jwks.keys().into_iter().filter(|jwk| {
        header.kid.as_deref().is_none_or(|kid| jwk.key_id() == Some(kid))
            && jwk.algorithm().is_none_or(|algorithm| algorithm == header.alg)
    }) {
        let Some(verifier) = client_assertion_verifier(&header.alg, jwk) else {
            continue;
        };
        if let Ok((payload, _)) = josekit::jwt::decode_with_verifier(assertion, verifier.as_ref()) {
            return Some(payload.as_ref().clone());
        }
    }
    None
}

fn client_assertion_verifier(
    algorithm: &str,
    jwk: &josekit::jwk::Jwk,
) -> Option<Box<dyn josekit::jws::JwsVerifier>> {
    use josekit::jws::{
        ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512,
    };
    Some(match algorithm {
        "RS256" => Box::new(RS256.verifier_from_jwk(jwk).ok()?),
        "RS384" => Box::new(RS384.verifier_from_jwk(jwk).ok()?),
        "RS512" => Box::new(RS512.verifier_from_jwk(jwk).ok()?),
        "PS256" => Box::new(PS256.verifier_from_jwk(jwk).ok()?),
        "PS384" => Box::new(PS384.verifier_from_jwk(jwk).ok()?),
        "PS512" => Box::new(PS512.verifier_from_jwk(jwk).ok()?),
        "ES256" => Box::new(ES256.verifier_from_jwk(jwk).ok()?),
        "ES384" => Box::new(ES384.verifier_from_jwk(jwk).ok()?),
        "ES512" => Box::new(ES512.verifier_from_jwk(jwk).ok()?),
        "EdDSA" => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?),
        _ => return None,
    })
}

async fn validate_client_assertion_claims(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    client: &OAuthProviderClient,
    claims: &Map<String, Value>,
    endpoint: &str,
    provider_issuer: &str,
) -> Result<(), OAuthProviderError> {
    let subject = claims.get("sub").and_then(Value::as_str);
    if subject != Some(client.client_id.as_str())
        || claims.get("iss").and_then(Value::as_str) != subject
    {
        return Err(OAuthProviderError::InvalidClient(
            "client assertion subject mismatch".into(),
        ));
    }
    validate_client_assertion_audience(claims, endpoint, provider_issuer)?;
    let now = Utc::now().timestamp();
    let exp = claims.get("exp").and_then(Value::as_f64).ok_or_else(|| {
        OAuthProviderError::InvalidClient("client assertion must include exp claim".into())
    })?;
    validate_client_assertion_lifetime(config, claims, now, exp)?;
    reserve_client_assertion(store, client, claims, exp.ceil() as i64).await
}

fn validate_client_assertion_audience(
    claims: &Map<String, Value>,
    endpoint: &str,
    provider_issuer: &str,
) -> Result<(), OAuthProviderError> {
    let audiences = claims.get("aud").map_or_else(Vec::new, |audience| match audience {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    });
    if audiences
        .iter()
        .any(|audience| *audience == endpoint || *audience == provider_issuer)
    {
        Ok(())
    } else {
        Err(OAuthProviderError::InvalidClient(
            "client assertion aud does not match the endpoint".into(),
        ))
    }
}

fn validate_client_assertion_lifetime(
    config: &OAuthProviderConfig,
    claims: &Map<String, Value>,
    now: i64,
    exp: f64,
) -> Result<(), OAuthProviderError> {
    let now = now as f64;
    if exp <= now {
        return Err(OAuthProviderError::InvalidClient(
            "client assertion has expired".into(),
        ));
    }
    if exp - now > config.assertion_max_lifetime as f64 {
        return Err(OAuthProviderError::InvalidClient(format!(
            "client assertion exp is too far in the future (max {}s)",
            config.assertion_max_lifetime
        )));
    }
    if claims
        .get("iat")
        .and_then(Value::as_f64)
        .is_some_and(|iat| now - iat > config.assertion_max_lifetime as f64)
    {
        return Err(OAuthProviderError::InvalidClient(format!(
            "client assertion iat is too far in the past (max {}s)",
            config.assertion_max_lifetime
        )));
    }
    Ok(())
}

async fn reserve_client_assertion(
    store: &dyn OAuthProviderStore,
    client: &OAuthProviderClient,
    claims: &Map<String, Value>,
    exp: i64,
) -> Result<(), OAuthProviderError> {
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OAuthProviderError::InvalidClient("client assertion must include jti claim".into())
        })?;
    let expires_at = DateTime::from_timestamp(exp, 0).ok_or_else(|| {
        OAuthProviderError::InvalidClient("client assertion exp is invalid".into())
    })?;
    let reserved = store
        .reserve_oauth_client_assertion(OAuthProviderClientAssertion {
            id: client_assertion_id(&format!("private_key_jwt:{}", client.client_id), jti),
            expires_at,
        })
        .await
        .map_err(server)?;
    if !reserved {
        return Err(OAuthProviderError::InvalidClient(
            "client assertion jti has already been used".into(),
        ));
    }
    Ok(())
}
