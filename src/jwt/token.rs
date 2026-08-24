use super::{
    JwkAlgorithm, JwtAdapterContext, JwtConfig, JwtError, JwtProtectedHeader, JwtSession,
    JwtSigningOverrides, ResolvedSigningKey, keyring,
};
use crate::{AuthError, AuthService};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::{Map, Number, Value};

pub struct JwtService<'a> {
    service: &'a AuthService,
    config: &'a JwtConfig,
}

impl AuthService {
    pub fn jwt(&self) -> Option<JwtService<'_>> {
        self.jwt_plugin().map(|plugin| JwtService {
            service: self,
            config: plugin.config(),
        })
    }
}

impl<'a> JwtService<'a> {
    pub async fn create_jwk(
        &self,
        context: &JwtAdapterContext,
        algorithm: Option<JwkAlgorithm>,
    ) -> Result<crate::StoredJwk, AuthError> {
        keyring::create(
            self.service,
            self.config,
            context,
            algorithm.unwrap_or_else(|| self.config.jwks.key_pair_config.unwrap_or_default()),
        )
        .await
    }

    pub async fn resolve_signing_key(
        &self,
        context: &JwtAdapterContext,
        overrides: &JwtSigningOverrides,
    ) -> Result<Option<ResolvedSigningKey>, AuthError> {
        keyring::resolve(self.service, self.config, context, overrides).await
    }

    pub async fn get_jwt_token(
        &self,
        context: &JwtAdapterContext,
        session: &JwtSession,
    ) -> Result<String, AuthError> {
        get_jwt_token(self.service, self.config, context, session).await
    }

    pub async fn sign_jwt(
        &self,
        context: &JwtAdapterContext,
        payload: Map<String, Value>,
        header: Option<JwtProtectedHeader>,
        signing: JwtSigningOverrides,
    ) -> Result<String, AuthError> {
        sign_jwt(self.service, self.config, context, payload, header, signing).await
    }

    pub async fn sign_jwt_with_override_options(
        &self,
        context: &JwtAdapterContext,
        payload: Map<String, Value>,
        overrides: Option<&super::JwtOverrideOptions>,
    ) -> Result<String, AuthError> {
        let config = overrides
            .map(|overrides| overrides.apply_to(self.config))
            .unwrap_or_else(|| self.config.clone());
        sign_jwt(
            self.service,
            &config,
            context,
            payload,
            None,
            JwtSigningOverrides::default(),
        )
        .await
    }

    pub async fn verify_jwt(
        &self,
        context: &JwtAdapterContext,
        token: &str,
        issuer: Option<&str>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        verify_jwt(self.service, self.config, context, token, issuer).await
    }
}

pub(crate) async fn get_jwt_token(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
    session: &JwtSession,
) -> Result<String, AuthError> {
    let mut payload = if let Some(define) = &config.jwt.define_payload {
        define.define_payload(session).await?
    } else {
        session.user.as_object().cloned().ok_or(JwtError::Signing)?
    };
    payload
        .entry("iat")
        .or_insert_with(|| Value::Number(Utc::now().timestamp().into()));
    let subject = if let Some(resolver) = &config.jwt.get_subject {
        resolver.get_subject(session).await?
    } else {
        None
    }
    .or_else(|| {
        session
            .user
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
    .ok_or(JwtError::Signing)?;
    payload.insert("sub".into(), Value::String(subject));
    sign_jwt(
        service,
        config,
        context,
        payload,
        None,
        JwtSigningOverrides::default(),
    )
    .await
}

pub(crate) async fn sign_jwt(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
    mut payload: Map<String, Value>,
    header: Option<JwtProtectedHeader>,
    signing: JwtSigningOverrides,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp() as f64;
    let iat = numeric_claim(&payload, "iat").unwrap_or(now);
    let expiration = super::to_exp_jwt(&config.jwt.expiration_time, iat)?;
    set_default_number(&mut payload, "exp", expiration)?;
    let origin = service.jwt_default_origin();
    let issuer = config
        .jwt
        .issuer
        .clone()
        .or_else(|| origin.clone())
        .ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "JWT issuer requires a configured base URL or explicit jwt.issuer".into(),
            )
        })?;
    let audience = config
        .jwt
        .audience
        .clone()
        .or_else(|| origin.map(Into::into))
        .ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "JWT audience requires a configured base URL or explicit jwt.audience".into(),
            )
        })?;
    if payload.get("iss").is_none_or(Value::is_null) {
        payload.insert("iss".into(), Value::String(issuer));
    }
    if payload.get("aud").is_none_or(Value::is_null) {
        payload.insert("aud".into(), audience.value());
    }
    if let Some(remote) = &config.jwt.sign {
        return remote.sign(payload, header, Some(signing)).await;
    }
    let resolved = keyring::resolve(service, config, context, &signing)
        .await?
        .ok_or(JwtError::Signing)?;
    let algorithm = super::crypto::algorithm_from_name(&resolved.alg)
        .ok_or_else(|| JwtError::KeyConfiguration("unsupported resolved algorithm".into()))?;
    super::crypto::sign_compact(
        &payload,
        header.as_ref(),
        algorithm,
        &resolved.kid,
        &resolved.key.private_key,
    )
}

pub(crate) async fn verify_jwt(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
    token: &str,
    issuer: Option<&str>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let Some(kid) = token_kid(token) else {
        return Ok(None);
    };
    let keys = keyring::all_keys(service, config, context).await?;
    let Some(key) = keys.iter().find(|key| key.id == kid) else {
        return Ok(None);
    };
    let primary = config.jwks.key_pair_config.unwrap_or_default();
    let Some(algorithm) = keyring::effective_algorithm(key, primary) else {
        return Ok(None);
    };
    let Some(payload) = super::crypto::verify_compact(token, algorithm, &key.public_key) else {
        return Ok(None);
    };
    let Some(expected_issuer) = issuer
        .map(str::to_owned)
        .or_else(|| config.jwt.issuer.clone())
        .or_else(|| service.jwt_default_origin())
    else {
        return Ok(None);
    };
    if Some(expected_issuer.as_str()) != payload.get("iss").and_then(Value::as_str) {
        return Ok(None);
    }
    let expected_audience = config
        .jwt
        .audience
        .clone()
        .or_else(|| service.jwt_default_origin().map(Into::into));
    if !audience_matches(payload.get("aud"), expected_audience.as_ref()) {
        return Ok(None);
    }
    let now = Utc::now().timestamp() as f64;
    let Some(exp) = optional_numeric_claim(&payload, "exp") else {
        return Ok(None);
    };
    let Some(nbf) = optional_numeric_claim(&payload, "nbf") else {
        return Ok(None);
    };
    if exp.is_some_and(|exp| exp <= now)
        || nbf.is_some_and(|nbf| nbf > now)
        || payload
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || payload.get("aud").is_none_or(Value::is_null)
    {
        return Ok(None);
    }
    Ok(Some(payload))
}

fn token_kid(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    header
        .get("kid")?
        .as_str()
        .filter(|kid| !kid.is_empty())
        .map(str::to_owned)
}

fn set_default_number(
    payload: &mut Map<String, Value>,
    name: &str,
    value: f64,
) -> Result<(), AuthError> {
    if payload.get(name).is_none_or(Value::is_null) {
        payload.insert(
            name.into(),
            Value::Number(Number::from_f64(value).ok_or(JwtError::Signing)?),
        );
    }
    Ok(())
}

fn numeric_claim(payload: &Map<String, Value>, name: &str) -> Option<f64> {
    payload.get(name).and_then(Value::as_f64)
}

fn optional_numeric_claim(payload: &Map<String, Value>, name: &str) -> Option<Option<f64>> {
    match payload.get(name) {
        None => Some(None),
        Some(value) => value.as_f64().map(Some),
    }
}

fn audience_matches(actual: Option<&Value>, expected: Option<&super::JwtAudience>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let expected = expected.values();
    match actual {
        Some(Value::String(value)) => expected.contains(value),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| expected.iter().any(|expected| expected == value)),
        _ => false,
    }
}
