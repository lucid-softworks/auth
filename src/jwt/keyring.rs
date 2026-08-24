use super::{
    JwkAlgorithm, JwtAdapterContext, JwtConfig, JwtError, JwtSigningOverrides, NewJwk,
    ResolvedSigningKey, StoredJwk, crypto,
};
use crate::{AuthError, AuthService};
use chrono::Utc;

pub(crate) async fn all_keys(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
) -> Result<Vec<StoredJwk>, AuthError> {
    if let Some(reader) = &config.adapter.get_jwks {
        return Ok(reader.get_jwks(context).await?.unwrap_or_default());
    }
    default_store(service)?.list_jwks(&config.schema).await
}

pub(crate) async fn create(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
    algorithm: JwkAlgorithm,
) -> Result<StoredJwk, AuthError> {
    let pair = crypto::generate_exported_key_pair(algorithm)?;
    let private_json = serde_json::to_string(&pair.private_web_key).map_err(key_json)?;
    let private_key = if config.jwks.disable_private_key_encryption {
        private_json
    } else {
        let encrypted = service
            .encrypt_jwt_private_key(private_json.as_bytes())
            .map_err(|_| JwtError::KeyEncryption)?;
        serde_json::to_string(&encrypted).map_err(key_json)?
    };
    let now = Utc::now();
    let expires_at = config
        .jwks
        .rotation_interval
        .filter(|interval| *interval != chrono::Duration::zero())
        .map(|interval| now + interval);
    let data = NewJwk {
        public_key: serde_json::to_string(&pair.public_web_key).map_err(key_json)?,
        private_key,
        created_at: now,
        expires_at,
        alg: Some(pair.alg),
        crv: pair.crv,
    };
    if let Some(creator) = &config.adapter.create_jwk {
        return creator.create_jwk(data, context).await;
    }
    default_store(service)?
        .create_jwk(&config.schema, data)
        .await
}

pub(crate) async fn resolve(
    service: &AuthService,
    config: &JwtConfig,
    context: &JwtAdapterContext,
    overrides: &JwtSigningOverrides,
) -> Result<Option<ResolvedSigningKey>, AuthError> {
    if config.jwt.sign.is_some() {
        return Ok(None);
    }
    let primary = config.jwks.key_pair_config.unwrap_or_default();
    let keys = all_keys(service, config, context).await?;
    let now = Utc::now();
    let mut key = if let Some(id) = &overrides.signing_key_id {
        let selected = keys.iter().find(|key| &key.id == id).cloned().ok_or_else(|| {
            JwtError::KeyConfiguration(format!(
                "signJWT: signingKeyId \"{id}\" not found in JWKS. The key must be provisioned before it can be referenced."
            ))
        })?;
        if let Some(requested) = overrides.signing_algorithm
            && effective_algorithm(&selected, primary) != Some(requested)
        {
            return Err(JwtError::KeyConfiguration(format!(
                "signJWT: signingKeyId \"{id}\" does not match signingAlgorithm \"{}\".",
                requested.name()
            ))
            .into());
        }
        Some(selected)
    } else if let Some(requested) = overrides.signing_algorithm {
        let selected = newest_live_matching(&keys, requested, primary, now);
        if selected.is_some() {
            selected
        } else if requested == primary || config.jwks.key_pair_configs.contains(&requested) {
            Some(create(service, config, context, requested).await?)
        } else {
            let extras = config
                .jwks
                .key_pair_configs
                .iter()
                .map(|algorithm| algorithm.name())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(JwtError::KeyConfiguration(format!(
                "signJWT: no key with alg \"{}\" found in JWKS. The configured primary is \"{}\" and additional algorithms are: {}.",
                requested.name(),
                primary.name(),
                if extras.is_empty() { "none" } else { &extras }
            ))
            .into());
        }
    } else {
        newest_live_matching(&keys, primary, primary, now)
    };
    if key
        .as_ref()
        .is_none_or(|key| key.expires_at.is_some_and(|expires| expires < now))
    {
        if overrides.signing_key_id.is_some() || overrides.signing_algorithm.is_some() {
            return Err(JwtError::KeyConfiguration(
                "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly."
                    .into(),
            )
            .into());
        }
        key = Some(create(service, config, context, primary).await?);
    }
    let mut key = key.expect("missing keys are provisioned above");
    let algorithm = effective_algorithm(&key, primary).ok_or_else(|| {
        JwtError::KeyConfiguration("stored JWT key has an unsupported algorithm".into())
    })?;
    key.private_key = decrypt_private_key(service, config, &key.private_key)?;
    Ok(Some(ResolvedSigningKey {
        alg: algorithm.name().into(),
        kid: key.id.clone(),
        key,
    }))
}

pub(crate) fn effective_algorithm(key: &StoredJwk, primary: JwkAlgorithm) -> Option<JwkAlgorithm> {
    key.alg
        .as_deref()
        .map(crypto::algorithm_from_name)
        .unwrap_or(Some(primary))
}

fn newest_live_matching(
    keys: &[StoredJwk],
    requested: JwkAlgorithm,
    primary: JwkAlgorithm,
    now: chrono::DateTime<Utc>,
) -> Option<StoredJwk> {
    newest(keys.iter().filter(|key| {
        effective_algorithm(key, primary) == Some(requested)
            && key.expires_at.is_none_or(|expires| expires >= now)
    }))
}

fn newest<'a>(keys: impl Iterator<Item = &'a StoredJwk>) -> Option<StoredJwk> {
    keys.max_by_key(|key| key.created_at).cloned()
}

fn decrypt_private_key(
    service: &AuthService,
    config: &JwtConfig,
    stored: &str,
) -> Result<String, AuthError> {
    if config.jwks.disable_private_key_encryption {
        return Ok(stored.into());
    }
    let envelope: String = serde_json::from_str(stored).map_err(|_| JwtError::KeyDecryption)?;
    let plaintext = service
        .decrypt_jwt_private_key(&envelope)
        .map_err(|_| JwtError::KeyDecryption)?;
    String::from_utf8(plaintext).map_err(|_| JwtError::KeyDecryption.into())
}

fn default_store(service: &AuthService) -> Result<&dyn crate::JwkStore, AuthError> {
    service.jwk_store().ok_or_else(|| {
        JwtError::KeyConfiguration(
            "the authentication store does not provide JWT key persistence and no custom adapter callback was configured"
                .into(),
        )
        .into()
    })
}

fn key_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("JWT key JSON failed: {error}"))
}
