use super::AuthService;
use crate::{AuthError, PasskeyConfig};
use rand::RngExt;
use webauthn_rs::prelude::Url;
use webauthn_rs_core::WebauthnCore;

pub(super) fn challenge(
    service: &AuthService,
    config: &PasskeyConfig,
) -> Result<WebauthnCore, AuthError> {
    let origins = match &config.origins {
        Some(origins) => parse_origins(origins.iter().map(String::as_str))?,
        None => vec![default_origin(service)?],
    };
    Ok(core(service, config, origins))
}

pub(super) fn verification(
    service: &AuthService,
    config: &PasskeyConfig,
    request_origin: Option<&str>,
) -> Result<WebauthnCore, AuthError> {
    let origins = match &config.origins {
        Some(origins) => parse_origins(origins.iter().map(String::as_str))?,
        None => vec![
            Url::parse(
                request_origin.ok_or_else(|| AuthError::InvalidRequest("origin missing".into()))?,
            )
            .map_err(|_| AuthError::PasskeyVerificationFailed)?,
        ],
    };
    Ok(core(service, config, origins))
}

pub(super) fn random_user_handle() -> [u8; 32] {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    std::array::from_fn(|_| ALPHABET[rng.random_range(0..ALPHABET.len())])
}

fn core(service: &AuthService, config: &PasskeyConfig, origins: Vec<Url>) -> WebauthnCore {
    let rp_id = config
        .rp_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            service
                .config
                .base_url
                .as_ref()
                .and_then(|url| url.host_str())
        })
        .unwrap_or("localhost");
    let rp_name = config
        .rp_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("Better Auth");
    WebauthnCore::new_unsafe_experts_only(
        rp_name,
        rp_id,
        origins,
        std::time::Duration::from_secs(300),
        None,
        None,
    )
}

fn default_origin(service: &AuthService) -> Result<Url, AuthError> {
    if let Some(base_url) = &service.config.base_url {
        return Url::parse(&base_url.origin().ascii_serialization())
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()));
    }
    Url::parse("http://localhost")
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
}

fn parse_origins<'a>(origins: impl Iterator<Item = &'a str>) -> Result<Vec<Url>, AuthError> {
    origins
        .map(|origin| {
            Url::parse(origin).map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_handles_match_better_auths_opaque_alphabet() {
        let handle = random_user_handle();
        assert_eq!(handle.len(), 32);
        assert!(
            handle
                .iter()
                .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
        );
    }
}
