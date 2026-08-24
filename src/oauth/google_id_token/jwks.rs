use super::GoogleIdTokenError;
use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;

#[async_trait]
pub(super) trait GoogleJwksSource: Send + Sync {
    async fn fetch(&self) -> Result<JwkSet, GoogleIdTokenError>;
}

pub(super) struct GoogleJwksHttpSource {
    client: reqwest::Client,
    jwks_url: String,
}

impl GoogleJwksHttpSource {
    pub(super) fn new(jwks_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            jwks_url: jwks_url.into(),
        }
    }
}

#[async_trait]
impl GoogleJwksSource for GoogleJwksHttpSource {
    async fn fetch(&self) -> Result<JwkSet, GoogleIdTokenError> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_| GoogleIdTokenError::JwksUnavailable)?;
        if !response.status().is_success() {
            return Err(GoogleIdTokenError::JwksUnavailable);
        }
        response
            .json()
            .await
            .map_err(|_| GoogleIdTokenError::JwksUnavailable)
    }
}

#[cfg(test)]
pub(super) struct StaticGoogleJwksSource(pub(super) JwkSet);

#[cfg(test)]
#[async_trait]
impl GoogleJwksSource for StaticGoogleJwksSource {
    async fn fetch(&self) -> Result<JwkSet, GoogleIdTokenError> {
        Ok(self.0.clone())
    }
}
