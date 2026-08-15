use crate::AuthError;
use async_trait::async_trait;
use sha1::{Digest, Sha1};
use std::time::Duration;

const PWNED_PASSWORDS_RANGE_URL: &str = "https://api.pwnedpasswords.com/range";

/// Checks plaintext passwords before they are accepted by the authentication service.
#[async_trait]
pub trait PasswordBreachChecker: Send + Sync {
    async fn is_compromised(&self, password: &str) -> Result<bool, AuthError>;
}

/// Native client for the Have I Been Pwned Pwned Passwords k-anonymity API.
#[derive(Clone)]
pub struct PwnedPasswordsChecker {
    client: reqwest::Client,
    range_url: String,
}

impl PwnedPasswordsChecker {
    pub fn new() -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("lucid-auth password checker")
            .build()
            .map_err(|_| AuthError::PasswordCheckUnavailable)?;
        Ok(Self {
            client,
            range_url: PWNED_PASSWORDS_RANGE_URL.into(),
        })
    }

    #[cfg(test)]
    fn with_range_url(range_url: impl Into<String>) -> Result<Self, AuthError> {
        let mut checker = Self::new()?;
        checker.range_url = range_url.into();
        Ok(checker)
    }
}

#[async_trait]
impl PasswordBreachChecker for PwnedPasswordsChecker {
    async fn is_compromised(&self, password: &str) -> Result<bool, AuthError> {
        let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
        let (prefix, suffix) = hash.split_at(5);
        let response = self
            .client
            .get(format!("{}/{prefix}", self.range_url.trim_end_matches('/')))
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|_| AuthError::PasswordCheckUnavailable)?;
        if !response.status().is_success() {
            return Err(AuthError::PasswordCheckUnavailable);
        }
        let body = response
            .text()
            .await
            .map_err(|_| AuthError::PasswordCheckUnavailable)?;
        Ok(body.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tokio::net::TcpListener;

    async fn checker(response: &'static str) -> PwnedPasswordsChecker {
        let app = Router::new().route("/range/5BAA6", get(move || async move { response }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        PwnedPasswordsChecker::with_range_url(format!("http://{address}/range")).unwrap()
    }

    #[tokio::test]
    async fn detects_only_the_matching_hash_suffix() {
        let compromised = checker(
            "00000000000000000000000000000000000:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\r\n",
        )
        .await;
        assert!(compromised.is_compromised("password").await.unwrap());

        let clean = checker("00000000000000000000000000000000000:0\r\n").await;
        assert!(!clean.is_compromised("password").await.unwrap());
    }
}
