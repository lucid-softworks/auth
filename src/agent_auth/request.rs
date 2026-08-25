use super::AgentSession;
use reqwest::header::HeaderMap;

#[derive(Clone, Debug)]
pub struct AgentRequestVerifier {
    base_url: String,
    client: reqwest::Client,
}

impl AgentRequestVerifier {
    pub fn new(base_url: impl Into<String>) -> Result<Self, AgentRequestVerifierError> {
        let base_url = base_url.into();
        let parsed =
            url::Url::parse(&base_url).map_err(|_| AgentRequestVerifierError::InvalidBaseUrl)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.cannot_be_a_base() {
            return Err(AgentRequestVerifierError::InvalidBaseUrl);
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client: reqwest::Client::new(),
        })
    }

    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub async fn verify(
        &self,
        request_headers: &HeaderMap,
    ) -> Result<Option<AgentSession>, AgentRequestVerifierError> {
        if !request_headers.contains_key(reqwest::header::AUTHORIZATION) {
            return Ok(None);
        }
        let response = self
            .client
            .get(format!("{}/agent/session", self.base_url))
            .headers(request_headers.clone())
            .send()
            .await
            .map_err(AgentRequestVerifierError::Request)?;
        if !response.status().is_success() {
            return Ok(None);
        }
        Ok(response.json::<AgentSession>().await.ok())
    }
}

pub async fn verify_agent_request(
    base_url: &str,
    request_headers: &HeaderMap,
) -> Result<Option<AgentSession>, AgentRequestVerifierError> {
    AgentRequestVerifier::new(base_url)?
        .verify(request_headers)
        .await
}

#[derive(Debug, thiserror::Error)]
pub enum AgentRequestVerifierError {
    #[error("Agent Auth base URL is invalid")]
    InvalidBaseUrl,
    #[error("Agent Auth session verification request failed: {0}")]
    Request(#[source] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_authorization_does_not_make_a_request() {
        let verifier = AgentRequestVerifier::new("https://provider.example/api/auth/").unwrap();
        assert!(verifier.verify(&HeaderMap::new()).await.unwrap().is_none());
    }
}
