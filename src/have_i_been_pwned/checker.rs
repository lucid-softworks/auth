use async_trait::async_trait;
use sha1::{Digest, Sha1};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range";

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum PasswordBreachCheckError {
    #[error("password range request failed with status {0}")]
    Status(u16),
    #[error("password range request could not be completed")]
    Unavailable,
}

/// Independently reusable, in-process password compromise checker.
#[async_trait]
pub trait PasswordBreachChecker: Send + Sync {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError>;
}

/// Better Auth's HIBP k-anonymity transport and response parser.
#[derive(Clone)]
pub struct PwnedPasswordsChecker {
    client: reqwest::Client,
    range_url: String,
}

impl PwnedPasswordsChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            range_url: RANGE_URL.into(),
        }
    }

    #[cfg(test)]
    fn with_range_url(range_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            range_url: range_url.into(),
        }
    }
}

impl Default for PwnedPasswordsChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PasswordBreachChecker for PwnedPasswordsChecker {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        if password.is_empty() {
            return Ok(false);
        }
        let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
        let (prefix, suffix) = hash.split_at(5);
        let response = self
            .client
            .get(format!("{}/{prefix}", self.range_url.trim_end_matches('/')))
            .header("Add-Padding", "true")
            .header("User-Agent", "BetterAuth Password Checker")
            .send()
            .await
            .map_err(|_| PasswordBreachCheckError::Unavailable)?;
        if !response.status().is_success() {
            return Err(PasswordBreachCheckError::Status(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let data = if content_type == "application/json" || content_type.ends_with("+json") {
            response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(PasswordBreachCheckError::Unavailable)?
        } else {
            response
                .text()
                .await
                .map_err(|_| PasswordBreachCheckError::Unavailable)?
        };
        Ok(matches_suffix(&data, suffix))
    }
}

fn matches_suffix(data: &str, suffix: &str) -> bool {
    data.split('\n').any(|line| {
        line.split(':')
            .next()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::Request, routing::get};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn parser_keeps_the_exact_split_without_trimming_or_format_validation() {
        let suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        assert!(matches_suffix(&format!("{suffix}:1\r\n"), suffix));
        assert!(matches_suffix(&suffix.to_lowercase(), suffix));
        assert!(matches_suffix(suffix, suffix));
        assert!(!matches_suffix(&format!(" {suffix}:1"), suffix));
        assert!(!matches_suffix(&format!("{suffix}X:1"), suffix));
        assert!(!matches_suffix("<html>failure</html>", suffix));
        assert!(!matches_suffix("", suffix));
    }

    #[tokio::test]
    async fn request_uses_the_pinned_prefix_method_and_headers() {
        let observed = Arc::new(Mutex::new(None));
        let captured = observed.clone();
        let app = Router::new().route(
            "/range/5BAA6",
            get(move |request: Request| {
                let captured = captured.clone();
                async move {
                    *captured.lock().unwrap() = Some((
                        request.method().clone(),
                        request.uri().clone(),
                        request.headers().clone(),
                    ));
                    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\r\n"
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let checker = PwnedPasswordsChecker::with_range_url(format!("http://{address}/range"));

        assert!(checker.is_compromised("password").await.unwrap());
        let (method, uri, headers) = observed.lock().unwrap().clone().unwrap();
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(uri.path(), "/range/5BAA6");
        assert_eq!(headers["add-padding"], "true");
        assert_eq!(headers["user-agent"], "BetterAuth Password Checker");
        assert!(!uri.to_string().contains("password"));
        assert!(!uri.to_string().contains("1E4C9B93"));
    }

    #[tokio::test]
    async fn successful_non_string_json_data_uses_the_generic_failure() {
        let app = Router::new().route(
            "/range/5BAA6",
            get(|| async { axum::Json(serde_json::json!({ "suffix": "not text" })) }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let checker = PwnedPasswordsChecker::with_range_url(format!("http://{address}/range"));

        assert_eq!(
            checker.is_compromised("password").await,
            Err(PasswordBreachCheckError::Unavailable)
        );
    }
}
