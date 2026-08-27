use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Clone, Deserialize)]
pub(super) struct TokenBody {
    pub token: String,
    pub state: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct OAuthProxyQuery {
    pub provider: String,
    pub state: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct TransferQuery {
    pub client_id: String,
    pub state: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct TransferBody {
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
}

pub(super) fn query<T: DeserializeOwned>(raw: Option<&str>) -> Result<T, ()> {
    serde_urlencoded::from_str(raw.unwrap_or_default()).map_err(|_| ())
}

pub(super) fn hook_query(raw: Option<&str>) -> Option<TransferQuery> {
    let query = query::<TransferQuery>(raw).ok()?;
    (!query.code_challenge.is_empty() && !query.state.is_empty()).then_some(query)
}

pub(super) fn validation_error(message: impl Into<String>) -> axum::response::Response {
    crate::axum::api_error(
        axum::http::StatusCode::BAD_REQUEST,
        "VALIDATION_ERROR",
        message,
    )
}

pub(super) fn required_query_error(field: &str) -> axum::response::Response {
    validation_error(format!(
        "[query.{field}] Invalid input: expected string, received undefined"
    ))
}

pub(super) fn nonempty_body_error(field: &str) -> axum::response::Response {
    validation_error(format!(
        "[body.{field}] Too small: expected string to have >=1 characters"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_query_is_exact_case_nonempty_and_rejects_duplicates() {
        assert_eq!(
            hook_query(Some("client_id=electron&state=s&code_challenge=c")),
            Some(TransferQuery {
                client_id: "electron".into(),
                state: "s".into(),
                code_challenge: "c".into(),
            })
        );
        assert!(hook_query(Some("clientId=electron&state=s&code_challenge=c")).is_none());
        assert!(hook_query(Some("client_id=electron&state=&code_challenge=c")).is_none());
        assert!(
            hook_query(Some(
                "client_id=electron&client_id=electron&state=s&code_challenge=c"
            ))
            .is_none()
        );
    }
}
