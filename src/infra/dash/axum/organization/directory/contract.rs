use super::pairing::DirectoryPairing;
use crate::ScimScope;
use axum::{http::StatusCode, response::Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateBody {
    pub provider_id: String,
    pub pairing: Option<DirectoryPairing>,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RotateBody {
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) fn policy(
    requested: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(Vec<ScimScope>, DateTime<Utc>), Response> {
    let expires_at = expires_at.unwrap_or_else(|| Utc::now() + Duration::days(365));
    if expires_at <= Utc::now() {
        return Err(bad_request("Directory sync credential expiry must be in the future"));
    }
    let values = requested.unwrap_or_else(|| {
        ScimScope::ALL
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect()
    });
    if values.is_empty() || values.iter().collect::<HashSet<_>>().len() != values.len() {
        return Err(bad_request("Directory sync credential scopes must be unique"));
    }
    let scopes = values
        .iter()
        .map(|value| {
            ScimScope::ALL
                .into_iter()
                .find(|scope| scope.as_str() == value)
                .ok_or_else(|| bad_request("Invalid directory sync credential scope"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((scopes, expires_at))
}

fn bad_request(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}
