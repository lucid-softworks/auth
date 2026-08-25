use serde_json::{Map, Value};

use super::{
    McpProtectedRequestHandlerOptions, McpRemoteVerifyOptions, VerificationFailure,
    jwt::{ClaimFailure, validate_claims},
};

pub(super) async fn verify(
    http: &reqwest::Client,
    token: &str,
    remote: &McpRemoteVerifyOptions,
    options: &McpProtectedRequestHandlerOptions,
) -> Result<Map<String, Value>, VerificationFailure> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &remote.client_id)
        .append_pair("client_secret", &remote.client_secret)
        .append_pair("token", token)
        .append_pair("token_type_hint", "access_token")
        .finish();
    let response = http
        .post(&remote.introspect_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(infrastructure)?;
    if response.status().is_redirection() {
        return Err(VerificationFailure::Infrastructure(format!(
            "The OAuth endpoint \"{}\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.",
            remote.introspect_url
        )));
    }
    if !response.status().is_success() {
        return Err(VerificationFailure::Infrastructure(
            "introspection failed".into(),
        ));
    }
    let value: Value = response
        .json()
        .await
        .map_err(|_| VerificationFailure::Infrastructure("introspection failed".into()))?;
    let mut payload = value
        .as_object()
        .cloned()
        .ok_or_else(|| VerificationFailure::Infrastructure("introspection failed".into()))?;
    if !payload.get("active").is_some_and(js_truthy) {
        return Err(VerificationFailure::Challenge(
            crate::OAuthProviderError::InvalidToken("token inactive".into()),
        ));
    }
    if options.jwt_verify_options.token_type.is_some() {
        return Err(VerificationFailure::Infrastructure(
            "introspection claims are invalid".into(),
        ));
    }
    let skip_audience =
        payload.get("aud").is_none_or(|value| !js_truthy(value)) && remote.allow_missing_audience;
    let original_audience = skip_audience.then(|| payload.remove("aud")).flatten();
    if skip_audience {
        payload.insert("aud".into(), Value::String(options.audience.clone()));
    }
    let mut payload = validate_claims(payload, options).map_err(|failure| match failure {
        ClaimFailure::Expired => VerificationFailure::Challenge(
            crate::OAuthProviderError::InvalidToken("token expired".into()),
        ),
        ClaimFailure::Invalid => {
            VerificationFailure::Infrastructure("introspection claims are invalid".into())
        }
    })?;
    if skip_audience {
        payload.remove("aud");
        if let Some(audience) = original_audience {
            payload.insert("aud".into(), audience);
        }
    }
    Ok(payload)
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn infrastructure(error: impl std::fmt::Display) -> VerificationFailure {
    VerificationFailure::Infrastructure(error.to_string())
}
