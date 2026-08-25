#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::{CaptchaConfig, CaptchaError, CaptchaProvider, ProtectedEndpoints};
use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const TURNSTILE_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_URL: &str = "https://www.google.com/recaptcha/api/siteverify";
const HCAPTCHA_URL: &str = "https://api.hcaptcha.com/siteverify";
const CAPTCHAFOX_URL: &str = "https://api.captchafox.com/siteverify";

pub(super) async fn intercept(
    service: &crate::AuthService,
    config: &CaptchaConfig,
    endpoints: &ProtectedEndpoints,
    request: Request,
) -> Result<Request, Response> {
    if !endpoints.matches(request.uri().path(), service.base_path()) {
        return Ok(request);
    }
    if config.secret_key().is_empty() {
        tracing::error!(endpoint = %request.uri(), "captcha verification failed: Missing secret key");
        return Err(error_response(CaptchaError::UnknownError));
    }
    let response = request
        .headers()
        .get("x-captcha-response")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    let remote_ip = service.resolve_client_ip(|name| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    });
    let Some(response) = response else {
        return Err(error_response(CaptchaError::MissingResponse));
    };
    match verify(config, response, remote_ip.as_deref()).await {
        Ok(true) => Ok(request),
        Ok(false) => Err(error_response(CaptchaError::VerificationFailed)),
        Err(error) => {
            tracing::error!(endpoint = %request.uri(), error = %error, "captcha provider verification failed");
            Err(error_response(CaptchaError::UnknownError))
        }
    }
}

fn error_response(error: CaptchaError) -> Response {
    let status = StatusCode::from_u16(error.status()).expect("captcha statuses are valid");
    let body = serde_json::to_string(&ErrorBody {
        message: error.to_string(),
        code: error.code(),
    })
    .expect("captcha errors are serializable");
    (
        status,
        [(header::CONTENT_TYPE, "text/plain;charset=UTF-8")],
        Body::from(body),
    )
        .into_response()
}

#[derive(Serialize)]
struct ErrorBody {
    message: String,
    code: &'static str,
}

#[derive(Serialize)]
struct TurnstileBody<'a> {
    secret: &'a str,
    response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<&'a str>,
}

async fn verify(
    config: &CaptchaConfig,
    captcha_response: &str,
    remote_ip: Option<&str>,
) -> Result<bool, VerifyError> {
    let request = provider_request(config, captcha_response, remote_ip);
    let data = fetch(request).await?;
    if !js_truthy(&data) {
        return Err(VerifyError::Unavailable);
    }
    let success = data.get("success").is_some_and(js_truthy);
    if !success {
        return Ok(false);
    }
    Ok(provider_constraints_match(config, &data))
}

fn provider_constraints_match(config: &CaptchaConfig, data: &Value) -> bool {
    match config {
        CaptchaConfig::CloudflareTurnstile(options) => {
            action_matches(options.expected_action.as_deref(), data)
                && turnstile_hostname_matches(options.allowed_hostnames.as_deref(), data)
        }
        CaptchaConfig::GoogleRecaptcha(options) => {
            let score_matches = data
                .get("score")
                .and_then(Value::as_f64)
                .is_none_or(|score| {
                    score.partial_cmp(&options.min_score.unwrap_or(0.5))
                        != Some(std::cmp::Ordering::Less)
                });
            score_matches
                && action_matches(options.expected_action.as_deref(), data)
                && google_hostname_matches(options.allowed_hostnames.as_deref(), data)
        }
        CaptchaConfig::HCaptcha(_) | CaptchaConfig::CaptchaFox(_) => true,
    }
}

fn action_matches(expected: Option<&str>, data: &Value) -> bool {
    expected
        .filter(|value| !value.is_empty())
        .is_none_or(|expected| data.get("action").and_then(Value::as_str) == Some(expected))
}

fn turnstile_hostname_matches(allowed: Option<&[String]>, data: &Value) -> bool {
    allowed
        .filter(|values| !values.is_empty())
        .is_none_or(|allowed| {
            data.get("hostname")
                .and_then(Value::as_str)
                .filter(|hostname| !hostname.is_empty())
                .is_some_and(|hostname| allowed.iter().any(|value| value == hostname))
        })
}

fn google_hostname_matches(allowed: Option<&[String]>, data: &Value) -> bool {
    allowed
        .filter(|values| !values.is_empty())
        .is_none_or(|allowed| {
            data.get("hostname")
                .and_then(Value::as_str)
                .is_some_and(|hostname| allowed.iter().any(|value| value == hostname))
        })
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

struct ProviderRequest {
    url: String,
    body: ProviderBody,
}

enum ProviderBody {
    Json(String),
    Form(String),
}

fn provider_request(
    config: &CaptchaConfig,
    response: &str,
    remote_ip: Option<&str>,
) -> ProviderRequest {
    let default_url = match config.provider() {
        CaptchaProvider::CloudflareTurnstile => TURNSTILE_URL,
        CaptchaProvider::GoogleRecaptcha => RECAPTCHA_URL,
        CaptchaProvider::HCaptcha => HCAPTCHA_URL,
        CaptchaProvider::CaptchaFox => CAPTCHAFOX_URL,
    };
    let url = config
        .site_verify_url_override()
        .filter(|url| !url.is_empty())
        .unwrap_or(default_url)
        .to_owned();
    let body = match config {
        CaptchaConfig::CloudflareTurnstile(_) => ProviderBody::Json(
            serde_json::to_string(&TurnstileBody {
                secret: config.secret_key(),
                response,
                remoteip: remote_ip.filter(|value| !value.is_empty()),
            })
            .expect("captcha request is serializable"),
        ),
        CaptchaConfig::GoogleRecaptcha(_) => {
            form_body(config.secret_key(), response, None, remote_ip, "remoteip")
        }
        CaptchaConfig::HCaptcha(options) => form_body(
            config.secret_key(),
            response,
            options.site_key.as_deref(),
            remote_ip,
            "remoteip",
        ),
        CaptchaConfig::CaptchaFox(options) => form_body(
            config.secret_key(),
            response,
            options.site_key.as_deref(),
            remote_ip,
            "remoteIp",
        ),
    };
    ProviderRequest { url, body }
}

fn form_body(
    secret: &str,
    response: &str,
    site_key: Option<&str>,
    remote_ip: Option<&str>,
    remote_name: &str,
) -> ProviderBody {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("secret", secret)
        .append_pair("response", response);
    if let Some(site_key) = site_key.filter(|value| !value.is_empty()) {
        serializer.append_pair("sitekey", site_key);
    }
    if let Some(remote_ip) = remote_ip.filter(|value| !value.is_empty()) {
        serializer.append_pair(remote_name, remote_ip);
    }
    ProviderBody::Form(serializer.finish())
}

async fn fetch(request: ProviderRequest) -> Result<Value, VerifyError> {
    let client = reqwest::Client::new();
    let builder = match request.body {
        ProviderBody::Json(body) => client
            .post(request.url)
            .header(header::CONTENT_TYPE.as_str(), "application/json")
            .body(body),
        ProviderBody::Form(body) => client
            .post(request.url)
            .header(
                header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(body),
    };
    let response = tokio::time::timeout(VERIFY_TIMEOUT, async {
        let response = builder.send().await.map_err(|_| VerifyError::Unavailable)?;
        if !response.status().is_success() {
            return Err(VerifyError::Unavailable);
        }
        response.text().await.map_err(|_| VerifyError::Unavailable)
    })
    .await
    .map_err(|_| VerifyError::Timeout)??;
    Ok(serde_json::from_str(&response).unwrap_or(Value::String(response)))
}

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("CAPTCHA service unavailable")]
    Unavailable,
    #[error("CAPTCHA service request timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CaptchaFoxOptions, CloudflareTurnstileOptions, GoogleRecaptchaOptions, HCaptchaOptions,
    };
    use serde_json::json;

    #[test]
    fn provider_requests_have_exact_urls_encodings_and_field_names() {
        let cases = [
            CaptchaConfig::CloudflareTurnstile(CloudflareTurnstileOptions::new("s +&")),
            CaptchaConfig::GoogleRecaptcha(GoogleRecaptchaOptions::new("s +&")),
            CaptchaConfig::HCaptcha({
                let mut o = HCaptchaOptions::new("s +&");
                o.site_key = Some("site +&".into());
                o
            }),
            CaptchaConfig::CaptchaFox({
                let mut o = CaptchaFoxOptions::new("s +&");
                o.site_key = Some("site +&".into());
                o
            }),
        ];
        let expected = [
            (
                TURNSTILE_URL,
                "{\"secret\":\"s +&\",\"response\":\"t +&\",\"remoteip\":\"203.0.113.9\"}",
            ),
            (
                RECAPTCHA_URL,
                "secret=s+%2B%26&response=t+%2B%26&remoteip=203.0.113.9",
            ),
            (
                HCAPTCHA_URL,
                "secret=s+%2B%26&response=t+%2B%26&sitekey=site+%2B%26&remoteip=203.0.113.9",
            ),
            (
                CAPTCHAFOX_URL,
                "secret=s+%2B%26&response=t+%2B%26&sitekey=site+%2B%26&remoteIp=203.0.113.9",
            ),
        ];
        for (config, (url, body)) in cases.iter().zip(expected) {
            let request = provider_request(config, "t +&", Some("203.0.113.9"));
            assert_eq!(request.url, url);
            match request.body {
                ProviderBody::Json(actual) | ProviderBody::Form(actual) => assert_eq!(actual, body),
            }
        }
    }

    #[test]
    fn response_constraints_and_js_truthiness_match_runtime() {
        assert!(js_truthy(&json!({})));
        assert!(js_truthy(&json!([])));
        assert!(!js_truthy(&Value::Null));
        assert!(js_truthy(&json!("false")));
        let mut google = GoogleRecaptchaOptions::new("secret");
        google.expected_action = Some("login".into());
        google.allowed_hostnames = Some(vec!["example.com".into()]);
        let config = CaptchaConfig::GoogleRecaptcha(google);
        assert!(provider_constraints_match(
            &config,
            &json!({"score": 0.5, "action": "login", "hostname": "example.com"})
        ));
        assert!(!provider_constraints_match(
            &config,
            &json!({"score": 0.49, "action": "login", "hostname": "example.com"})
        ));
        let mut nan_threshold = GoogleRecaptchaOptions::new("secret");
        nan_threshold.min_score = Some(f64::NAN);
        assert!(provider_constraints_match(
            &CaptchaConfig::GoogleRecaptcha(nan_threshold),
            &json!({"score": 0.0})
        ));
    }

    #[test]
    fn error_response_is_the_direct_middleware_wire_shape() {
        let response = error_response(CaptchaError::MissingResponse);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain;charset=UTF-8"
        );
    }
}
