pub(crate) use super::http::two_factor_error;
use super::http::{
    challenge_verification_error, expire_plugin_cookie, set_plugin_cookie, verification_error,
};
use crate::{
    AuthError, AuthService, AxumPluginRoute, SessionWithUser,
    axum::http::{
        auth_error, clear_session_cookie, session_token, signed_cookie_token, with_session_cookie,
    },
    protocol::better_auth::{BetterAuthUser, StatusResponse},
    service::{
        BackupCodeVerification, TwoFactorEnableResult, TwoFactorSignInOutcome,
        TwoFactorVerification,
    },
};
use axum::{
    Extension, Json,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) fn routes(_service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
    vec![
        route("/two-factor/enable", enable),
        route("/two-factor/disable", disable),
        route("/two-factor/get-totp-uri", get_totp_uri),
        route("/two-factor/verify-totp", verify_totp),
        route("/two-factor/send-otp", send_otp),
        route("/two-factor/verify-otp", verify_otp),
        route("/two-factor/generate-backup-codes", generate_backup_codes),
        route("/two-factor/verify-backup-code", verify_backup_code),
    ]
}

fn route<H, T>(path: &'static str, handler: H) -> AxumPluginRoute
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    AxumPluginRoute::new(path, post(handler))
}

#[derive(Deserialize)]
struct EnableRequest {
    password: Option<String>,
    method: Option<String>,
    issuer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnableResponse {
    method: &'static str,
    #[serde(rename = "totpURI")]
    #[serde(skip_serializing_if = "Option::is_none")]
    totp_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_codes: Option<Vec<String>>,
}

async fn enable(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<EnableRequest>,
) -> Response {
    let Some((session, token)) = active_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match input.method.as_deref().unwrap_or("totp") {
        "totp" => {
            service
                .enable_two_factor_totp(&session, &token, input.password, input.issuer)
                .await
        }
        "otp" => {
            service
                .enable_two_factor_otp(&session, &token, input.password)
                .await
        }
        _ => Err(AuthError::InvalidRequest(
            "method must be otp or totp".into(),
        )),
    };
    match result {
        Ok(result) => enable_response(&service, result),
        Err(error) => auth_error(error),
    }
}

fn enable_response(service: &AuthService, result: TwoFactorEnableResult) -> Response {
    let response = Json(EnableResponse {
        method: result.method,
        totp_uri: result.totp_uri,
        backup_codes: result.backup_codes,
    });
    match result.replacement_session {
        Some(replacement) => with_session_cookie(service, &replacement.token, Some(true), response),
        None => response.into_response(),
    }
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: Option<String>,
}

async fn disable(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<PasswordRequest>,
) -> Response {
    let Some((session, token)) = active_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let trust_cookie = service.plugin_cookie("trust_device");
    let trust_value = signed_cookie_token(&service, &headers, &trust_cookie.name);
    match service
        .disable_two_factor(&session, &token, input.password, trust_value.as_deref())
        .await
    {
        Ok(replacement) => {
            let response = with_session_cookie(
                &service,
                &replacement.token,
                Some(true),
                Json(StatusResponse { status: true }),
            );
            expire_plugin_cookie(&service, "trust_device", response)
        }
        Err(error) => auth_error(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpUriResponse {
    #[serde(rename = "totpURI")]
    totp_uri: String,
}

async fn get_totp_uri(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<PasswordRequest>,
) -> Response {
    let Some((session, _)) = active_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .get_two_factor_totp_uri(&session, input.password)
        .await
    {
        Ok(totp_uri) => Json(TotpUriResponse { totp_uri }).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyCodeRequest {
    code: String,
    trust_device: Option<bool>,
}

async fn verify_totp(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyCodeRequest>,
) -> Response {
    let (active, challenge) = verification_auth(&service, &headers).await;
    match service
        .verify_two_factor_totp(
            active,
            challenge,
            &input.code,
            input.trust_device.unwrap_or(false),
        )
        .await
    {
        Ok(result) => verification_response(&service, result).await,
        Err(error) => challenge_verification_error(&service, error),
    }
}

async fn send_otp(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    _body: Option<Json<serde_json::Value>>,
) -> Response {
    let (active, challenge) = verification_auth(&service, &headers).await;
    match service.send_two_factor_otp(active, challenge).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn verify_otp(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyCodeRequest>,
) -> Response {
    let (active, challenge) = verification_auth(&service, &headers).await;
    match service
        .verify_two_factor_otp(
            active,
            challenge,
            &input.code,
            input.trust_device.unwrap_or(false),
        )
        .await
    {
        Ok(result) => verification_response(&service, result).await,
        Err(error) => verification_error(&service, error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupCodesResponse {
    status: bool,
    backup_codes: Vec<String>,
}

async fn generate_backup_codes(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<PasswordRequest>,
) -> Response {
    let Some((session, _)) = active_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .generate_two_factor_backup_codes(&session, input.password)
        .await
    {
        Ok(backup_codes) => Json(BackupCodesResponse {
            status: true,
            backup_codes,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBackupCodeRequest {
    code: String,
    disable_session: Option<bool>,
    trust_device: Option<bool>,
}

async fn verify_backup_code(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyBackupCodeRequest>,
) -> Response {
    let (active, challenge) = verification_auth(&service, &headers).await;
    match service
        .verify_two_factor_backup_code(
            active,
            challenge,
            &input.code,
            input.disable_session.unwrap_or(false),
            input.trust_device.unwrap_or(false),
        )
        .await
    {
        Ok(result) => backup_verification_response(&service, result).await,
        Err(error) => challenge_verification_error(&service, error),
    }
}

#[derive(Serialize)]
struct VerificationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    user: BetterAuthUser,
}

async fn verification_response(service: &AuthService, result: TwoFactorVerification) -> Response {
    let user = match service.better_auth_user(&result.result.session.user).await {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    let response = Json(VerificationResponse {
        token: Some(result.result.token.clone()),
        user,
    });
    let mut response =
        with_session_cookie(service, &result.result.token, result.remember_me, response);
    response = expire_plugin_cookie(service, "two_factor", response);
    if let Some(trust_cookie) = result.trust_cookie {
        response = set_plugin_cookie(
            service,
            "trust_device",
            &trust_cookie,
            service
                .two_factor_plugin()
                .expect("validated plugin")
                .config
                .trust_device_ttl
                .num_seconds(),
            response,
        );
    }
    response
}

async fn backup_verification_response(
    service: &AuthService,
    result: BackupCodeVerification,
) -> Response {
    if let Some(completed) = result.completed {
        return verification_response(service, completed).await;
    }
    match service.better_auth_user(&result.user).await {
        Ok(user) => Json(VerificationResponse {
            token: result.token,
            user,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn active_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<(SessionWithUser, String)> {
    let token = session_token(service, headers)?;
    let session = service.session(&token).await.ok().flatten()?;
    Some((session, token))
}

async fn verification_auth(
    service: &AuthService,
    headers: &HeaderMap,
) -> (Option<(SessionWithUser, String)>, Option<String>) {
    let active = active_session(service, headers).await;
    let cookie = service.plugin_cookie("two_factor");
    let challenge = signed_cookie_token(service, headers, &cookie.name);
    (active, challenge)
}

pub(crate) async fn finish_password_sign_in(
    service: &AuthService,
    headers: &HeaderMap,
    result: crate::SignInResult,
    remember_me: Option<bool>,
    callback_url: Option<String>,
) -> Response {
    let trust_cookie = service.plugin_cookie("trust_device");
    let trust_value = signed_cookie_token(service, headers, &trust_cookie.name);
    match service
        .begin_two_factor_sign_in(result, remember_me, trust_value.as_deref())
        .await
    {
        Ok(TwoFactorSignInOutcome::Continue {
            result,
            rotated_trust_cookie,
        }) => {
            let result = *result;
            let token = result.token.clone();
            let body =
                match crate::axum::sign_in_response(service, result, callback_url.clone()).await {
                    Ok(body) => body,
                    Err(error) => return auth_error(error),
                };
            let mut response = with_session_cookie(service, &token, remember_me, Json(body));
            if let Some(rotated) = rotated_trust_cookie {
                let max_age = service
                    .two_factor_plugin()
                    .expect("validated plugin")
                    .config
                    .trust_device_ttl
                    .num_seconds();
                response = set_plugin_cookie(service, "trust_device", &rotated, max_age, response);
            }
            if let Some(callback_url) = callback_url
                && let Ok(location) = HeaderValue::from_str(&callback_url)
            {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        }
        Ok(TwoFactorSignInOutcome::Challenge {
            identifier,
            methods,
            max_age_seconds,
        }) => {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct ChallengeResponse {
                two_factor_redirect: bool,
                two_factor_methods: Vec<String>,
            }
            let response = clear_session_cookie(
                service,
                Json(ChallengeResponse {
                    two_factor_redirect: true,
                    two_factor_methods: methods,
                }),
            );
            let response = set_plugin_cookie(
                service,
                "two_factor",
                &identifier,
                max_age_seconds,
                response,
            );
            if trust_value.is_some() {
                expire_plugin_cookie(service, "trust_device", response)
            } else {
                response
            }
        }
        Err(error) => auth_error(error),
    }
}
