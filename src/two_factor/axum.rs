pub(crate) use super::http::two_factor_error;
use super::http::{
    challenge_verification_error, expire_plugin_cookie, set_plugin_cookie, verification_error,
};
use crate::{
    AuthError, AuthService, AxumPluginRoute, SessionWithUser,
    axum::http::{auth_error, session_token, signed_cookie_token, with_bound_session_cookie},
    protocol::better_auth::{BetterAuthUser, StatusResponse},
    service::{BackupCodeVerification, TwoFactorEnableResult, TwoFactorVerification},
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
pub(crate) use sign_in::finish_password_sign_in;
use std::sync::Arc;

mod sign_in;

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
        Ok(result) => enable_response(&service, &headers, &session.user.id, result).await,
        Err(error) => auth_error(error),
    }
}

async fn enable_response(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: &str,
    result: TwoFactorEnableResult,
) -> Response {
    let response = Json(EnableResponse {
        method: result.method,
        totp_uri: result.totp_uri,
        backup_codes: result.backup_codes,
    });
    match result.replacement_session {
        Some(replacement) => {
            with_bound_session_cookie(
                service,
                headers,
                user_id,
                &replacement.token,
                Some(true),
                response,
            )
            .await
        }
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
            let response = with_bound_session_cookie(
                &service,
                &headers,
                &session.user.id,
                &replacement.token,
                Some(true),
                Json(StatusResponse { status: true }),
            )
            .await;
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
        Ok(result) => verification_response(&service, &headers, result).await,
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
        Ok(result) => verification_response(&service, &headers, result).await,
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
        Ok(result) => backup_verification_response(&service, &headers, result).await,
        Err(error) => challenge_verification_error(&service, error),
    }
}

#[derive(Serialize)]
struct VerificationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    user: BetterAuthUser,
}

async fn verification_response(
    service: &AuthService,
    headers: &HeaderMap,
    result: TwoFactorVerification,
) -> Response {
    let user_id = result.result.session.user.id.clone();
    let user = match service.better_auth_user(&result.result.session.user).await {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    let response = Json(VerificationResponse {
        token: Some(result.result.token.clone()),
        user,
    });
    let mut response = with_bound_session_cookie(
        service,
        headers,
        &user_id,
        &result.result.token,
        result.remember_me,
        response,
    )
    .await;
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
    headers: &HeaderMap,
    result: BackupCodeVerification,
) -> Response {
    if let Some(completed) = result.completed {
        return verification_response(service, headers, completed).await;
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
