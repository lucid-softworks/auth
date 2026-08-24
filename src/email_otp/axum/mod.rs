mod account;
mod change_email;
mod verification;

use super::{EmailOtpConfig, EmailOtpRequestContext, EmailOtpType};
use crate::{AuthError, AuthService, AxumPluginRoute, axum::http::PeerAddress};
use axum::{
    Extension,
    http::{HeaderMap, header},
    routing::post,
};
use serde::Serialize;
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<EmailOtpConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        route("/email-otp/send-verification-otp", post(verification::send)),
        route(
            "/email-otp/check-verification-otp",
            post(verification::check),
        ),
        route("/email-otp/verify-email", post(verification::verify)),
        route("/sign-in/email-otp", post(account::sign_in)),
        route(
            "/email-otp/request-password-reset",
            post(account::request_reset),
        ),
        route("/forget-password/email-otp", post(account::request_reset)),
        route("/email-otp/reset-password", post(account::reset)),
        route(
            "/email-otp/request-email-change",
            post(change_email::request),
        ),
        route("/email-otp/change-email", post(change_email::change)),
    ]
    .into_iter()
    .map(|route| route.with_extension(config.clone()))
    .collect()
}

struct RouteWithExtension(AxumPluginRoute);

impl RouteWithExtension {
    fn with_extension(self, config: Arc<EmailOtpConfig>) -> AxumPluginRoute {
        let (path, route) = self.0.into_parts();
        AxumPluginRoute::new(path, route.layer(Extension(config)))
    }
}

fn route(path: &'static str, route: axum::routing::MethodRouter) -> RouteWithExtension {
    RouteWithExtension(AxumPluginRoute::new(path, route))
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

fn success() -> SuccessResponse {
    SuccessResponse { success: true }
}

fn parse_type(value: &str) -> Result<EmailOtpType, AuthError> {
    match value {
        "email-verification" => Ok(EmailOtpType::EmailVerification),
        "sign-in" => Ok(EmailOtpType::SignIn),
        "forget-password" => Ok(EmailOtpType::ForgetPassword),
        "change-email" => Ok(EmailOtpType::ChangeEmail),
        _ => Err(AuthError::InvalidRequest("Invalid OTP type".into())),
    }
}

fn context(
    service: &AuthService,
    headers: &HeaderMap,
    peer: PeerAddress,
) -> EmailOtpRequestContext {
    EmailOtpRequestContext {
        origin: header_text(headers, header::ORIGIN).map(str::to_owned),
        ip_address: crate::axum::http::client_ip(service, headers, peer),
        user_agent: crate::axum::http::user_agent(headers),
    }
}

fn header_text(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
