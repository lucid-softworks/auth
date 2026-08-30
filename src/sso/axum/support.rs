use crate::{AuthService, SessionWithUser, SsoPlugin, SsoProvider};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;

pub(super) async fn required_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Box<Response>> {
    crate::axum::http::current_session(service, headers)
        .await
        .ok_or_else(|| Box::new(error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")))
}

pub(super) fn error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error_with_body(
        status,
        json!({"code": code, "message": message.into()}),
    )
}

pub(super) fn storage(error: super::super::SsoStoreError) -> Response {
    tracing::error!(error = %error, "SSO provider storage failed");
    self::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Failed to read SSO providers",
    )
}

pub(super) async fn has_access(
    service: &AuthService,
    provider: &SsoProvider,
    user_id: &str,
) -> bool {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        return provider.user_id == user_id;
    };
    let Ok(organization) = service.organization_plugin() else {
        return provider.user_id == user_id;
    };
    organization
        .store
        .find_member(organization_id, user_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|member| {
            member
                .role
                .split(',')
                .any(|role| matches!(role.trim(), "owner" | "admin"))
        })
}

pub(super) fn base_url(service: &AuthService) -> String {
    service
        .auth_base_url()
        .map(|url| url.to_string().trim_end_matches('/').to_owned())
        .unwrap_or_else(|| service.base_path().trim_end_matches('/').to_owned())
}

pub(super) fn oidc_redirect_uri(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider_id: &str,
) -> String {
    let Some(configured) = plugin
        .options()
        .redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return format!("{}/sso/callback/{provider_id}", base_url(service));
    };
    if url::Url::parse(configured).is_ok() {
        return configured.to_owned();
    }
    format!(
        "{}/{}",
        base_url(service),
        configured.trim_start_matches('/')
    )
}

pub(super) async fn authorized_provider(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
) -> Result<(SessionWithUser, SsoProvider), Box<Response>> {
    let session = required_session(service, headers).await?;
    let provider = plugin
        .store()
        .find_by_provider_id(provider_id)
        .await
        .map_err(|error| Box::new(storage(error)))?
        .ok_or_else(|| {
            Box::new(self::error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Provider not found",
            ))
        })?;
    if !has_access(service, &provider, &session.user.id).await {
        return Err(Box::new(self::error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "You don't have access to this provider",
        )));
    }
    Ok((session, provider))
}
