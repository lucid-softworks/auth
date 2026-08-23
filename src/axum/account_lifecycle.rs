use super::http::{auth_error, current_session, serialize_cookie, with_cookie};
use crate::{AuthError, AuthService, SocialSignInInput, SocialSignInResult};
use axum::{
    Extension, Json, Router,
    extract::Query,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/list-accounts", get(list_accounts))
        .route("/link-social", post(link_social))
        .route("/unlink-account", post(unlink_account))
        .route("/get-access-token", post(get_access_token))
        .route("/refresh-token", post(refresh_token))
        .route("/account-info", get(account_info))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInput {
    account_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountSelection {
    account_id: Option<String>,
    use_account_cookie: Option<bool>,
    user_id: Option<String>,
}

#[derive(Serialize)]
struct LinkStatus {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<bool>,
    redirect: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    status: bool,
}

async fn list_accounts(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.list_linked_accounts(&actor).await {
        Ok(accounts) => Json(accounts).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn link_social(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    super::body::BetterAuthBody(input): super::body::BetterAuthBody<SocialSignInInput>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.link_social_account(&actor, input).await {
        Ok(SocialSignInResult::Authorization {
            url,
            redirect,
            state,
        }) => {
            let mut response = Json(LinkStatus {
                url: url.clone(),
                status: None,
                redirect,
            })
            .into_response();
            if redirect && let Ok(location) = HeaderValue::from_str(&url) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            let cookie = service.plugin_cookie("state");
            with_cookie(
                response,
                serialize_cookie(&cookie, &service.signed_cookie_value(&state), Some(300)),
            )
        }
        Ok(SocialSignInResult::Linked) => Json(LinkStatus {
            url: String::new(),
            status: Some(true),
            redirect: false,
        })
        .into_response(),
        Ok(SocialSignInResult::Session(_)) => auth_error(AuthError::InvalidRequest(
            "session response is invalid for account linking".into(),
        )),
        Err(error) => auth_error(error),
    }
}

async fn unlink_account(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    super::body::BetterAuthBody(input): super::body::BetterAuthBody<AccountInput>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let account_id = match Uuid::parse_str(&input.account_id) {
        Ok(id) => id,
        Err(_) => return auth_error(AuthError::AccountNotFound),
    };
    match service.unlink_account(&actor, account_id).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn get_access_token(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    super::body::BetterAuthBody(input): super::body::BetterAuthBody<AccountSelection>,
) -> Response {
    account_token_response(&service, &headers, input, false).await
}

async fn refresh_token(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    super::body::BetterAuthBody(input): super::body::BetterAuthBody<AccountSelection>,
) -> Response {
    account_token_response(&service, &headers, input, true).await
}

async fn account_token_response(
    service: &AuthService,
    headers: &HeaderMap,
    input: AccountSelection,
    refresh: bool,
) -> Response {
    let Some(actor) = current_session(service, headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let account_id = match selected_account_id(&input) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let result = if refresh {
        service
            .refresh_provider_access_token(&actor, account_id)
            .await
    } else {
        service.get_provider_access_token(&actor, account_id).await
    };
    match result {
        Ok(tokens) => Json(tokens).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn account_info(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(input): Query<AccountSelection>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let account_id = match selected_account_id(&input) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service.provider_account_info(&actor, account_id).await {
        Ok(info) => Json(info).into_response(),
        Err(error) => auth_error(error),
    }
}

fn selected_account_id(input: &AccountSelection) -> Result<Uuid, AuthError> {
    let _ = (&input.use_account_cookie, &input.user_id);
    input
        .account_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or(AuthError::AccountNotFound)
}
