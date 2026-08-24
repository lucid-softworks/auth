use super::http::{
    account_data_cookie, auth_error, clear_account_cookie, current_session, serialize_cookie,
    with_account_cookie, with_cookie,
};
use crate::{AuthError, AuthService, OAuthAccount, SocialSignInInput, SocialSignInResult};
use axum::{
    Extension, Json, Router,
    extract::{OriginalUri, Query},
    http::{HeaderMap, HeaderValue, Method, Uri, header},
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
#[serde(deny_unknown_fields)]
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
    let provider_id = input.provider.clone();
    match service.link_social_account(&actor, input).await {
        Ok(SocialSignInResult::Authorization {
            url,
            redirect,
            state_cookie_name,
            state_cookie_value,
            state_cookie_max_age,
            ..
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
            let cookie = service.plugin_cookie(state_cookie_name);
            with_cookie(
                response,
                serialize_cookie(&cookie, &state_cookie_value, Some(state_cookie_max_age)),
            )
        }
        Ok(SocialSignInResult::Linked) => {
            let response = Json(LinkStatus {
                url: String::new(),
                status: Some(true),
                redirect: false,
            })
            .into_response();
            match service
                .account_cookie_for_provider(actor.user.id, &provider_id)
                .await
            {
                Ok(Some(account)) => with_account_cookie(&service, &headers, account, response),
                Ok(None) => response,
                Err(error) => auth_error(error),
            }
        }
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
    account_token_response(&service, &headers, input, false, None).await
}

async fn refresh_token(
    Extension(service): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    super::body::BetterAuthBody(input): super::body::BetterAuthBody<AccountSelection>,
) -> Response {
    account_token_response(&service, &headers, input, true, Some((&method, &uri))).await
}

async fn account_token_response(
    service: &AuthService,
    headers: &HeaderMap,
    input: AccountSelection,
    refresh: bool,
    request: Option<(&Method, &Uri)>,
) -> Response {
    let Some(actor) = current_session(service, headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let selected = match selected_account(service, headers, &actor, &input) {
        Ok(selected) => selected,
        Err(error) => return account_selection_error(service, headers, &input, error),
    };
    let from_cookie = matches!(selected, SelectedAccount::Cookie(_));
    let selected_id = match &selected {
        SelectedAccount::Database(account_id) => *account_id,
        SelectedAccount::Cookie(account) => account.id,
    };
    let result = match (refresh, selected) {
        (true, SelectedAccount::Database(account_id)) => {
            let context = refresh_context(headers, request);
            service
                .refresh_provider_access_token_with_context(&actor, account_id, &context)
                .await
        }
        (false, SelectedAccount::Database(account_id)) => {
            service.get_provider_access_token(&actor, account_id).await
        }
        (true, SelectedAccount::Cookie(account)) => {
            let context = refresh_context(headers, request);
            service
                .refresh_provider_access_token_from_cookie_with_context(&actor, *account, &context)
                .await
        }
        (false, SelectedAccount::Cookie(account)) => {
            service
                .get_provider_access_token_from_cookie(&actor, *account)
                .await
        }
    };
    match result {
        Ok(tokens) => {
            let refreshed_id = tokens.account_id;
            let response = Json(tokens).into_response();
            let should_update_cookie = refreshed_id.is_some()
                && (!refresh
                    || from_cookie
                    || selected_cookie_matches(service, headers, actor.user.id, selected_id));
            refresh_selected_account_cookie(
                service,
                headers,
                actor.user.id,
                should_update_cookie.then_some(selected_id),
                response,
            )
            .await
        }
        Err(error) if from_cookie => {
            clear_account_cookie(service, Some(headers), auth_error(error))
        }
        Err(error) => auth_error(error),
    }
}

fn refresh_context(
    headers: &HeaderMap,
    request: Option<(&Method, &Uri)>,
) -> crate::OAuthRefreshContext {
    crate::OAuthRefreshContext {
        request: request.map(|(method, uri)| crate::OAuthRequestContext {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
        }),
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
    let selected = match selected_account(&service, &headers, &actor, &input) {
        Ok(selected) => selected,
        Err(error) => return account_selection_error(&service, &headers, &input, error),
    };
    let from_cookie = matches!(selected, SelectedAccount::Cookie(_));
    let (account_id, needs_refresh, result) = match selected {
        SelectedAccount::Database(account_id) => {
            let needs_refresh = if service.account_cookie_enabled() {
                match service
                    .account_cookie_for_id(actor.user.id, account_id)
                    .await
                {
                    Ok(Some(account)) => account_needs_refresh(&account),
                    Ok(None) => false,
                    Err(error) => return auth_error(error),
                }
            } else {
                false
            };
            (
                account_id,
                needs_refresh,
                service.provider_account_info(&actor, account_id).await,
            )
        }
        SelectedAccount::Cookie(account) => {
            let needs_refresh = account_needs_refresh(&account);
            let account_id = account.id;
            (
                account_id,
                needs_refresh,
                service
                    .provider_account_info_from_cookie(&actor, *account)
                    .await,
            )
        }
    };
    match result {
        Ok(info) => {
            let response = Json(info).into_response();
            refresh_selected_account_cookie(
                &service,
                &headers,
                actor.user.id,
                needs_refresh.then_some(account_id),
                response,
            )
            .await
        }
        Err(error) if from_cookie => {
            clear_account_cookie(&service, Some(&headers), auth_error(error))
        }
        Err(error) => auth_error(error),
    }
}

enum SelectedAccount {
    Database(Uuid),
    Cookie(Box<OAuthAccount>),
}

fn selected_account(
    service: &AuthService,
    headers: &HeaderMap,
    actor: &crate::SessionWithUser,
    input: &AccountSelection,
) -> Result<SelectedAccount, AuthError> {
    let _ = &input.user_id;
    let valid_selection = matches!(
        (&input.account_id, input.use_account_cookie),
        (Some(_), None) | (None, Some(true))
    );
    if !valid_selection {
        return Err(AuthError::InvalidRequest(
            "select exactly one of accountId or useAccountCookie: true".into(),
        ));
    }
    if let Some(account_id) = input.account_id.as_deref()
        && input.use_account_cookie.is_none()
        && let Ok(account_id) = Uuid::parse_str(account_id)
    {
        return Ok(SelectedAccount::Database(account_id));
    }
    if input.account_id.is_none()
        && input.use_account_cookie == Some(true)
        && service.account_cookie_enabled()
        && let Some(account) = account_data_cookie(service, headers)
            .and_then(|value| service.decode_account_cookie(&value))
        && account.user_id == actor.user.id
    {
        return Ok(SelectedAccount::Cookie(Box::new(account)));
    }
    Err(AuthError::AccountNotFound)
}

fn account_selection_error(
    service: &AuthService,
    headers: &HeaderMap,
    input: &AccountSelection,
    error: AuthError,
) -> Response {
    let response = auth_error(error);
    if input.use_account_cookie == Some(true) && service.account_cookie_enabled() {
        clear_account_cookie(service, Some(headers), response)
    } else {
        response
    }
}

fn selected_cookie_matches(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: Uuid,
    account_id: Uuid,
) -> bool {
    account_data_cookie(service, headers)
        .and_then(|value| service.decode_account_cookie(&value))
        .is_some_and(|account| account.user_id == user_id && account.id == account_id)
}

async fn refresh_selected_account_cookie(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: Uuid,
    account_id: Option<Uuid>,
    response: Response,
) -> Response {
    let Some(account_id) = account_id else {
        return response;
    };
    match service.account_cookie_for_id(user_id, account_id).await {
        Ok(Some(account)) => with_account_cookie(service, headers, account, response),
        Ok(None) => clear_account_cookie(service, Some(headers), response),
        Err(error) => auth_error(error),
    }
}

fn account_needs_refresh(account: &OAuthAccount) -> bool {
    account.refresh_token.is_some()
        && account
            .access_token_expires_at
            .is_some_and(|expires| expires - chrono::Utc::now() < chrono::Duration::seconds(5))
}
