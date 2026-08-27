use super::{
    cookies,
    input::{TransferBody, TransferQuery, query, required_query_error},
};
use crate::{
    AuthService,
    axum::{body::BetterAuthBody, http::current_session_cache_first},
};
use axum::{
    Extension, Json,
    extract::RawQuery,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct TransferResponse {
    url: Option<String>,
    redirect: bool,
    electron_authorization_code: String,
}

pub(super) async fn transfer(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(options): Extension<Arc<super::ElectronOptions>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    BetterAuthBody(body): BetterAuthBody<TransferBody>,
) -> Response {
    let Some(session) = current_session_cache_first(&service, &headers).await else {
        return crate::axum::api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let query = match query::<TransferQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(()) => return required_query_error("client_id"),
    };
    if query.client_id != options.client_id {
        return electron_error("INVALID_CLIENT_ID", "Invalid client ID");
    }
    if query.state.is_empty() {
        return electron_error("MISSING_STATE", "state is required");
    }
    if query.code_challenge.is_empty() {
        return electron_error("MISSING_PKCE", "pkce is required");
    }
    let issued = match crate::electron::transfer::issue(
        &service,
        &options,
        &session.user.id,
        &query.state,
        &query.code_challenge,
    )
    .await
    {
        Ok(issued) => issued,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let url = body.callback_url.filter(|value| !value.is_empty());
    let response = Json(TransferResponse {
        redirect: url.is_some(),
        url,
        electron_authorization_code: issued.identifier,
    })
    .into_response();
    cookies::set_redirect(&service, &options, &issued.redirect_token, response)
}

fn electron_error(code: &'static str, message: &'static str) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, code, message)
}
