use super::ApiKeyConfiguration;
use super::{
    http_input::{
        CreateRequest, DeleteRequest, GetRequest, ListRequest, VerifyRequest, client_update,
        resolve_configuration, valid_prefix,
    },
    http_response,
};
use crate::{
    ApiKeyError, ApiKeySortDirection, AuthError, AuthService, AxumPluginRoute, NewApiKey,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn routes(
    _service: Arc<AuthService>,
    configurations: Arc<Vec<ApiKeyConfiguration>>,
) -> Vec<AxumPluginRoute> {
    vec![
        route("/api-key/create", post(create), configurations.clone()),
        route("/api-key/get", get(get_one), configurations.clone()),
        route("/api-key/list", get(list), configurations.clone()),
        route("/api-key/update", post(update), configurations.clone()),
        route("/api-key/delete", post(delete), configurations.clone()),
        route("/api-key/verify", post(verify), configurations.clone()),
        route(
            "/api-key/delete-all-expired-api-keys",
            post(delete_expired),
            configurations,
        ),
    ]
}

fn route(
    path: &'static str,
    route: axum::routing::MethodRouter,
    configurations: Arc<Vec<ApiKeyConfiguration>>,
) -> AxumPluginRoute {
    AxumPluginRoute::new(path, route.layer(Extension(configurations)))
}

async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(configurations): Extension<Arc<Vec<ApiKeyConfiguration>>>,
    headers: HeaderMap,
    Json(input): Json<CreateRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    };
    if input.user_id.is_some() {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    }
    if input.contains_server_only_property() {
        return auth_error(ApiKeyError::ServerOnlyProperty.into());
    }
    if input
        .prefix
        .as_deref()
        .is_some_and(|prefix| !valid_prefix(prefix))
    {
        return auth_error(AuthError::InvalidRequest(
            "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."
                .into(),
        ));
    }
    let config = resolve_configuration(&configurations, input.config_id.as_deref());
    let expires_at = input
        .expires_in
        .map(|seconds| Utc::now() + Duration::seconds(seconds));
    let request = NewApiKey {
        config_id: config.config_id.clone(),
        name: input.name,
        prefix: input.prefix,
        expires_at,
        permissions: None,
        metadata: input.metadata.filter(|value| !value.is_null()),
        remaining: None,
        refill_amount: None,
        refill_interval: None,
        rate_limit_enabled: config.rate_limit.enabled,
        rate_limit_time_window: Some(config.rate_limit.time_window_milliseconds),
        rate_limit_max: Some(config.rate_limit.max_requests),
    };
    let result = if config.reference == crate::ApiKeyReference::Organization {
        let Some(organization_id) = input
            .organization_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            return auth_error(ApiKeyError::OrganizationIdRequired.into());
        };
        service
            .issue_organization_api_key(&actor, config, request, organization_id)
            .await
    } else {
        service.issue_api_key(&actor, config, request).await
    };
    match result {
        Ok(issued) => http_response::issued(issued.api_key, issued.key),
        Err(error) => auth_error(error),
    }
}

async fn get_one(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(configurations): Extension<Arc<Vec<ApiKeyConfiguration>>>,
    headers: HeaderMap,
    Query(input): Query<GetRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    };
    let Ok(id) = Uuid::parse_str(&input.id) else {
        return auth_error(ApiKeyError::NotFound.into());
    };
    let config = resolve_configuration(&configurations, input.config_id.as_deref());
    match service.get_api_key(&actor, config, id).await {
        Ok(api_key) => Json(api_key).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(input): Query<ListRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    };
    let direction = match input.sort_direction.as_deref() {
        Some("desc") => ApiKeySortDirection::Descending,
        Some("asc") | None => ApiKeySortDirection::Ascending,
        Some(_) => return auth_error(AuthError::InvalidRequest("invalid sortDirection".into())),
    };
    let result = match input.organization_id.as_deref() {
        Some(id) => match Uuid::parse_str(id) {
            Ok(id) => {
                service
                    .list_organization_api_keys(
                        &actor,
                        input.config_id.as_deref(),
                        input.sort_by.as_deref(),
                        direction,
                        id,
                    )
                    .await
            }
            Err(_) => Err(ApiKeyError::UserNotOrganizationMember.into()),
        },
        None => {
            service
                .list_api_keys(
                    &actor,
                    input.config_id.as_deref(),
                    input.sort_by.as_deref(),
                    direction,
                )
                .await
        }
    };
    match result {
        Ok(api_keys) => {
            let total = api_keys.len();
            let offset = input.offset.unwrap_or(0);
            let api_keys = api_keys
                .into_iter()
                .skip(offset)
                .take(input.limit.unwrap_or(usize::MAX))
                .collect::<Vec<_>>();
            http_response::list(api_keys, total, input.limit, input.offset)
        }
        Err(error) => auth_error(error),
    }
}

async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(configurations): Extension<Arc<Vec<ApiKeyConfiguration>>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    };
    if input.get("userId").is_some() {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    }
    if [
        "remaining",
        "refillAmount",
        "refillInterval",
        "rateLimitEnabled",
        "rateLimitTimeWindow",
        "rateLimitMax",
        "permissions",
    ]
    .iter()
    .any(|field| input.get(field).is_some())
    {
        return auth_error(ApiKeyError::ServerOnlyProperty.into());
    }
    let Some(key_id) = input.get("keyId").and_then(Value::as_str) else {
        return auth_error(ApiKeyError::NotFound.into());
    };
    let Ok(key_id) = Uuid::parse_str(key_id) else {
        return auth_error(ApiKeyError::NotFound.into());
    };
    let config_id = input.get("configId").and_then(Value::as_str);
    let config = resolve_configuration(&configurations, config_id);
    let update = match client_update(&input, config) {
        Ok(update) => update,
        Err(error) => return auth_error(error),
    };
    match service.update_api_key(&actor, config, key_id, update).await {
        Ok(api_key) => Json(api_key).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(configurations): Extension<Arc<Vec<ApiKeyConfiguration>>>,
    headers: HeaderMap,
    Json(input): Json<DeleteRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(ApiKeyError::UnauthorizedSession.into());
    };
    let Ok(key_id) = Uuid::parse_str(&input.key_id) else {
        return auth_error(ApiKeyError::NotFound.into());
    };
    let config = resolve_configuration(&configurations, input.config_id.as_deref());
    match service.delete_api_key(&actor, config, key_id).await {
        Ok(()) => Json(json!({ "success": true })).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(configurations): Extension<Arc<Vec<ApiKeyConfiguration>>>,
    Json(input): Json<VerifyRequest>,
) -> Response {
    match service
        .verify_api_key(
            &input.key,
            &configurations,
            input.config_id.as_deref(),
            input.permissions.as_ref(),
        )
        .await
    {
        Ok(verified) => Json(json!({
            "valid": true,
            "error": null,
            "key": verified.api_key,
        }))
        .into_response(),
        Err(AuthError::ApiKey(error)) => http_response::invalid_verification(error),
        Err(_) => http_response::invalid_verification(ApiKeyError::Invalid),
    }
}

async fn delete_expired(Extension(service): Extension<Arc<AuthService>>) -> Response {
    match service.delete_expired_api_keys().await {
        Ok(_) => Json(json!({ "success": true, "error": null })).into_response(),
        Err(error) => auth_error(error),
    }
}
