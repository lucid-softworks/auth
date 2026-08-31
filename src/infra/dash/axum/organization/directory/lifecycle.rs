use super::{claims, managed, store};
use crate::{AuthService, DashPlugin};
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EventsQuery {
    limit: Option<f64>,
    offset: Option<f64>,
    sort_direction: Option<String>,
}

pub(crate) async fn rotate(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id)): Path<(String, String)>,
    Json(body): Json<managed::RotateBody>,
) -> Response {
    let (scim, claims) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (scopes, expires_at) = match managed::policy(body.scopes, body.expires_at) {
        Ok(policy) => policy,
        Err(response) => return response,
    };
    let row = match active_directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    let updated = match store::touch_active(service.database_store(), &row, &claims.actor_id).await {
        Ok(row) => row,
        Err(error) => return conflict(error),
    };
    let connection_id = updated.connection_id.as_deref().expect("active directory is bound");
    match scim
        .rotate_managed_credential(
            connection_id,
            &updated.provisioning_domain_id,
            claims.actor_id.trim(),
            scopes,
            expires_at,
        )
        .await
    {
        Ok((_, credential, token)) => managed::secured(
            Json(json!({
                "connectionId": connection_id,
                "credential": credential,
                "scimToken": token,
                "scimEndpoint": format!("{}/scim/v2", managed::base_url(&service).trim_end_matches('/')),
            }))
            .into_response(),
        ),
        Err(error) => managed::scim_error(error),
    }
}

pub(crate) async fn revoke(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id, credential_id)): Path<(String, String, String)>,
) -> Response {
    let (scim, claims) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let row = match active_directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    let updated = match store::touch_active(service.database_store(), &row, &claims.actor_id).await {
        Ok(row) => row,
        Err(error) => return conflict(error),
    };
    let connection_id = updated.connection_id.as_deref().expect("active directory is bound");
    match scim
        .revoke_managed_credential(
            connection_id,
            &updated.provisioning_domain_id,
            &credential_id,
            claims.actor_id.trim(),
        )
        .await
    {
        Ok(state) => Json(updated.response(&managed::base_url(&service), Some(&state))).into_response(),
        Err(error) => managed::scim_error(error),
    }
}

pub(crate) async fn events(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id)): Path<(String, String)>,
    Query(query): Query<EventsQuery>,
) -> Response {
    let (scim, _) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let row = match managed::directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    let (limit, offset, ascending) = page(&query);
    let Some(connection_id) = row.connection_id else {
        return Json(json!({"events": [], "total": 0, "limit": limit, "offset": offset})).into_response();
    };
    let mut events = match scim
        .list_managed_connection_events(&connection_id, &row.provisioning_domain_id)
        .await
    {
        Ok(events) => events,
        Err(error) => return managed::scim_error(error),
    };
    events.sort_by_key(|event| event.sequence);
    if !ascending {
        events.reverse();
    }
    let total = events.len();
    let events = events.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
    Json(json!({"events": events, "total": total, "limit": limit, "offset": offset})).into_response()
}

pub(crate) async fn decommission(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id)): Path<(String, String)>,
) -> Response {
    let (scim, claims) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut row = match managed::directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    if row.status == "decommissioned" {
        return directory_response(&service, scim, &row).await;
    }
    let Some(connection_id) = row.connection_id.clone() else {
        return conflict_message("Directory sync connection has an invalid catalog binding");
    };
    if row.status == "active" {
        row = match store::start_decommission(service.database_store(), &row, &claims.actor_id).await {
            Ok(row) => row,
            Err(error) => return conflict(error),
        };
    }
    if row.status != "decommissioning" {
        return conflict_message("Directory sync connection cannot be decommissioned");
    }
    let state = match scim
        .decommission_managed_connection(
            &connection_id,
            &row.provisioning_domain_id,
            claims.actor_id.trim(),
        )
        .await
    {
        Ok(state) => state,
        Err(error) => return managed::scim_error(error),
    };
    row = match store::finish_decommission(service.database_store(), &row, &claims.actor_id).await {
        Ok(row) => row,
        Err(error) => return conflict(error),
    };
    Json(row.response(&managed::base_url(&service), Some(&state))).into_response()
}

pub(crate) async fn unpair(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id)): Path<(String, String)>,
) -> Response {
    let (scim, claims) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let row = match managed::directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    if row.status != "decommissioned" {
        return conflict_message("Directory sync can only be unpaired after it has decommissioned");
    }
    let row = if row.pairing_enforced {
        match store::unpair(service.database_store(), &row, &claims.actor_id).await {
            Ok(row) => row,
            Err(error) => return conflict(error),
        }
    } else {
        row
    };
    directory_response(&service, scim, &row).await
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
async fn active_directory(
    service: &AuthService,
    organization_id: &str,
    provider_id: &str,
) -> Result<super::model::DirectoryRow, Response> {
    let row = managed::directory(service, organization_id, provider_id).await?;
    if row.status != "active" || row.connection_id.is_none() {
        return Err(conflict_message("Directory sync connection is not active"));
    }
    Ok(row)
}

async fn directory_response(
    service: &AuthService,
    scim: &crate::ScimPlugin,
    row: &super::model::DirectoryRow,
) -> Response {
    match managed::managed_state(scim, row).await {
        Ok(state) => Json(row.response(&managed::base_url(service), state.as_ref())).into_response(),
        Err(error) => managed::scim_error(error),
    }
}

fn page(query: &EventsQuery) -> (usize, usize, bool) {
    let limit = query.limit.filter(|value| value.is_finite()).unwrap_or(10.0).floor().clamp(1.0, 100.0) as usize;
    let offset = query.offset.filter(|value| value.is_finite()).unwrap_or(0.0).floor().max(0.0) as usize;
    (limit, offset, query.sort_direction.as_deref() == Some("asc"))
}

fn conflict(error: crate::AuthError) -> Response {
    (StatusCode::CONFLICT, Json(json!({"code": "CONFLICT", "message": error.to_string()}))).into_response()
}

fn conflict_message(message: &'static str) -> Response {
    super::super::support::error(StatusCode::CONFLICT, "CONFLICT", message)
}
