use super::{claims, model::DirectoryRow, pairing, store};
use crate::{AuthService, DashPlugin, ScimError, ScimManagedCredential, ScimScope};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateBody {
    provider_id: String,
    pairing: Option<pairing::DirectoryPairing>,
    scopes: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RotateBody {
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub(crate) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Response {
    let (scim, _) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let rows = match store::list(service.database_store(), &organization_id).await {
        Ok(rows) => rows,
        Err(error) => return super::super::support::route_error(error),
    };
    let mut response = Vec::with_capacity(rows.len());
    for row in rows {
        let state = match managed_state(scim, &row).await {
            Ok(state) => state,
            Err(error) => return scim_error(error),
        };
        response.push(row.response(&base_url(&service), state.as_ref()));
    }
    Json(response).into_response()
}

pub(crate) async fn get_one(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, provider_id)): Path<(String, String)>,
) -> Response {
    let (scim, _) = match claims::authorize(&service, &dash, &headers, &organization_id, false).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let row = match directory(&service, &organization_id, &provider_id).await {
        Ok(row) => row,
        Err(response) => return response,
    };
    match managed_state(scim, &row).await {
        Ok(state) => Json(row.response(&base_url(&service), state.as_ref())).into_response(),
        Err(error) => scim_error(error),
    }
}

pub(crate) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Response {
    let (scim, claims) = match claims::authorize(&service, &dash, &headers, &organization_id, true).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = validate_provider_id(&body.provider_id) {
        return response;
    }
    let pairing = match body.pairing {
        Some(pairing) => match pairing::resolve(&service, &dash, &organization_id, pairing).await {
            Ok(pairing) => Some(pairing),
            Err(response) => return response,
        },
        None => None,
    };
    let (scopes, expires_at) = match policy(body.scopes, body.expires_at) {
        Ok(policy) => policy,
        Err(response) => return response,
    };
    let reserved = match store::reserve(
        service.database_store(),
        store::NewDirectory {
            organization_id: &organization_id,
            provider_id: body.provider_id.trim(),
            actor_id: claims.actor_id.trim(),
            creation_request_id: claims.setup_operation_id.as_deref(),
            pairing: pairing.as_ref(),
        },
    )
    .await
    {
        Ok(row) => row,
        Err(error) => return catalog_error(error),
    };
    let issued = scim
        .create_managed_connection(
            &reserved.creation_request_id,
            &reserved.provisioning_domain_id,
            claims.actor_id.trim(),
            scopes,
            expires_at,
        )
        .await;
    let (connection, credential, token) = match issued {
        Ok(value) => value,
        Err(error) => return scim_error(error),
    };
    let row = match store::bind(service.database_store(), &reserved, &connection.connection_id).await {
        Ok(row) => row,
        Err(error) => return catalog_error(error),
    };
    let state = (connection.clone(), vec![credential.clone()]);
    let mut body = row.response(&base_url(&service), Some(&state));
    let object = body.as_object_mut().expect("directory response is an object");
    object.insert("connectionId".into(), json!(connection.connection_id));
    object.insert("credential".into(), credential_value(&credential));
    object.insert("scimToken".into(), json!(token));
    secured(Json(body).into_response())
}

pub(crate) async fn legacy_unavailable() -> Response {
    super::super::support::error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "Legacy SCIM directory sync is not available with the managed SCIM plugin",
    )
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) fn policy(
    requested: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(Vec<ScimScope>, DateTime<Utc>), Response> {
    let expires_at = expires_at.unwrap_or_else(|| Utc::now() + Duration::days(365));
    if expires_at <= Utc::now() {
        return Err(bad_request("Directory sync credential expiry must be in the future"));
    }
    let values = requested.unwrap_or_else(|| {
        ScimScope::ALL
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect()
    });
    if values.is_empty() || values.iter().collect::<HashSet<_>>().len() != values.len() {
        return Err(bad_request("Directory sync credential scopes must be unique"));
    }
    let scopes = values
        .iter()
        .map(|value| scope(value).ok_or_else(|| bad_request("Invalid directory sync credential scope")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((scopes, expires_at))
}

fn scope(value: &str) -> Option<ScimScope> {
    ScimScope::ALL.into_iter().find(|scope| scope.as_str() == value)
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn directory(
    service: &AuthService,
    organization_id: &str,
    provider_id: &str,
) -> Result<DirectoryRow, Response> {
    store::get(service.database_store(), organization_id, provider_id)
        .await
        .map_err(super::super::support::route_error)?
        .ok_or_else(|| {
            super::super::support::error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Directory sync connection not found",
            )
        })
}

pub(super) async fn managed_state(
    scim: &crate::ScimPlugin,
    row: &DirectoryRow,
) -> Result<Option<(crate::ScimManagedConnection, Vec<ScimManagedCredential>)>, ScimError> {
    let Some(connection_id) = &row.connection_id else {
        return Ok(None);
    };
    scim.get_managed_connection(connection_id, &row.provisioning_domain_id)
        .await
        .map(Some)
}

pub(super) fn base_url(service: &AuthService) -> String {
    service
        .auth_base_url()
        .map(|url| url.to_string())
        .unwrap_or_else(|| service.base_path().to_owned())
}

fn credential_value(credential: &ScimManagedCredential) -> Value {
    serde_json::to_value(credential).expect("managed credentials serialize")
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
fn validate_provider_id(provider_id: &str) -> Result<(), Response> {
    if provider_id.trim().is_empty() || provider_id.trim().len() > 255 {
        return Err(bad_request("Invalid directory sync provider ID"));
    }
    Ok(())
}

pub(super) fn secured(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn catalog_error(error: crate::AuthError) -> Response {
    let message = error.to_string();
    if message.contains("already has") || message.contains("catalog binding changed") {
        return dynamic_error(StatusCode::CONFLICT, "CONFLICT", message);
    }
    super::super::support::route_error(error)
}

pub(super) fn scim_error(error: ScimError) -> Response {
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let code = match status {
        StatusCode::BAD_REQUEST => "BAD_REQUEST",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::CONFLICT => "CONFLICT",
        _ => "INTERNAL_SERVER_ERROR",
    };
    dynamic_error(status, code, error.detail)
}

fn bad_request(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}

fn dynamic_error(status: StatusCode, code: &'static str, message: String) -> Response {
    (status, Json(json!({"code": code, "message": message}))).into_response()
}
