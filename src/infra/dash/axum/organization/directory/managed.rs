use super::{claims, contract, model::DirectoryRow, pairing, store};
use crate::{AuthService, DashPlugin, ScimError, ScimManagedCredential, ScimScope};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Response {
    if !claims::managed_mode(&service, &dash) {
        return match claims::unconstrained(&dash, &headers).await {
            Ok(()) => Json(json!([])).into_response(),
            Err(response) => response,
        };
    }
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
    Json(body): Json<contract::CreateBody>,
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
    let (scopes, expires_at) = match contract::policy(body.scopes, body.expires_at) {
        Ok(policy) => policy,
        Err(response) => return response,
    };
    if let Some(response) = recover_setup(
        &service,
        scim,
        &organization_id,
        body.provider_id.trim(),
        &claims,
        pairing.as_ref(),
        &scopes,
        expires_at,
    )
    .await
    {
        return response;
    }
    create_fresh(
        &service,
        scim,
        &organization_id,
        body.provider_id.trim(),
        &claims,
        pairing.as_ref(),
        scopes,
        expires_at,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_fresh(
    service: &AuthService,
    scim: &crate::ScimPlugin,
    organization_id: &str,
    provider_id: &str,
    claims: &claims::DirectoryClaims,
    pairing: Option<&pairing::ResolvedPairing>,
    scopes: Vec<ScimScope>,
    expires_at: DateTime<Utc>,
) -> Response {
    let reserved = match store::reserve(
        service.database_store(),
        store::NewDirectory {
            organization_id,
            provider_id,
            actor_id: claims.actor_id.trim(),
            creation_request_id: claims.setup_operation_id.as_deref(),
            pairing,
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
        Err(error) => {
            let _ = store::release_reservation(service.database_store(), &reserved).await;
            return scim_error(error);
        }
    };
    let row = match store::bind(service.database_store(), &reserved, &connection.connection_id).await {
        Ok(row) => row,
        Err(error) => {
            let _ = scim
                .decommission_managed_connection(
                    &connection.connection_id,
                    &reserved.provisioning_domain_id,
                    claims.actor_id.trim(),
                )
                .await;
            let _ = store::release_reservation(service.database_store(), &reserved).await;
            return catalog_error(error);
        }
    };
    created_response(service, &row, connection, credential, token)
}

#[allow(clippy::too_many_arguments)]
async fn recover_setup(
    service: &AuthService,
    scim: &crate::ScimPlugin,
    organization_id: &str,
    provider_id: &str,
    claims: &claims::DirectoryClaims,
    pairing: Option<&pairing::ResolvedPairing>,
    scopes: &[ScimScope],
    expires_at: DateTime<Utc>,
) -> Option<Response> {
    let setup_id = claims.setup_operation_id.as_deref()?;
    let row = match store::get(service.database_store(), organization_id, provider_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return None,
        Err(error) => return Some(super::super::support::route_error(error)),
    };
    let serialized_pairing = pairing.map(|pairing| {
        serde_json::to_string(&pairing.pairing).expect("directory SSO pairing serializes")
    });
    if row.creation_request_id != setup_id
        || row.status != "active"
        || row.connection_id.is_none()
        || row.serialized_sso_pairing != serialized_pairing
    {
        return Some(conflict_message(
            "This directory sync alias belongs to a different setup operation",
        ));
    }
    recover_existing(service, scim, row, claims, scopes, expires_at).await
}

async fn recover_existing(
    service: &AuthService,
    scim: &crate::ScimPlugin,
    row: DirectoryRow,
    claims: &claims::DirectoryClaims,
    scopes: &[ScimScope],
    expires_at: DateTime<Utc>,
) -> Option<Response> {
    let connection_id = row.connection_id.as_deref().expect("binding checked");
    let state = match scim
        .get_managed_connection(connection_id, &row.provisioning_domain_id)
        .await
    {
        Ok(state) => state,
        Err(error) => return Some(scim_error(error)),
    };
    if state.0.creation_request_id != row.creation_request_id || state.0.status != "active" {
        return Some(conflict_message(
            "Managed connection ownership changed before setup recovery",
        ));
    }
    let updated = match store::touch_active(service.database_store(), &row, &claims.actor_id).await {
        Ok(row) => row,
        Err(error) => return Some(catalog_error(error)),
    };
    for credential in state.1.iter().filter(|credential| credential.status == "active") {
        if let Err(error) = scim
            .revoke_managed_credential(
                connection_id,
                &row.provisioning_domain_id,
                &credential.credential_id,
                claims.actor_id.trim(),
            )
            .await
        {
            return Some(scim_error(error));
        }
    }
    match scim
        .rotate_managed_credential(
            connection_id,
            &row.provisioning_domain_id,
            claims.actor_id.trim(),
            scopes.to_vec(),
            expires_at,
        )
        .await
    {
        Ok((connection, credential, token)) => Some(created_response(
            service,
            &updated,
            connection,
            credential,
            token,
        )),
        Err(error) => Some(scim_error(error)),
    }
}

fn created_response(
    service: &AuthService,
    row: &DirectoryRow,
    connection: crate::ScimManagedConnection,
    credential: ScimManagedCredential,
    token: String,
) -> Response {
    let state = (connection.clone(), vec![credential.clone()]);
    let mut body = row.response(&base_url(service), Some(&state));
    let object = body.as_object_mut().expect("directory response is an object");
    object.insert("connectionId".into(), json!(connection.connection_id));
    object.insert("credential".into(), credential_value(&credential));
    object.insert("scimToken".into(), json!(token));
    secured(Json(body).into_response())
}

pub(crate) async fn legacy_unavailable(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Response {
    if let Err(response) = claims::legacy(&service, &dash, &headers).await {
        return response;
    }
    super::super::support::error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "SCIM plugin is not enabled or does not support this feature",
    )
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

fn conflict_message(message: &'static str) -> Response {
    super::super::support::error(StatusCode::CONFLICT, "CONFLICT", message)
}

fn dynamic_error(status: StatusCode, code: &'static str, message: String) -> Response {
    (status, Json(json!({"code": code, "message": message}))).into_response()
}
