use super::support::{OrganizationClaims, claims, error, plugin as organization_plugin, route_error};
use crate::{AuthService, DashPlugin, SsoPlugin, SsoProvider, SsoProviderUpdate};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub(super) mod domain;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MarkDomainBody {
    provider_id: String,
    verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProviderBody {
    provider_id: String,
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Response {
    let claims = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if organization_plugin(&service).is_err() {
        return Json(json!([])).into_response();
    }
    if !has_access(&claims, &organization_id) {
        return forbidden();
    }
    let Some(sso) = service.sso_plugin() else {
        return Json(json!([])).into_response();
    };
    let providers = match sso.store().list().await {
        Ok(providers) => providers,
        Err(_) => return Json(json!([])).into_response(),
    };
    let base_url = service
        .auth_base_url()
        .map(|url| url.to_string().trim_end_matches('/').to_owned())
        .unwrap_or_else(|| service.base_path().trim_end_matches('/').to_owned());
    let providers = providers
        .into_iter()
        .filter(|provider| provider.organization_id.as_deref() == Some(&organization_id))
        .map(|provider| {
            crate::sso::sanitize_provider(
                &provider,
                &base_url,
                &sso.options().schema.sso_provider.additional_fields,
            )
        })
        .collect::<Vec<_>>();
    Json(providers).into_response()
}

pub(super) async fn mark_domain_verified(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<MarkDomainBody>,
) -> Response {
    let claims = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if organization_plugin(&service).is_err() {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Organization plugin not enabled",
        );
    }
    if !has_access(&claims, &organization_id) {
        return forbidden();
    }
    if body.verified {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid literal value, expected false",
        );
    }
    let Some(sso) = service
        .sso_plugin()
        .filter(|plugin| plugin.options().domain_verification)
    else {
        return sso_domain_feature_error();
    };
    let provider = match sso.store().find_by_provider_id(&body.provider_id).await {
        Ok(Some(provider))
            if provider.organization_id.as_deref() == Some(organization_id.as_str()) =>
        {
            provider
        }
        Ok(_) => {
            return error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "SSO provider not found",
            );
        }
        Err(storage) => return route_error(crate::AuthError::SsoStore(storage)),
    };
    if let Err(storage) = sso
        .store()
        .update(
            &provider.id,
            SsoProviderUpdate {
                domain_verified: Some(false),
                ..SsoProviderUpdate::default()
            },
        )
        .await
    {
        return route_error(crate::AuthError::SsoStore(storage));
    }
    Json(json!({
        "success": true,
        "domainVerified": false,
        "message": "Domain verification unmarked",
    }))
    .into_response()
}

pub(super) async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<ProviderBody>,
) -> Response {
    let sso = match authorized_sso(
        &service,
        &dash,
        &headers,
        &organization_id,
        false,
    )
    .await
    {
        Ok(sso) => sso,
        Err(response) => return *response,
    };
    let provider = match organization_provider(sso, &organization_id, &body.provider_id).await {
        Ok(provider) => provider,
        Err(response) => return *response,
    };
    match crate::sso::delete_provider_guarded(&service, sso, &provider).await {
        Ok(true) => Json(json!({
            "success": true,
            "message": "SSO provider deleted successfully",
        }))
        .into_response(),
        Ok(false) | Err(crate::AuthError::SsoStore(crate::SsoStoreError::NotFound)) => {
            provider_not_found()
        }
        Err(crate::AuthError::SsoProviderMutationRejected) => error(
            StatusCode::CONFLICT,
            "SSO_PROVIDER_MUTATION_REJECTED",
            "SSO provider mutation is not allowed",
        ),
        Err(storage) => route_error(storage),
    }
}

fn has_access(claims: &OrganizationClaims, organization_id: &str) -> bool {
    claims.organization_id == organization_id
}

fn forbidden() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "You do not have access to this organization",
    )
}

fn sso_domain_feature_error() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "SSO plugin with domain verification is not enabled or feature is not supported in your plugin version",
    )
}

async fn authorized_sso<'a>(
    service: &'a AuthService,
    dash: &DashPlugin,
    headers: &HeaderMap,
    organization_id: &str,
    require_domain_verification: bool,
) -> Result<&'a SsoPlugin, Box<Response>> {
    let claims = claims::<OrganizationClaims>(dash, headers)
        .await
        .map_err(Box::new)?;
    organization_plugin(service).map_err(Box::new)?;
    if !has_access(&claims, organization_id) {
        return Err(Box::new(forbidden()));
    }
    let Some(sso) = service.sso_plugin() else {
        return Err(Box::new(if require_domain_verification {
            sso_domain_feature_error()
        } else {
            sso_feature_error()
        }));
    };
    if require_domain_verification && !sso.options().domain_verification {
        return Err(Box::new(sso_domain_feature_error()));
    }
    Ok(sso)
}

async fn organization_provider(
    sso: &SsoPlugin,
    organization_id: &str,
    provider_id: &str,
) -> Result<SsoProvider, Box<Response>> {
    match sso.store().find_by_provider_id(provider_id).await {
        Ok(Some(provider))
            if provider.organization_id.as_deref() == Some(organization_id) =>
        {
            Ok(provider)
        }
        Ok(_) => Err(Box::new(provider_not_found())),
        Err(storage) => Err(Box::new(route_error(crate::AuthError::SsoStore(storage)))),
    }
}

fn provider_not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "SSO provider not found",
    )
}

fn sso_feature_error() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "SSO plugin is not enabled or feature is not supported in your plugin version",
    )
}
