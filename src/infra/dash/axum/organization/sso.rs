use super::support::{OrganizationClaims, claims, error, plugin as organization_plugin, route_error};
use crate::{AuthService, DashPlugin, SsoProviderUpdate};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MarkDomainBody {
    provider_id: String,
    verified: bool,
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
