use super::RegisterBody;
use crate::{AuthService, SsoPlugin};
use axum::{http::StatusCode, response::Response};

const BUILT_IN_PROVIDER_IDS: [&str; 6] = [
    "credential",
    "email-otp",
    "magic-link",
    "phone-number",
    "anonymous",
    "siwe",
];

pub(super) async fn validate(
    service: &AuthService,
    plugin: &SsoPlugin,
    body: &RegisterBody,
    user_id: &str,
) -> Result<(), Box<Response>> {
    if plugin.options().providers_limit == 0 {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "SSO provider registration is disabled",
        )));
    }
    let providers = plugin
        .store()
        .list()
        .await
        .map_err(|error| Box::new(super::super::support::storage(error)))?;
    if providers
        .iter()
        .filter(|provider| provider.user_id == user_id)
        .count()
        >= plugin.options().providers_limit
    {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "You have reached the maximum number of SSO providers",
        )));
    }
    if url::Url::parse(&body.issuer).is_err() {
        return Err(Box::new(super::super::support::error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid issuer",
        )));
    }
    validate_organization(service, body.organization_id.as_deref(), user_id).await?;
    if reserved(service, &body.provider_id) {
        return Err(Box::new(super::super::support::error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "UNPROCESSABLE_ENTITY",
            "This providerId is reserved and cannot be used for an SSO provider",
        )));
    }
    if providers
        .iter()
        .any(|provider| provider.provider_id == body.provider_id)
    {
        return Err(Box::new(super::persistence::duplicate()));
    }
    Ok(())
}

async fn validate_organization(
    service: &AuthService,
    organization_id: Option<&str>,
    user_id: &str,
) -> Result<(), Box<Response>> {
    let Some(organization_id) = organization_id else {
        return Ok(());
    };
    let organization = service.organization_plugin().map_err(|_| {
        Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "You are not a member of the organization",
        ))
    })?;
    let member = organization
        .store
        .find_member(organization_id, user_id)
        .await
        .map_err(|error| {
            Box::new(super::super::support::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                error.to_string(),
            ))
        })?
        .ok_or_else(|| {
            Box::new(super::super::support::error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "You are not a member of the organization",
            ))
        })?;
    if member
        .role
        .split(',')
        .any(|role| matches!(role.trim(), "owner" | "admin"))
    {
        return Ok(());
    }
    Err(Box::new(error(
        StatusCode::FORBIDDEN,
        "You must be an organization owner or admin to register SSO providers",
    )))
}

fn reserved(service: &AuthService, provider_id: &str) -> bool {
    BUILT_IN_PROVIDER_IDS.contains(&provider_id)
        || service
            .reserved_account_provider_ids()
            .contains(&provider_id)
}

fn error(status: StatusCode, message: &'static str) -> Response {
    super::super::support::error(status, status_code(status), message)
}

const fn status_code(status: StatusCode) -> &'static str {
    if status.as_u16() == 403 {
        "FORBIDDEN"
    } else {
        "BAD_REQUEST"
    }
}
