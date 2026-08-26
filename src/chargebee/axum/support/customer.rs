#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::{api_error, error, internal_error};
use crate::chargebee::{
    ChargebeeCallbackContext, ChargebeeErrorCode, ChargebeeOrganizationSnapshot,
    ChargebeeSessionSnapshot, ChargebeeUserSnapshot,
};
use crate::{AuthService, SessionWithUser, chargebee::axum::ChargebeeRouteState};
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value};
use uuid::Uuid;

pub(in crate::chargebee::axum) struct CustomerRequest<'a> {
    pub service: &'a AuthService,
    pub state: &'a ChargebeeRouteState,
    pub session: &'a SessionWithUser,
    pub customer_type: super::super::input::CustomerType,
    pub reference_id: &'a str,
    pub metadata: Option<&'a Map<String, Value>>,
    pub existing_customer_id: Option<&'a str>,
    pub context: &'a ChargebeeCallbackContext,
}

pub(in crate::chargebee::axum) fn user_snapshot(
    session: &SessionWithUser,
) -> ChargebeeUserSnapshot {
    ChargebeeUserSnapshot {
        id: session.user.id.to_string(),
        name: session.user.name.clone(),
        email: session.user.email.clone(),
        email_verified: session.user.email_verified,
        chargebee_customer_id: session_customer_id(session).map(str::to_owned),
        additional_fields: session.user.additional_fields.clone(),
    }
}

pub(in crate::chargebee::axum) fn session_customer_id(session: &SessionWithUser) -> Option<&str> {
    session
        .user
        .additional_fields
        .get("chargebeeCustomerId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub(in crate::chargebee::axum) fn session_snapshot(
    session: &SessionWithUser,
) -> ChargebeeSessionSnapshot {
    ChargebeeSessionSnapshot {
        id: session.session.id.to_string(),
        user_id: session.user.id.to_string(),
        active_organization_id: AuthService::active_organization_id(session)
            .map(|id| id.to_string()),
        additional_fields: session.session.additional_fields.clone(),
    }
}

pub(in crate::chargebee::axum) async fn customer_id(
    request: CustomerRequest<'_>,
) -> Result<String, Response> {
    if let Some(customer_id) = request
        .existing_customer_id
        .filter(|value| !value.is_empty())
    {
        return Ok(customer_id.to_owned());
    }
    let user = user_snapshot(request.session);
    match request.customer_type {
        super::super::input::CustomerType::User => super::super::super::customer::user_customer_id(
            &request.state.options,
            request.state.store.as_ref(),
            &request.session.user.id,
            &user,
            request.metadata,
            request.context,
        )
        .await
        .map_err(api_error),
        super::super::input::CustomerType::Organization => {
            let organization =
                organization_snapshot(request.service, request.state, request.reference_id).await?;
            let organization_id = organization_id(request.reference_id)?;
            super::super::super::customer::organization_customer_id(
                &request.state.options,
                request.state.store.as_ref(),
                organization_id,
                &organization,
                request.metadata,
                request.context,
            )
            .await
            .map_err(api_error)
        }
    }
}

pub(in crate::chargebee::axum) async fn organization_snapshot(
    service: &AuthService,
    state: &ChargebeeRouteState,
    reference_id: &str,
) -> Result<ChargebeeOrganizationSnapshot, Response> {
    let id = organization_id(reference_id)?;
    let organization = service
        .organization_plugin()
        .map_err(internal_error)?
        .store
        .find_organization_by_id(id)
        .await
        .map_err(internal_error)?
        .ok_or_else(organization_not_found)?;
    let chargebee_customer_id = state
        .store
        .organization_customer_id(id)
        .await
        .map_err(internal_error)?;
    Ok(ChargebeeOrganizationSnapshot {
        id: organization.id.to_string(),
        name: organization.name,
        chargebee_customer_id,
        metadata: organization.metadata,
    })
}

fn organization_id(reference_id: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(reference_id).map_err(|_| organization_not_found())
}

fn organization_not_found() -> Response {
    error(
        ChargebeeErrorCode::OrganizationNotFound,
        StatusCode::BAD_REQUEST,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_customer_reads_only_the_exact_additional_field() {
        let mut fields = serde_json::Map::new();
        fields.insert("chargebeeCustomerId".into(), Value::String("cached".into()));
        assert_eq!(
            fields.get("chargebeeCustomerId").and_then(Value::as_str),
            Some("cached")
        );
        assert!(fields.get("chargebee_customer_id").is_none());
    }
}
