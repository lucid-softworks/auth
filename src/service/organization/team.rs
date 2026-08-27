mod core;
mod member;

use super::AuthService;
use crate::{AuthError, OrganizationError, OrganizationMember, OrganizationPermissions};
use std::collections::BTreeMap;

async fn require_team_permission(
    service: &AuthService,
    member: &OrganizationMember,
    action: &str,
    code: &'static str,
    message: &'static str,
) -> Result<(), AuthError> {
    let permissions: OrganizationPermissions =
        BTreeMap::from([("team".into(), vec![action.into()])]);
    if service
        .organization_has_permission(member, &permissions, false)
        .await?
    {
        Ok(())
    } else {
        Err(OrganizationError::forbidden(code, message).into())
    }
}

async fn require_member_update(
    service: &AuthService,
    member: &OrganizationMember,
    code: &'static str,
    message: &'static str,
) -> Result<(), AuthError> {
    let permissions: OrganizationPermissions =
        BTreeMap::from([("member".into(), vec!["update".into()])]);
    if service
        .organization_has_permission(member, &permissions, false)
        .await?
    {
        Ok(())
    } else {
        Err(OrganizationError::forbidden(code, message).into())
    }
}

fn active_or(
    session: &crate::SessionWithUser,
    organization_id: Option<String>,
) -> Result<String, AuthError> {
    organization_id
        .or_else(|| AuthService::active_organization_id(session))
        .ok_or_else(|| {
            OrganizationError::bad_request("NO_ACTIVE_ORGANIZATION", "No active organization")
                .into()
        })
}

fn team_not_found() -> AuthError {
    OrganizationError::bad_request("TEAM_NOT_FOUND", "Team not found").into()
}

fn member_not_found() -> AuthError {
    OrganizationError::bad_request(
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        "User is not a member of the organization",
    )
    .into()
}
