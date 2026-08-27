use super::super::AuthService;
use crate::{
    AuthError, OrganizationError, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationPermissions, SessionWithUser,
};
use chrono::Utc;
use std::collections::BTreeMap;

pub(super) async fn validate_teams(
    plugin: &crate::OrganizationPlugin,
    organization_id: &str,
    team_ids: &[String],
) -> Result<(), AuthError> {
    if !team_ids.is_empty() && !plugin.config.teams.enabled {
        return Err(team_not_found());
    }
    for team_id in team_ids {
        let valid = plugin
            .store
            .find_team(team_id)
            .await?
            .is_some_and(|team| team.organization_id == organization_id);
        if !valid {
            return Err(team_not_found());
        }
        if let Some(limit) = plugin.config.teams.maximum_members_per_team
            && plugin.store.list_team_members(team_id).await?.len() >= limit
        {
            return Err(OrganizationError::forbidden(
                "TEAM_MEMBER_LIMIT_REACHED",
                "Team member limit reached",
            )
            .into());
        }
    }
    Ok(())
}

pub(super) async fn require_pending(
    plugin: &crate::OrganizationPlugin,
    invitation_id: &str,
) -> Result<OrganizationInvitation, AuthError> {
    plugin
        .store
        .find_invitation(invitation_id)
        .await?
        .filter(|invitation| {
            invitation.status == OrganizationInvitationStatus::Pending
                && invitation.expires_at > Utc::now()
        })
        .ok_or_else(invitation_not_found)
}

pub(super) fn require_recipient(
    session: &SessionWithUser,
    invitation: &OrganizationInvitation,
    require_verified: Option<bool>,
) -> Result<(), AuthError> {
    if !invitation.email.eq_ignore_ascii_case(&session.user.email) {
        return Err(OrganizationError::forbidden(
            "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
            "You are not the recipient of the invitation",
        )
        .into());
    }
    if require_verified == Some(true) && !session.user.email_verified {
        return Err(OrganizationError::forbidden(
            "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
            "Email verification required before accepting or rejecting invitation",
        )
        .into());
    }
    Ok(())
}

pub(super) fn require_invitation_viewer(
    session: &SessionWithUser,
    invitation: &OrganizationInvitation,
    require_verified: Option<bool>,
) -> Result<(), AuthError> {
    if !invitation.email.eq_ignore_ascii_case(&session.user.email) {
        return Err(OrganizationError::forbidden(
            "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
            "You are not the recipient of the invitation",
        )
        .into());
    }
    if require_verified == Some(true) && !session.user.email_verified {
        return Err(OrganizationError::forbidden(
            "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
            "Email verification required for invitation",
        )
        .into());
    }
    Ok(())
}

pub(super) async fn require_permission(
    service: &AuthService,
    member: &crate::OrganizationMember,
    action: &str,
) -> Result<(), AuthError> {
    let permissions: OrganizationPermissions =
        BTreeMap::from([("invitation".into(), vec![action.into()])]);
    if service
        .organization_has_permission(member, &permissions, false)
        .await?
    {
        return Ok(());
    }
    let (code, message) = if action == "cancel" {
        (
            "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION",
            "You are not allowed to cancel this invitation",
        )
    } else {
        (
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
            "You are not allowed to invite users to this organization",
        )
    };
    Err(OrganizationError::forbidden(code, message).into())
}

pub(super) fn single_team_id(invitation: &OrganizationInvitation) -> Option<String> {
    invitation
        .team_id
        .as_deref()
        .and_then(|ids| (!ids.contains(',')).then_some(ids))
        .map(str::to_owned)
}

pub(super) fn normalize_roles(role: &str) -> String {
    role.split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn has_role(roles: &str, expected: &str) -> bool {
    roles.split(',').map(str::trim).any(|role| role == expected)
}

pub(super) fn organization_not_found() -> AuthError {
    OrganizationError::bad_request("ORGANIZATION_NOT_FOUND", "Organization not found").into()
}

pub(super) fn member_not_found() -> AuthError {
    OrganizationError::bad_request("MEMBER_NOT_FOUND", "Member not found").into()
}

pub(super) fn invitation_not_found() -> AuthError {
    OrganizationError::bad_request("INVITATION_NOT_FOUND", "Invitation not found").into()
}

pub(super) fn inviter_missing() -> AuthError {
    OrganizationError::bad_request(
        "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
        "Inviter is no longer a member of the organization",
    )
    .into()
}

fn team_not_found() -> AuthError {
    OrganizationError::bad_request("TEAM_NOT_FOUND", "Team not found").into()
}
