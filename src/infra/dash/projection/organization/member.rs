use super::{EventLocation, EventObservation, observation};
use crate::{AfterOrganizationEvent, AuthUser, OrganizationMember};
use serde_json::{Value, json};

pub(super) fn project(
    event: &AfterOrganizationEvent<'_>,
    location: EventLocation,
) -> EventObservation {
    match event {
        AfterOrganizationEvent::MemberAdded { organization, member, user } => observation(
            organization,
            user,
            "organization_member_added",
            "Member added to organization",
            fields(member, user, None),
            location,
        ),
        AfterOrganizationEvent::MemberRemoved { organization, member, user } => observation(
            organization,
            user,
            "organization_member_removed",
            "Member removed from organization",
            fields(member, user, None),
            location,
        ),
        AfterOrganizationEvent::MemberRoleUpdated { organization, member, previous_role, user } => observation(
            organization,
            user,
            "organization_member_role_updated",
            "Organization member role updated",
            fields(member, user, Some(previous_role)),
            location,
        ),
        _ => unreachable!("member projection receives a member event"),
    }
}

fn fields(
    member: &OrganizationMember,
    user: &AuthUser,
    previous_role: Option<&&str>,
) -> Vec<(&'static str, Value)> {
    let mut fields = vec![("userId", json!(member.user_id)), ("memberName", json!(user.name))];
    if let Some(previous_role) = previous_role {
        fields.push(("newRole", json!(member.role)));
        fields.push(("oldRole", json!(previous_role)));
    } else {
        fields.push(("role", json!(member.role)));
    }
    fields.extend([("memberId", json!(member.id)), ("memberEmail", json!(user.email))]);
    fields
}
