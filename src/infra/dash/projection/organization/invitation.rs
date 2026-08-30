use super::{EventLocation, EventObservation, observation};
use crate::{AfterOrganizationEvent, AuthUser, OrganizationInvitation, OrganizationMember};
use serde_json::{Value, json};

pub(super) fn project(event: &AfterOrganizationEvent<'_>, location: EventLocation) -> EventObservation {
    let (organization, invitation, user, member, prefix, event_type, display) = match event {
        AfterOrganizationEvent::MemberInvited { organization, invitation, user } => (*organization, *invitation, *user, None, "inviter", "organization_member_invited", "User invited to organization"),
        AfterOrganizationEvent::InvitationAccepted { organization, invitation, member, user } => (*organization, *invitation, *user, Some(*member), "acceptedBy", "organization_member_invite_accepted", "User accepted invite organization invite"),
        AfterOrganizationEvent::InvitationRejected { organization, invitation, user } => (*organization, *invitation, *user, None, "rejectedBy", "organization_member_invite_rejected", "User rejected organization invite"),
        AfterOrganizationEvent::InvitationCanceled { organization, invitation, user } => (*organization, *invitation, *user, None, "cancelledBy", "organization_member_invite_canceled", "Organization invite cancelled"),
        _ => unreachable!("invitation projection receives an invitation event"),
    };
    observation(organization, user, event_type, display, fields(invitation, prefix, user, member), location)
}

fn fields(invitation: &OrganizationInvitation, prefix: &str, user: &AuthUser, member: Option<&OrganizationMember>) -> Vec<(&'static str, Value)> {
    let actor = match prefix {
        "inviter" => ["inviterId", "inviterName", "inviterEmail"],
        "acceptedBy" => ["acceptedById", "acceptedByName", "acceptedByEmail"],
        "rejectedBy" => ["rejectedById", "rejectedByName", "rejectedByEmail"],
        "cancelledBy" => ["cancelledById", "cancelledByName", "cancelledByEmail"],
        _ => unreachable!("published invitation actor"),
    };
    let mut fields = vec![
        ("inviteeId", json!(invitation.id)), ("inviteeEmail", json!(invitation.email)),
        ("inviteeRole", json!(invitation.role)), ("inviteeTeamId", json!(invitation.team_id)),
        (actor[0], json!(user.id)), (actor[1], json!(user.name)), (actor[2], json!(user.email)),
    ];
    if let Some(member) = member {
        fields.extend([("memberId", json!(member.id)), ("memberRole", json!(member.role))]);
    }
    fields
}
