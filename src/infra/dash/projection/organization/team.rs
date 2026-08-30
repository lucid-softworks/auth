use super::{EventLocation, EventObservation, observation};
use crate::{AfterOrganizationEvent, AuthUser, OrganizationTeam, OrganizationTeamMember};
use serde_json::{Value, json};

pub(super) fn project(event: &AfterOrganizationEvent<'_>, location: EventLocation) -> EventObservation {
    match event {
        AfterOrganizationEvent::TeamCreated { organization, team, user } => team_observation(organization, team, user, "organization_team_created", "Organization team created", location),
        AfterOrganizationEvent::TeamUpdated { organization, team, user } => team_observation(organization, team, user, "organization_team_updated", "Organization team updated", location),
        AfterOrganizationEvent::TeamDeleted { organization, team, user } => team_observation(organization, team, user, "organization_team_deleted", "Organization team deleted", location),
        AfterOrganizationEvent::TeamMemberAdded { organization, team, team_member, user } => team_member_observation(organization, team, team_member, user, "organization_team_member_added", "User added to organization team", location),
        AfterOrganizationEvent::TeamMemberRemoved { organization, team, team_member, user } => team_member_observation(organization, team, team_member, user, "organization_team_member_removed", "User removed from organization team", location),
        _ => unreachable!("team projection receives a team event"),
    }
}

fn team_observation(organization: &crate::Organization, team: &OrganizationTeam, user: &AuthUser, event_type: &'static str, display: &'static str, location: EventLocation) -> EventObservation {
    observation(organization, user, event_type, display, [("teamId", json!(team.id)), ("teamName", json!(team.name))], location)
}

fn team_member_observation(organization: &crate::Organization, team: &OrganizationTeam, member: &OrganizationTeamMember, user: &AuthUser, event_type: &'static str, display: &'static str, location: EventLocation) -> EventObservation {
    let fields: [(&'static str, Value); 4] = [("teamId", json!(member.team_id)), ("teamName", json!(team.name)), ("userid", json!(member.user_id)), ("memberName", json!(user.name))];
    observation(organization, user, event_type, display, fields, location)
}
