use super::super::{
    Organization, OrganizationInvitation, OrganizationMember, OrganizationRole, OrganizationTeam,
    OrganizationTeamMember,
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

mod invitation;
mod member;
mod organization;
mod role;
mod team;

#[derive(Default)]
pub struct MemoryOrganizationStore {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    organizations: HashMap<Uuid, Organization>,
    members: HashMap<Uuid, OrganizationMember>,
    invitations: HashMap<Uuid, OrganizationInvitation>,
    teams: HashMap<Uuid, OrganizationTeam>,
    team_members: HashMap<Uuid, OrganizationTeamMember>,
    roles: HashMap<Uuid, OrganizationRole>,
}

fn has_role(member: &OrganizationMember, role: &str) -> bool {
    member
        .role
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}
