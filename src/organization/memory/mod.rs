use super::super::{
    Organization, OrganizationInvitation, OrganizationMember, OrganizationRole, OrganizationTeam,
    OrganizationTeamMember,
};
use std::collections::HashMap;
use tokio::sync::RwLock;

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
    organizations: HashMap<String, Organization>,
    members: HashMap<String, OrganizationMember>,
    invitations: HashMap<String, OrganizationInvitation>,
    teams: HashMap<String, OrganizationTeam>,
    team_members: HashMap<String, OrganizationTeamMember>,
    roles: HashMap<String, OrganizationRole>,
    serial_ids: HashMap<String, u64>,
}

fn create_id(
    model: &str,
    supplier: &dyn crate::DatabaseIdSupplier,
    state: &mut State,
) -> Result<String, crate::AuthError> {
    match supplier.prepare()? {
        crate::PreparedDatabaseId::Value(value) => Ok(value.into_output_string()),
        crate::PreparedDatabaseId::DeferredSerial => {
            let value = state.serial_ids.entry(model.into()).or_default();
            *value = value.saturating_add(1);
            Ok(value.to_string())
        }
        crate::PreparedDatabaseId::Deferred => Err(crate::AuthError::Storage(format!(
            "database adapter did not return an id for model '{model}'"
        ))),
    }
}

fn duplicate_id(model: &str) -> crate::AuthError {
    crate::AuthError::Storage(format!("{model} id already exists"))
}

fn has_role(member: &OrganizationMember, role: &str) -> bool {
    member
        .role
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}
