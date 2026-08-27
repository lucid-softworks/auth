use super::AuthService;
use crate::{
    AuthError, DatabaseIdInput, Organization, OrganizationCreateOutcome, OrganizationMember,
    OrganizationPlugin, OrganizationTeam, OrganizationTeamMember,
};

pub(super) async fn create(
    service: &AuthService,
    plugin: &OrganizationPlugin,
    organization: &mut Organization,
    member: &mut OrganizationMember,
    default_team: &mut Option<(OrganizationTeam, OrganizationTeamMember)>,
) -> Result<OrganizationCreateOutcome, AuthError> {
    let organization_plan =
        service.database_id_plan("organization", supplied_id(&organization.id), true);
    let member_plan = service.database_id_plan("member", DatabaseIdInput::Absent, false);
    let team_plan = service.database_id_plan(
        "team",
        default_team
            .as_ref()
            .map_or(DatabaseIdInput::Absent, |(team, _)| supplied_id(&team.id)),
        true,
    );
    let team_member_plan = service.database_id_plan("teamMember", DatabaseIdInput::Absent, false);
    let organization_id = || organization_plan.prepare(service.store.as_ref());
    let member_id = || member_plan.prepare(service.store.as_ref());
    let team_id = || team_plan.prepare(service.store.as_ref());
    let team_member_id = || team_member_plan.prepare(service.store.as_ref());
    let default_team_create = default_team.as_mut().map(|(team, team_member)| {
        (
            team,
            &team_id as &dyn crate::DatabaseIdSupplier,
            team_member,
            &team_member_id as &dyn crate::DatabaseIdSupplier,
        )
    });
    plugin
        .store
        .create_organization(
            organization,
            &organization_id,
            member,
            &member_id,
            default_team_create,
            plugin.config.organization_limit,
        )
        .await
}

fn supplied_id(id: &str) -> DatabaseIdInput {
    if id.is_empty() {
        DatabaseIdInput::Absent
    } else {
        DatabaseIdInput::String(id.to_owned())
    }
}
