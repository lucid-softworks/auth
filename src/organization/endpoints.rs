use crate::{PluginEndpoint, PluginHttpMethod};

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

macro_rules! endpoint_set {
    ($($extra:expr),* $(,)?) => {
        &[
    endpoint(
        PluginHttpMethod::Post,
        "/organization/create",
        "organization.create",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update",
        "organization.update",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/delete",
        "organization.delete",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/set-active",
        "organization.setActive",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-organization",
        "organization.getOrganization",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-full-organization",
        "organization.getFullOrganization",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list",
        "organization.list",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/check-slug",
        "organization.checkSlug",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/invite-member",
        "organization.inviteMember",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/cancel-invitation",
        "organization.cancelInvitation",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/accept-invitation",
        "organization.acceptInvitation",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-invitation",
        "organization.getInvitation",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/reject-invitation",
        "organization.rejectInvitation",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-invitations",
        "organization.listInvitations",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-user-invitations",
        "organization.listUserInvitations",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-active-member",
        "organization.getActiveMember",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/remove-member",
        "organization.removeMember",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update-member-role",
        "organization.updateMemberRole",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/leave",
        "organization.leave",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-members",
        "organization.listMembers",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-active-member-role",
        "organization.getActiveMemberRole",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/has-permission",
        "organization.hasPermission",
    ),
            $($extra,)*
        ]
    };
}

pub(super) const CORE: &[PluginEndpoint] = endpoint_set!();

pub(super) const WITH_TEAMS: &[PluginEndpoint] = endpoint_set!(
    endpoint(
        PluginHttpMethod::Post,
        "/organization/create-team",
        "organization.createTeam"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-teams",
        "organization.listTeams"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/remove-team",
        "organization.removeTeam"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update-team",
        "organization.updateTeam"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/set-active-team",
        "organization.setActiveTeam"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-user-teams",
        "organization.listUserTeams"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-team-members",
        "organization.listTeamMembers"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/add-team-member",
        "organization.addTeamMember"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/remove-team-member",
        "organization.removeTeamMember"
    ),
);

pub(super) const WITH_DYNAMIC_ACCESS: &[PluginEndpoint] = endpoint_set!(
    endpoint(
        PluginHttpMethod::Post,
        "/organization/create-role",
        "organization.createRole"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/delete-role",
        "organization.deleteRole"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-roles",
        "organization.listRoles"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-role",
        "organization.getRole"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update-role",
        "organization.updateRole"
    ),
);

pub(super) const WITH_TEAMS_AND_DYNAMIC_ACCESS: &[PluginEndpoint] = endpoint_set!(
    endpoint(
        PluginHttpMethod::Post,
        "/organization/create-team",
        "organization.createTeam"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-teams",
        "organization.listTeams"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/remove-team",
        "organization.removeTeam"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update-team",
        "organization.updateTeam"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/set-active-team",
        "organization.setActiveTeam"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-user-teams",
        "organization.listUserTeams"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-team-members",
        "organization.listTeamMembers"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/add-team-member",
        "organization.addTeamMember"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/remove-team-member",
        "organization.removeTeamMember"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/create-role",
        "organization.createRole"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/delete-role",
        "organization.deleteRole"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/list-roles",
        "organization.listRoles"
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/organization/get-role",
        "organization.getRole"
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/organization/update-role",
        "organization.updateRole"
    ),
);

pub(super) const fn for_options(
    teams: bool,
    dynamic_access_control: bool,
) -> &'static [PluginEndpoint] {
    match (teams, dynamic_access_control) {
        (false, false) => CORE,
        (true, false) => WITH_TEAMS,
        (false, true) => WITH_DYNAMIC_ACCESS,
        (true, true) => WITH_TEAMS_AND_DYNAMIC_ACCESS,
    }
}
