use crate::{
    AuthUser, Organization, OrganizationInvitation, OrganizationMember, OrganizationTeam,
    OrganizationTeamMember,
};

/// Successful Better Auth organization lifecycle observations.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum AfterOrganizationEvent<'a> {
    Created {
        organization: &'a Organization,
        user: &'a AuthUser,
    },
    Updated {
        organization: &'a Organization,
        user: &'a AuthUser,
    },
    MemberAdded {
        organization: &'a Organization,
        member: &'a OrganizationMember,
        user: &'a AuthUser,
    },
    MemberRemoved {
        organization: &'a Organization,
        member: &'a OrganizationMember,
        user: &'a AuthUser,
    },
    MemberRoleUpdated {
        organization: &'a Organization,
        member: &'a OrganizationMember,
        previous_role: &'a str,
        user: &'a AuthUser,
    },
    MemberInvited {
        organization: &'a Organization,
        invitation: &'a OrganizationInvitation,
        user: &'a AuthUser,
    },
    InvitationAccepted {
        organization: &'a Organization,
        invitation: &'a OrganizationInvitation,
        member: &'a OrganizationMember,
        user: &'a AuthUser,
    },
    InvitationRejected {
        organization: &'a Organization,
        invitation: &'a OrganizationInvitation,
        user: &'a AuthUser,
    },
    InvitationCanceled {
        organization: &'a Organization,
        invitation: &'a OrganizationInvitation,
        user: &'a AuthUser,
    },
    TeamCreated {
        organization: &'a Organization,
        team: &'a OrganizationTeam,
        user: &'a AuthUser,
    },
    TeamUpdated {
        organization: &'a Organization,
        team: &'a OrganizationTeam,
        user: &'a AuthUser,
    },
    TeamDeleted {
        organization: &'a Organization,
        team: &'a OrganizationTeam,
        user: &'a AuthUser,
    },
    TeamMemberAdded {
        organization: &'a Organization,
        team: &'a OrganizationTeam,
        team_member: &'a OrganizationTeamMember,
        user: &'a AuthUser,
    },
    TeamMemberRemoved {
        organization: &'a Organization,
        team: &'a OrganizationTeam,
        team_member: &'a OrganizationTeamMember,
        user: &'a AuthUser,
    },
}
