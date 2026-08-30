use super::AuthService;
use crate::{
    AfterOrganizationEvent, AuthUser, Organization, OrganizationInvitation, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember,
};

impl AuthService {
    #[cfg(feature = "axum")]
    pub(in crate::service) async fn observe_dash_invitation_canceled(
        &self,
        organization: &Organization,
        invitation: &OrganizationInvitation,
        user: &AuthUser,
    ) {
        self.observe_invitation(
            InvitationObservation::Canceled,
            organization,
            invitation,
            user,
            None,
        )
        .await;
    }

    pub(super) async fn observe_organization_created(
        &self,
        organization: &Organization,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::Created { organization, user })
            .await;
    }

    pub(super) async fn observe_organization_updated(
        &self,
        organization: &Organization,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::Updated { organization, user })
            .await;
    }

    pub(in crate::service) async fn observe_member_added(
        &self,
        organization: &Organization,
        member: &OrganizationMember,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::MemberAdded {
                organization,
                member,
                user,
            })
            .await;
    }

    pub(in crate::service) async fn observe_member_removed(
        &self,
        organization: &Organization,
        member: &OrganizationMember,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::MemberRemoved {
                organization,
                member,
                user,
            })
            .await;
    }

    pub(in crate::service) async fn observe_member_role_updated(
        &self,
        organization: &Organization,
        member: &OrganizationMember,
        previous_role: &str,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::MemberRoleUpdated {
                organization,
                member,
                previous_role,
                user,
            })
            .await;
    }

    pub(super) async fn observe_member_invited(
        &self,
        organization: &Organization,
        invitation: &OrganizationInvitation,
        user: &AuthUser,
    ) {
        self.plugins
            .after_organization(&AfterOrganizationEvent::MemberInvited {
                organization,
                invitation,
                user,
            })
            .await;
    }

    pub(super) async fn observe_invitation(
        &self,
        kind: InvitationObservation,
        organization: &Organization,
        invitation: &OrganizationInvitation,
        user: &AuthUser,
        member: Option<&OrganizationMember>,
    ) {
        let event = match (kind, member) {
            (InvitationObservation::Accepted, Some(member)) => {
                AfterOrganizationEvent::InvitationAccepted {
                    organization,
                    invitation,
                    member,
                    user,
                }
            }
            (InvitationObservation::Rejected, _) => AfterOrganizationEvent::InvitationRejected {
                organization,
                invitation,
                user,
            },
            (InvitationObservation::Canceled, _) => AfterOrganizationEvent::InvitationCanceled {
                organization,
                invitation,
                user,
            },
            (InvitationObservation::Accepted, None) => return,
        };
        self.plugins.after_organization(&event).await;
    }

    pub(super) async fn observe_team(
        &self,
        kind: TeamObservation,
        organization: &Organization,
        team: &OrganizationTeam,
        user: &AuthUser,
    ) {
        let event = match kind {
            TeamObservation::Created => AfterOrganizationEvent::TeamCreated {
                organization,
                team,
                user,
            },
            TeamObservation::Updated => AfterOrganizationEvent::TeamUpdated {
                organization,
                team,
                user,
            },
            TeamObservation::Deleted => AfterOrganizationEvent::TeamDeleted {
                organization,
                team,
                user,
            },
        };
        self.plugins.after_organization(&event).await;
    }

    pub(super) async fn observe_team_member(
        &self,
        added: bool,
        organization: &Organization,
        team: &OrganizationTeam,
        team_member: &OrganizationTeamMember,
        user: &AuthUser,
    ) {
        let event = if added {
            AfterOrganizationEvent::TeamMemberAdded {
                organization,
                team,
                team_member,
                user,
            }
        } else {
            AfterOrganizationEvent::TeamMemberRemoved {
                organization,
                team,
                team_member,
                user,
            }
        };
        self.plugins.after_organization(&event).await;
    }
}

pub(super) enum InvitationObservation {
    Accepted,
    Rejected,
    Canceled,
}

pub(super) enum TeamObservation {
    Created,
    Updated,
    Deleted,
}
