use super::MemoryOrganizationStore;
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, OrganizationMember, OrganizationTeamMember,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl OrganizationInvitationStore for MemoryOrganizationStore {
    async fn create_invitation(
        &self,
        invitation: OrganizationInvitation,
        invitation_limit: usize,
        membership_limit: usize,
        cancel_pending: bool,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state
            .members
            .values()
            .filter(|member| member.organization_id == invitation.organization_id)
            .count()
            >= membership_limit
        {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        let pending_ids: Vec<_> = state
            .invitations
            .values()
            .filter(|existing| {
                existing.organization_id == invitation.organization_id
                    && existing.email.eq_ignore_ascii_case(&invitation.email)
                    && existing.status == OrganizationInvitationStatus::Pending
            })
            .map(|existing| existing.id)
            .collect();
        if !pending_ids.is_empty() && !cancel_pending {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyInvited);
        }
        for id in pending_ids {
            state
                .invitations
                .get_mut(&id)
                .expect("invitation exists")
                .status = OrganizationInvitationStatus::Canceled;
        }
        if state
            .invitations
            .values()
            .filter(|existing| {
                existing.organization_id == invitation.organization_id
                    && existing.status == OrganizationInvitationStatus::Pending
            })
            .count()
            >= invitation_limit
        {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        state.invitations.insert(invitation.id, invitation);
        Ok(OrganizationInvitationWriteOutcome::Written)
    }

    async fn find_invitation(&self, id: Uuid) -> Result<Option<OrganizationInvitation>, AuthError> {
        Ok(self.state.read().await.invitations.get(&id).cloned())
    }

    async fn list_invitations(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let mut invitations: Vec<_> = self
            .state
            .read()
            .await
            .invitations
            .values()
            .filter(|invitation| invitation.organization_id == organization_id)
            .cloned()
            .collect();
        invitations.sort_by_key(|invitation| (invitation.created_at, invitation.id));
        Ok(invitations)
    }

    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let mut invitations: Vec<_> = self
            .state
            .read()
            .await
            .invitations
            .values()
            .filter(|invitation| invitation.email.eq_ignore_ascii_case(email))
            .cloned()
            .collect();
        invitations.sort_by_key(|invitation| (invitation.created_at, invitation.id));
        Ok(invitations)
    }

    async fn set_invitation_status(
        &self,
        id: Uuid,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let mut state = self.state.write().await;
        let Some(invitation) = state.invitations.get_mut(&id) else {
            return Ok(None);
        };
        invitation.status = status;
        Ok(Some(invitation.clone()))
    }

    async fn resend_invitation(
        &self,
        organization_id: Uuid,
        email: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let mut state = self.state.write().await;
        let Some(invitation) = state.invitations.values_mut().find(|invitation| {
            invitation.organization_id == organization_id
                && invitation.email.eq_ignore_ascii_case(email)
                && invitation.status == OrganizationInvitationStatus::Pending
        }) else {
            return Ok(None);
        };
        invitation.expires_at = expires_at;
        Ok(Some(invitation.clone()))
    }

    async fn accept_invitation(
        &self,
        invitation_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
        membership_limit: usize,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(invitation) = state.invitations.get(&invitation_id).cloned() else {
            return Ok(OrganizationInvitationWriteOutcome::NotFound);
        };
        if invitation.status != OrganizationInvitationStatus::Pending {
            return Ok(OrganizationInvitationWriteOutcome::NotFound);
        }
        if invitation.expires_at <= now {
            return Ok(OrganizationInvitationWriteOutcome::Expired);
        }
        if state.members.values().any(|member| {
            member.organization_id == invitation.organization_id && member.user_id == user_id
        }) {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyMember);
        }
        if state
            .members
            .values()
            .filter(|member| member.organization_id == invitation.organization_id)
            .count()
            >= membership_limit
        {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        let member = OrganizationMember {
            id: Uuid::new_v4(),
            organization_id: invitation.organization_id,
            user_id,
            role: invitation.role,
            created_at: now,
        };
        state.members.insert(member.id, member);
        for team_id in invitation
            .team_id
            .as_deref()
            .into_iter()
            .flat_map(|value| value.split(','))
            .filter_map(|value| Uuid::parse_str(value).ok())
        {
            if !state
                .team_members
                .values()
                .any(|member| member.team_id == team_id && member.user_id == user_id)
            {
                let team_member = OrganizationTeamMember {
                    id: Uuid::new_v4(),
                    team_id,
                    user_id,
                    created_at: now,
                };
                state.team_members.insert(team_member.id, team_member);
            }
        }
        state
            .invitations
            .get_mut(&invitation_id)
            .expect("invitation exists")
            .status = OrganizationInvitationStatus::Accepted;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }
}
