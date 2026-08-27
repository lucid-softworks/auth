use super::{MemoryOrganizationStore, State, create_id, duplicate_id};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, OrganizationMember, OrganizationTeamMember,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OrganizationInvitationStore for MemoryOrganizationStore {
    async fn create_invitation(
        &self,
        invitation: &mut OrganizationInvitation,
        id: &dyn crate::DatabaseIdSupplier,
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
            .map(|existing| existing.id.clone())
            .collect();
        if !pending_ids.is_empty() && !cancel_pending {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyInvited);
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
        invitation.id = create_id("invitation", id, &mut state)?;
        if state.invitations.contains_key(&invitation.id) {
            return Err(duplicate_id("invitation"));
        }
        for id in pending_ids {
            state
                .invitations
                .get_mut(&id)
                .expect("invitation exists")
                .status = OrganizationInvitationStatus::Canceled;
        }
        state
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        Ok(OrganizationInvitationWriteOutcome::Written)
    }

    async fn find_invitation(&self, id: &str) -> Result<Option<OrganizationInvitation>, AuthError> {
        Ok(self.state.read().await.invitations.get(id).cloned())
    }

    async fn list_invitations(
        &self,
        organization_id: &str,
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
        invitations.sort_by_key(|invitation| (invitation.created_at, invitation.id.clone()));
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
        invitations.sort_by_key(|invitation| (invitation.created_at, invitation.id.clone()));
        Ok(invitations)
    }

    async fn set_invitation_status(
        &self,
        id: &str,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let mut state = self.state.write().await;
        let Some(invitation) = state.invitations.get_mut(id) else {
            return Ok(None);
        };
        invitation.status = status;
        Ok(Some(invitation.clone()))
    }

    async fn resend_invitation(
        &self,
        organization_id: &str,
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
        invitation_id: &str,
        user_id: &str,
        now: DateTime<Utc>,
        membership_limit: usize,
        member_id: &dyn crate::DatabaseIdSupplier,
        team_member_id: &dyn crate::DatabaseIdSupplier,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(invitation) = state.invitations.get(invitation_id).cloned() else {
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
        let (member, team_members) = prepare_acceptance_records(
            &mut state,
            &invitation,
            user_id,
            now,
            member_id,
            team_member_id,
        )?;
        state.members.insert(member.id.clone(), member);
        for team_member in team_members {
            state
                .team_members
                .insert(team_member.id.clone(), team_member);
        }
        state
            .invitations
            .get_mut(invitation_id)
            .expect("invitation exists")
            .status = OrganizationInvitationStatus::Accepted;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }
}

fn prepare_acceptance_records(
    state: &mut State,
    invitation: &OrganizationInvitation,
    user_id: &str,
    now: DateTime<Utc>,
    member_id: &dyn crate::DatabaseIdSupplier,
    team_member_id: &dyn crate::DatabaseIdSupplier,
) -> Result<(OrganizationMember, Vec<OrganizationTeamMember>), AuthError> {
    let member = OrganizationMember {
        id: create_id("member", member_id, state)?,
        organization_id: invitation.organization_id.clone(),
        user_id: user_id.to_owned(),
        role: invitation.role.clone(),
        created_at: now,
    };
    if state.members.contains_key(&member.id) {
        return Err(duplicate_id("member"));
    }
    let mut team_members = Vec::new();
    for team_id in invitation
        .team_id
        .as_deref()
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::to_owned)
    {
        let already_joined = state
            .team_members
            .values()
            .any(|member| member.team_id == team_id && member.user_id == user_id);
        if already_joined {
            continue;
        }
        let team_member = OrganizationTeamMember {
            id: create_id("teamMember", team_member_id, state)?,
            team_id,
            user_id: user_id.to_owned(),
            created_at: now,
        };
        if state.team_members.contains_key(&team_member.id)
            || team_members
                .iter()
                .any(|pending: &OrganizationTeamMember| pending.id == team_member.id)
        {
            return Err(duplicate_id("teamMember"));
        }
        team_members.push(team_member);
    }
    Ok((member, team_members))
}
