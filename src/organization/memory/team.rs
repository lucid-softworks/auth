use super::MemoryOrganizationStore;
use crate::{
    AuthError, OrganizationTeam, OrganizationTeamMember, OrganizationTeamStore,
    OrganizationTeamWriteOutcome,
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OrganizationTeamStore for MemoryOrganizationStore {
    async fn create_team(
        &self,
        team: OrganizationTeam,
        maximum_teams: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state.teams.values().any(|existing| {
            existing.organization_id == team.organization_id && existing.name == team.name
        }) {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if maximum_teams.is_some_and(|limit| {
            state
                .teams
                .values()
                .filter(|existing| existing.organization_id == team.organization_id)
                .count()
                >= limit
        }) {
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        state.teams.insert(team.id, team);
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn find_team(&self, id: Uuid) -> Result<Option<OrganizationTeam>, AuthError> {
        Ok(self.state.read().await.teams.get(&id).cloned())
    }

    async fn list_teams(&self, organization_id: Uuid) -> Result<Vec<OrganizationTeam>, AuthError> {
        let mut teams: Vec<_> = self
            .state
            .read()
            .await
            .teams
            .values()
            .filter(|team| team.organization_id == organization_id)
            .cloned()
            .collect();
        teams.sort_by_key(|team| (team.created_at, team.id));
        Ok(teams)
    }

    async fn update_team(
        &self,
        team: OrganizationTeam,
    ) -> Result<Option<OrganizationTeam>, AuthError> {
        let mut state = self.state.write().await;
        if !state.teams.contains_key(&team.id)
            || state.teams.values().any(|existing| {
                existing.id != team.id
                    && existing.organization_id == team.organization_id
                    && existing.name == team.name
            })
        {
            return Ok(None);
        }
        state.teams.insert(team.id, team.clone());
        Ok(Some(team))
    }

    async fn remove_team(
        &self,
        id: Uuid,
        allow_removing_all: bool,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(team) = state.teams.get(&id).cloned() else {
            return Ok(OrganizationTeamWriteOutcome::NotFound);
        };
        if !allow_removing_all
            && state
                .teams
                .values()
                .filter(|candidate| candidate.organization_id == team.organization_id)
                .count()
                <= 1
        {
            return Ok(OrganizationTeamWriteOutcome::LastTeam);
        }
        state.teams.remove(&id);
        state.team_members.retain(|_, member| member.team_id != id);
        let id = id.to_string();
        for invitation in state.invitations.values_mut().filter(|invitation| {
            invitation.organization_id == team.organization_id
                && invitation.status == crate::OrganizationInvitationStatus::Pending
        }) {
            let remaining = invitation
                .team_id
                .as_deref()
                .into_iter()
                .flat_map(|ids| ids.split(','))
                .filter(|candidate| *candidate != id)
                .collect::<Vec<_>>()
                .join(",");
            invitation.team_id = (!remaining.is_empty()).then_some(remaining);
        }
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn add_team_member(
        &self,
        member: OrganizationTeamMember,
        maximum_members: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state.team_members.values().any(|existing| {
            existing.team_id == member.team_id && existing.user_id == member.user_id
        }) {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if maximum_members.is_some_and(|limit| {
            state
                .team_members
                .values()
                .filter(|existing| existing.team_id == member.team_id)
                .count()
                >= limit
        }) {
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        state.team_members.insert(member.id, member);
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn remove_team_member(
        &self,
        team_id: Uuid,
        user_id: &str,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(id) = state
            .team_members
            .values()
            .find(|member| member.team_id == team_id && member.user_id == user_id)
            .map(|member| member.id)
        else {
            return Ok(OrganizationTeamWriteOutcome::NotFound);
        };
        state.team_members.remove(&id);
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn list_team_members(
        &self,
        team_id: Uuid,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError> {
        let mut members: Vec<_> = self
            .state
            .read()
            .await
            .team_members
            .values()
            .filter(|member| member.team_id == team_id)
            .cloned()
            .collect();
        members.sort_by_key(|member| (member.created_at, member.id));
        Ok(members)
    }

    async fn list_user_teams(&self, user_id: &str) -> Result<Vec<OrganizationTeam>, AuthError> {
        let state = self.state.read().await;
        let mut teams: Vec<_> = state
            .team_members
            .values()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.teams.get(&member.team_id).cloned())
            .collect();
        teams.sort_by_key(|team| (team.created_at, team.id));
        Ok(teams)
    }
}
