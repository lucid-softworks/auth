use super::{MemoryOrganizationStore, has_role};
use crate::{
    AuthError, OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OrganizationMemberStore for MemoryOrganizationStore {
    async fn find_member_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>, AuthError> {
        Ok(self.state.read().await.members.get(&id).cloned())
    }

    async fn find_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .members
            .values()
            .find(|member| member.organization_id == organization_id && member.user_id == user_id)
            .cloned())
    }

    async fn list_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, AuthError> {
        let mut members: Vec<_> = self
            .state
            .read()
            .await
            .members
            .values()
            .filter(|member| member.organization_id == organization_id)
            .cloned()
            .collect();
        members.sort_by_key(|member| (member.created_at, member.id));
        Ok(members)
    }

    async fn add_member(
        &self,
        member: OrganizationMember,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state.members.values().any(|existing| {
            existing.organization_id == member.organization_id && existing.user_id == member.user_id
        }) {
            return Ok(OrganizationMemberWriteOutcome::AlreadyMember);
        }
        if state
            .members
            .values()
            .filter(|existing| existing.organization_id == member.organization_id)
            .count()
            >= membership_limit
        {
            return Ok(OrganizationMemberWriteOutcome::LimitReached);
        }
        state.members.insert(member.id, member);
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: Uuid,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(current) = state.members.get(&member_id).cloned() else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        if has_role(&current, creator_role)
            && !role
                .split(',')
                .map(str::trim)
                .any(|value| value == creator_role)
            && state
                .members
                .values()
                .filter(|member| member.organization_id == current.organization_id)
                .filter(|member| has_role(member, creator_role))
                .count()
                <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        state
            .members
            .get_mut(&member_id)
            .expect("member exists")
            .role = role;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn remove_member(
        &self,
        member_id: Uuid,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(member) = state.members.get(&member_id).cloned() else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        if has_role(&member, creator_role)
            && state
                .members
                .values()
                .filter(|other| other.organization_id == member.organization_id)
                .filter(|other| has_role(other, creator_role))
                .count()
                <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        state.members.remove(&member_id);
        let organization_team_ids: Vec<_> = state
            .teams
            .values()
            .filter(|team| team.organization_id == member.organization_id)
            .map(|team| team.id)
            .collect();
        state.team_members.retain(|_, team_member| {
            team_member.user_id != member.user_id
                || !organization_team_ids.contains(&team_member.team_id)
        });
        Ok(OrganizationMemberWriteOutcome::Written)
    }
}
