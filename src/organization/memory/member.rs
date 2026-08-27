use super::{MemoryOrganizationStore, create_id, duplicate_id, has_role};
use crate::{
    AuthError, OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
};
use async_trait::async_trait;

#[async_trait]
impl OrganizationMemberStore for MemoryOrganizationStore {
    async fn raw_insert_member(
        &self,
        mut member: OrganizationMember,
        id: &dyn crate::DatabaseIdSupplier,
    ) -> Result<OrganizationMember, AuthError> {
        let mut state = self.state.write().await;
        if state.members.values().any(|existing| {
            existing.organization_id == member.organization_id && existing.user_id == member.user_id
        }) {
            return Err(AuthError::Storage(
                "test organization member already exists".into(),
            ));
        }
        member.id = create_id("member", id, &mut state)?;
        if state.members.contains_key(&member.id) {
            return Err(duplicate_id("member"));
        }
        state.members.insert(member.id.clone(), member.clone());
        Ok(member)
    }

    async fn find_member_by_id(&self, id: &str) -> Result<Option<OrganizationMember>, AuthError> {
        Ok(self.state.read().await.members.get(id).cloned())
    }

    async fn find_member(
        &self,
        organization_id: &str,
        user_id: &str,
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
        organization_id: &str,
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
        members.sort_by_key(|member| (member.created_at, member.id.clone()));
        Ok(members)
    }

    async fn add_member(
        &self,
        member: &mut OrganizationMember,
        id: &dyn crate::DatabaseIdSupplier,
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
        member.id = create_id("member", id, &mut state)?;
        if state.members.contains_key(&member.id) {
            return Err(duplicate_id("member"));
        }
        state.members.insert(member.id.clone(), member.clone());
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: &str,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(current) = state.members.get(member_id).cloned() else {
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
            .get_mut(member_id)
            .expect("member exists")
            .role = role;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn remove_member(
        &self,
        member_id: &str,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(member) = state.members.get(member_id).cloned() else {
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
        state.members.remove(member_id);
        let organization_team_ids: Vec<_> = state
            .teams
            .values()
            .filter(|team| team.organization_id == member.organization_id)
            .map(|team| team.id.clone())
            .collect();
        state.team_members.retain(|_, team_member| {
            team_member.user_id != member.user_id
                || !organization_team_ids.contains(&team_member.team_id)
        });
        Ok(OrganizationMemberWriteOutcome::Written)
    }
}
