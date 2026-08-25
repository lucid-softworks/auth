use super::{MemoryOrganizationStore, State};
use crate::{
    AuthError, Organization, OrganizationCreateOutcome, OrganizationDataStore, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember,
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OrganizationDataStore for MemoryOrganizationStore {
    async fn raw_insert_organization(
        &self,
        organization: Organization,
    ) -> Result<Organization, AuthError> {
        let mut state = self.state.write().await;
        if state
            .organizations
            .values()
            .any(|existing| existing.id == organization.id || existing.slug == organization.slug)
        {
            return Err(AuthError::Storage(
                "test organization id or slug already exists".into(),
            ));
        }
        state
            .organizations
            .insert(organization.id, organization.clone());
        Ok(organization)
    }

    async fn raw_delete_organization(&self, id: Uuid) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state
            .members
            .retain(|_, member| member.organization_id != id);
        state
            .invitations
            .retain(|_, invitation| invitation.organization_id != id);
        if state.organizations.remove(&id).is_some() {
            cascade_delete(&mut state, id);
        }
        Ok(())
    }

    async fn create_organization(
        &self,
        organization: Organization,
        owner: OrganizationMember,
        default_team: Option<(OrganizationTeam, OrganizationTeamMember)>,
        organization_limit: Option<usize>,
    ) -> Result<OrganizationCreateOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state
            .organizations
            .values()
            .any(|existing| existing.slug == organization.slug)
        {
            return Ok(OrganizationCreateOutcome::SlugTaken);
        }
        if organization_limit.is_some_and(|limit| {
            state
                .members
                .values()
                .filter(|member| member.user_id == owner.user_id)
                .count()
                >= limit
        }) {
            return Ok(OrganizationCreateOutcome::LimitReached);
        }
        state.organizations.insert(organization.id, organization);
        state.members.insert(owner.id, owner);
        if let Some((team, team_member)) = default_team {
            state.teams.insert(team.id, team);
            state.team_members.insert(team_member.id, team_member);
        }
        Ok(OrganizationCreateOutcome::Created)
    }

    async fn find_organization_by_id(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        Ok(self.state.read().await.organizations.get(&id).cloned())
    }

    async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .organizations
            .values()
            .find(|organization| organization.slug == slug)
            .cloned())
    }

    async fn list_organizations(&self, user_id: Uuid) -> Result<Vec<Organization>, AuthError> {
        let state = self.state.read().await;
        let mut organizations: Vec<_> = state
            .members
            .values()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.organizations.get(&member.organization_id).cloned())
            .collect();
        organizations.sort_by_key(|organization| (organization.created_at, organization.id));
        Ok(organizations)
    }

    async fn update_organization(
        &self,
        organization: Organization,
    ) -> Result<Option<Organization>, AuthError> {
        let mut state = self.state.write().await;
        if !state.organizations.contains_key(&organization.id)
            || state.organizations.values().any(|existing| {
                existing.id != organization.id && existing.slug == organization.slug
            })
        {
            return Ok(None);
        }
        state
            .organizations
            .insert(organization.id, organization.clone());
        Ok(Some(organization))
    }

    async fn delete_organization(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        let mut state = self.state.write().await;
        let Some(organization) = state.organizations.remove(&id) else {
            return Ok(None);
        };
        cascade_delete(&mut state, id);
        Ok(Some(organization))
    }
}

fn cascade_delete(state: &mut State, organization_id: Uuid) {
    let team_ids: Vec<_> = state
        .teams
        .values()
        .filter(|team| team.organization_id == organization_id)
        .map(|team| team.id)
        .collect();
    state
        .members
        .retain(|_, member| member.organization_id != organization_id);
    state
        .invitations
        .retain(|_, invitation| invitation.organization_id != organization_id);
    state
        .teams
        .retain(|_, team| team.organization_id != organization_id);
    state
        .team_members
        .retain(|_, member| !team_ids.contains(&member.team_id));
    state
        .roles
        .retain(|_, role| role.organization_id != organization_id);
}
