use super::{MemoryOrganizationStore, State, create_id, duplicate_id};
use crate::{
    AuthError, Organization, OrganizationCreateOutcome, OrganizationDataStore, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember,
};
use async_trait::async_trait;

#[async_trait]
impl OrganizationDataStore for MemoryOrganizationStore {
    async fn raw_insert_organization(
        &self,
        mut organization: Organization,
        id: &dyn crate::DatabaseIdSupplier,
    ) -> Result<Organization, AuthError> {
        let mut state = self.state.write().await;
        if state
            .organizations
            .values()
            .any(|existing| existing.slug == organization.slug)
        {
            return Err(AuthError::Storage(
                "test organization slug already exists".into(),
            ));
        }
        organization.id = create_id("organization", id, &mut state)?;
        if state.organizations.contains_key(&organization.id) {
            return Err(duplicate_id("organization"));
        }
        state
            .organizations
            .insert(organization.id.clone(), organization.clone());
        Ok(organization)
    }

    async fn raw_delete_organization(&self, id: &str) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state
            .members
            .retain(|_, member| member.organization_id != id);
        state
            .invitations
            .retain(|_, invitation| invitation.organization_id != id);
        if state.organizations.remove(id).is_some() {
            cascade_delete(&mut state, id);
        }
        Ok(())
    }

    async fn create_organization(
        &self,
        organization: &mut Organization,
        organization_id: &dyn crate::DatabaseIdSupplier,
        owner: &mut OrganizationMember,
        owner_id: &dyn crate::DatabaseIdSupplier,
        default_team: Option<(
            &mut OrganizationTeam,
            &dyn crate::DatabaseIdSupplier,
            &mut OrganizationTeamMember,
            &dyn crate::DatabaseIdSupplier,
        )>,
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
        organization.id = create_id("organization", organization_id, &mut state)?;
        if state.organizations.contains_key(&organization.id) {
            return Err(duplicate_id("organization"));
        }
        owner.id = create_id("member", owner_id, &mut state)?;
        if state.members.contains_key(&owner.id) {
            return Err(duplicate_id("member"));
        }
        owner.organization_id = organization.id.clone();
        if let Some((team, team_id, team_member, team_member_id)) = default_team {
            team.id = create_id("team", team_id, &mut state)?;
            if state.teams.contains_key(&team.id) {
                return Err(duplicate_id("team"));
            }
            team.organization_id = organization.id.clone();
            team_member.id = create_id("teamMember", team_member_id, &mut state)?;
            if state.team_members.contains_key(&team_member.id) {
                return Err(duplicate_id("teamMember"));
            }
            team_member.team_id = team.id.clone();
            state.teams.insert(team.id.clone(), team.clone());
            state
                .team_members
                .insert(team_member.id.clone(), team_member.clone());
        }
        state
            .organizations
            .insert(organization.id.clone(), organization.clone());
        state.members.insert(owner.id.clone(), owner.clone());
        Ok(OrganizationCreateOutcome::Created)
    }

    async fn find_organization_by_id(&self, id: &str) -> Result<Option<Organization>, AuthError> {
        Ok(self.state.read().await.organizations.get(id).cloned())
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

    async fn list_organizations(&self, user_id: &str) -> Result<Vec<Organization>, AuthError> {
        let state = self.state.read().await;
        let mut organizations: Vec<_> = state
            .members
            .values()
            .filter(|member| member.user_id == user_id)
            .filter_map(|member| state.organizations.get(&member.organization_id).cloned())
            .collect();
        organizations
            .sort_by_key(|organization| (organization.created_at, organization.id.clone()));
        Ok(organizations)
    }

    async fn list_all_organizations(&self) -> Result<Vec<Organization>, AuthError> {
        let mut organizations = self
            .state
            .read()
            .await
            .organizations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        organizations.sort_by_key(|organization| (organization.created_at, organization.id.clone()));
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
            .insert(organization.id.clone(), organization.clone());
        Ok(Some(organization))
    }

    async fn delete_organization(&self, id: &str) -> Result<Option<Organization>, AuthError> {
        let mut state = self.state.write().await;
        let Some(organization) = state.organizations.remove(id) else {
            return Ok(None);
        };
        cascade_delete(&mut state, id);
        Ok(Some(organization))
    }
}

fn cascade_delete(state: &mut State, organization_id: &str) {
    let team_ids: Vec<_> = state
        .teams
        .values()
        .filter(|team| team.organization_id == organization_id)
        .map(|team| team.id.clone())
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
