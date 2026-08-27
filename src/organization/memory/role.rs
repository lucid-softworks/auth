use super::{MemoryOrganizationStore, create_id, duplicate_id};
use crate::{AuthError, OrganizationRole, OrganizationRoleStore};
use async_trait::async_trait;

#[async_trait]
impl OrganizationRoleStore for MemoryOrganizationStore {
    async fn create_role(
        &self,
        role: &mut OrganizationRole,
        id: &dyn crate::DatabaseIdSupplier,
        maximum_roles: Option<usize>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        if state.roles.values().any(|existing| {
            existing.organization_id == role.organization_id && existing.role == role.role
        }) {
            return Ok(false);
        }
        if maximum_roles.is_some_and(|limit| {
            state
                .roles
                .values()
                .filter(|existing| existing.organization_id == role.organization_id)
                .count()
                >= limit
        }) {
            return Ok(false);
        }
        role.id = create_id("organizationRole", id, &mut state)?;
        if state.roles.contains_key(&role.id) {
            return Err(duplicate_id("organizationRole"));
        }
        state.roles.insert(role.id.clone(), role.clone());
        Ok(true)
    }

    async fn find_role(&self, id: &str) -> Result<Option<OrganizationRole>, AuthError> {
        Ok(self.state.read().await.roles.get(id).cloned())
    }

    async fn find_role_by_name(
        &self,
        organization_id: &str,
        role: &str,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .roles
            .values()
            .find(|existing| existing.organization_id == organization_id && existing.role == role)
            .cloned())
    }

    async fn list_roles(&self, organization_id: &str) -> Result<Vec<OrganizationRole>, AuthError> {
        let mut roles: Vec<_> = self
            .state
            .read()
            .await
            .roles
            .values()
            .filter(|role| role.organization_id == organization_id)
            .cloned()
            .collect();
        roles.sort_by_key(|role| (role.created_at, role.id.clone()));
        Ok(roles)
    }

    async fn update_role(
        &self,
        role: OrganizationRole,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        let mut state = self.state.write().await;
        if !state.roles.contains_key(&role.id)
            || state.roles.values().any(|existing| {
                existing.id != role.id
                    && existing.organization_id == role.organization_id
                    && existing.role == role.role
            })
        {
            return Ok(None);
        }
        state.roles.insert(role.id.clone(), role.clone());
        Ok(Some(role))
    }

    async fn delete_role(&self, id: &str) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(role) = state.roles.get(id) else {
            return Ok(false);
        };
        if state.members.values().any(|member| {
            member.organization_id == role.organization_id
                && member
                    .role
                    .split(',')
                    .map(str::trim)
                    .any(|assigned| assigned == role.role)
        }) {
            return Ok(false);
        }
        Ok(state.roles.remove(id).is_some())
    }
}
