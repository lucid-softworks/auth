use super::super::*;

impl AuthService {
    pub(crate) async fn dash_event_organization_access(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<bool, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::OrganizationPlugin>() else {
            return Ok(false);
        };
        Ok(plugin
            .store
            .find_member(organization_id, user_id)
            .await?
            .is_some())
    }

    pub(crate) async fn dash_elevated_organization_ids(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::OrganizationPlugin>() else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::new();
        for organization in plugin.store.list_organizations(user_id).await? {
            let Some(member) = plugin.store.find_member(&organization.id, user_id).await? else {
                continue;
            };
            if matches!(member.role.as_str(), "owner" | "admin")
                && !ids.contains(&organization.id)
            {
                ids.push(organization.id);
            }
        }
        Ok(ids)
    }

    pub(crate) async fn dash_elevated_organization_access(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<bool, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::OrganizationPlugin>() else {
            return Ok(false);
        };
        Ok(plugin
            .store
            .find_member(organization_id, user_id)
            .await?
            .is_some_and(|member| matches!(member.role.as_str(), "owner" | "admin")))
    }
}
