use super::AuthService;
use crate::{AuthError, OrganizationMember, OrganizationPermissions};

impl AuthService {
    pub(crate) async fn organization_has_permission(
        &self,
        member: &OrganizationMember,
        required: &OrganizationPermissions,
        allow_creator_all: bool,
    ) -> Result<bool, AuthError> {
        let plugin = self.organization_plugin()?;
        let roles: Vec<_> = member
            .role
            .split(',')
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .collect();
        if allow_creator_all && roles.contains(&plugin.config.creator_role.as_str()) {
            return Ok(true);
        }
        for role in roles {
            let permissions = match plugin.config.roles.get(role) {
                Some(permissions) => Some(permissions.clone()),
                None if plugin.config.dynamic_access_control.enabled => plugin
                    .store
                    .find_role_by_name(member.organization_id, role)
                    .await?
                    .map(|role| role.permission),
                None => None,
            };
            if permissions.is_some_and(|permissions| authorizes(&permissions, required)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) async fn organization_role_exists(
        &self,
        organization_id: uuid::Uuid,
        roles: &str,
    ) -> Result<bool, AuthError> {
        let plugin = self.organization_plugin()?;
        for role in roles
            .split(',')
            .map(str::trim)
            .filter(|role| !role.is_empty())
        {
            if plugin.config.roles.contains_key(role) {
                continue;
            }
            if !plugin.config.dynamic_access_control.enabled
                || plugin
                    .store
                    .find_role_by_name(organization_id, role)
                    .await?
                    .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn authorizes(available: &OrganizationPermissions, required: &OrganizationPermissions) -> bool {
    required.iter().all(|(resource, actions)| {
        available
            .get(resource)
            .is_some_and(|allowed| actions.iter().all(|action| allowed.contains(action)))
    })
}
