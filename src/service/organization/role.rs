use super::AuthService;
use crate::{
    AuthError, OrganizationError, OrganizationPermissions, OrganizationRole, SessionWithUser,
};
use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet};

impl AuthService {
    pub async fn create_organization_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        role: String,
        permission: OrganizationPermissions,
    ) -> Result<OrganizationRole, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_ac_permission(self, &member, "create").await?;
        validate_permission_resources(plugin, &permission)?;
        if !self
            .organization_has_permission(&member, &permission, false)
            .await?
        {
            return Err(OrganizationError::forbidden(
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
                "You are not allowed to create a role",
            )
            .into());
        }
        let role_name = role.to_lowercase();
        ensure_role_name_available(plugin, &organization_id, &role_name, None).await?;
        if let Some(limit) = plugin
            .config
            .dynamic_access_control
            .maximum_roles_per_organization
            && plugin.store.list_roles(&organization_id).await?.len() >= limit
        {
            return Err(OrganizationError::bad_request(
                "TOO_MANY_ROLES",
                "This organization has too many roles",
            )
            .into());
        }
        let mut role = OrganizationRole {
            id: String::new(),
            organization_id: organization_id.clone(),
            role: role_name.clone(),
            permission,
            created_at: Utc::now(),
            updated_at: None,
        };
        let plan = self.database_id_plan("organizationRole", crate::DatabaseIdInput::Absent, false);
        let id = || plan.prepare(self.store.as_ref());
        if plugin
            .store
            .create_role(
                &mut role,
                &id,
                plugin
                    .config
                    .dynamic_access_control
                    .maximum_roles_per_organization,
            )
            .await?
        {
            Ok(role)
        } else if plugin
            .store
            .find_role_by_name(&organization_id, &role_name)
            .await?
            .is_some()
        {
            Err(role_name_taken())
        } else {
            Err(OrganizationError::bad_request(
                "TOO_MANY_ROLES",
                "This organization has too many roles",
            )
            .into())
        }
    }

    pub async fn list_organization_roles(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
    ) -> Result<Vec<OrganizationRole>, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_ac_permission(self, &member, "read").await?;
        plugin.store.list_roles(&organization_id).await
    }

    pub async fn get_organization_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        role_id: Option<String>,
        role_name: Option<&str>,
    ) -> Result<OrganizationRole, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_ac_permission(self, &member, "read").await?;
        find_role(plugin, &organization_id, role_id, role_name)
            .await?
            .ok_or_else(role_not_found)
    }

    pub async fn update_organization_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        role_id: Option<String>,
        role_name: Option<&str>,
        new_name: Option<String>,
        permission: Option<OrganizationPermissions>,
    ) -> Result<OrganizationRole, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_ac_permission(self, &member, "update").await?;
        let mut role = find_role(plugin, &organization_id, role_id, role_name)
            .await?
            .ok_or_else(role_not_found)?;
        if let Some(permission) = permission {
            validate_permission_resources(plugin, &permission)?;
            if !self
                .organization_has_permission(&member, &permission, false)
                .await?
            {
                return Err(OrganizationError::forbidden(
                    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
                    "You are not allowed to update a role",
                )
                .into());
            }
            role.permission = permission;
        }
        if let Some(name) = new_name {
            let name = name.to_lowercase();
            ensure_role_name_available(plugin, &organization_id, &name, Some(role.id.clone()))
                .await?;
            role.role = name;
        }
        role.updated_at = Some(Utc::now());
        plugin
            .store
            .update_role(role)
            .await?
            .ok_or_else(role_name_taken)
    }

    pub async fn delete_organization_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        role_id: Option<String>,
        role_name: Option<&str>,
    ) -> Result<(), AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_ac_permission(self, &member, "delete").await?;
        if role_name.is_some_and(|name| plugin.config.roles.contains_key(name)) {
            return Err(OrganizationError::bad_request(
                "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
                "Cannot delete a pre-defined role",
            )
            .into());
        }
        let role = find_role(plugin, &organization_id, role_id, role_name)
            .await?
            .ok_or_else(role_not_found)?;
        if plugin
            .store
            .list_members(&organization_id)
            .await?
            .iter()
            .any(|member| {
                member
                    .role
                    .split(',')
                    .map(str::trim)
                    .any(|name| name == role.role)
            })
        {
            return Err(OrganizationError::bad_request(
                "ROLE_IS_ASSIGNED_TO_MEMBERS",
                "Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
            )
            .into());
        }
        if plugin.store.delete_role(&role.id).await? {
            Ok(())
        } else {
            Err(role_not_found())
        }
    }
}

async fn require_ac_permission(
    service: &AuthService,
    member: &crate::OrganizationMember,
    action: &str,
) -> Result<(), AuthError> {
    let permission = BTreeMap::from([("ac".into(), vec![action.into()])]);
    if service
        .organization_has_permission(member, &permission, false)
        .await?
    {
        Ok(())
    } else {
        let code = match action {
            "create" => "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
            "update" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
            "delete" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
            _ => "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
        };
        Err(OrganizationError::forbidden(code, "You are not allowed to access this role").into())
    }
}

async fn require_member(
    plugin: &crate::OrganizationPlugin,
    organization_id: &str,
    user_id: &str,
) -> Result<crate::OrganizationMember, AuthError> {
    plugin
        .store
        .find_member(organization_id, user_id)
        .await?
        .ok_or_else(|| {
            OrganizationError::forbidden(
                "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
                "You are not a member of this organization",
            )
            .into()
        })
}

async fn find_role(
    plugin: &crate::OrganizationPlugin,
    organization_id: &str,
    role_id: Option<String>,
    role_name: Option<&str>,
) -> Result<Option<OrganizationRole>, AuthError> {
    match (role_id, role_name) {
        (Some(id), _) => Ok(plugin
            .store
            .find_role(&id)
            .await?
            .filter(|role| role.organization_id == organization_id)),
        (None, Some(name)) => plugin.store.find_role_by_name(organization_id, name).await,
        _ => Ok(None),
    }
}

async fn ensure_role_name_available(
    plugin: &crate::OrganizationPlugin,
    organization_id: &str,
    name: &str,
    current_id: Option<String>,
) -> Result<(), AuthError> {
    if plugin.config.roles.contains_key(name)
        || plugin
            .store
            .find_role_by_name(organization_id, name)
            .await?
            .is_some_and(|role| Some(role.id) != current_id)
    {
        Err(role_name_taken())
    } else {
        Ok(())
    }
}

fn validate_permission_resources(
    plugin: &crate::OrganizationPlugin,
    permission: &OrganizationPermissions,
) -> Result<(), AuthError> {
    let resources: BTreeSet<_> = plugin
        .config
        .roles
        .values()
        .flat_map(|permissions| permissions.keys().cloned())
        .collect();
    if permission
        .keys()
        .any(|resource| !resources.contains(resource))
    {
        Err(OrganizationError::bad_request(
            "INVALID_RESOURCE",
            "The provided permission includes an invalid resource",
        )
        .into())
    } else {
        Ok(())
    }
}

fn active_or(
    session: &SessionWithUser,
    organization_id: Option<String>,
) -> Result<String, AuthError> {
    organization_id
        .or_else(|| AuthService::active_organization_id(session))
        .ok_or_else(|| {
            OrganizationError::bad_request("NO_ACTIVE_ORGANIZATION", "No active organization")
                .into()
        })
}

fn role_name_taken() -> AuthError {
    OrganizationError::bad_request(
        "ROLE_NAME_IS_ALREADY_TAKEN",
        "That role name is already taken",
    )
    .into()
}

fn role_not_found() -> AuthError {
    OrganizationError::bad_request("ROLE_NOT_FOUND", "Role not found").into()
}
