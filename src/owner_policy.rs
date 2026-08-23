use crate::{
    AdminConfig, AdminPlugin, AdminRole, AuthConfig, AuthError, AuthPlugin, AuthStore,
    PluginDescriptor, SensitiveOperation, SessionWithUser, UserManagementAction,
    UserManagementDecision, UserManagementOperation,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::BTreeSet;

const ROLES: [&str; 3] = ["owner", "member", "viewer"];

/// Optional lucid host policy layered over Better Auth's configurable Admin plugin.
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerPolicyPlugin;

impl OwnerPolicyPlugin {
    /// Builds the matching fixed-role Admin configuration required by this policy.
    pub fn admin_config() -> AdminConfig {
        let mut admin = AdminConfig::default();
        admin.roles.clear();
        admin.set_role("owner", AdminRole::administrator());
        admin.set_role("member", AdminRole::new());
        admin.set_role("viewer", AdminRole::new());
        admin.default_role = "member".into();
        admin.admin_roles = vec!["owner".into()];
        admin
    }

    /// Builds the matching Step-Up preset for the fixed owner role.
    pub fn step_up_config() -> crate::StepUpPolicyConfig {
        crate::StepUpPolicyConfig {
            required_roles: vec!["owner".into()],
            ..crate::StepUpPolicyConfig::default()
        }
    }

    pub(crate) fn is_owner_user(&self, user: &crate::AuthUser) -> bool {
        !user.is_anonymous && user.role == "owner" && !account_is_banned(user)
    }

    pub(crate) fn owner_role(&self) -> &'static str {
        "owner"
    }

    fn is_owner_session(&self, session: &SessionWithUser) -> bool {
        self.is_owner_user(&session.user) && session.session.actor_user_id.is_none()
    }

    async fn protect_final_owner(
        &self,
        store: &dyn AuthStore,
        target: &crate::AuthUser,
        removing_owner: bool,
    ) -> Result<(), AuthError> {
        if removing_owner
            && target.role == "owner"
            && store.count_users_by_role("owner").await? <= 1
        {
            return Err(AuthError::LastOwner);
        }
        Ok(())
    }

    fn validate_role(role: &str) -> Result<(), AuthError> {
        let roles: Vec<_> = role.split(',').map(str::trim).collect();
        if roles.len() != 1 || !ROLES.contains(&roles[0]) {
            return Err(AuthError::InvalidRequest(
                "owner policy roles must be owner, member, or viewer".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin for OwnerPolicyPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "lucid-owner-policy",
            display_name: "lucid-auth Owner Policy",
            version: env!("CARGO_PKG_VERSION"),
            dependencies: &["admin"],
            conflicts: &[],
            endpoints: &[],
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, config: &AuthConfig) -> Result<(), AuthError> {
        let admin = config
            .plugins
            .iter()
            .find_map(|plugin| plugin.as_any().downcast_ref::<AdminPlugin>())
            .map(AdminPlugin::config)
            .ok_or_else(|| {
                AuthError::InvalidConfiguration(
                    "owner-policy plugin requires the admin plugin".into(),
                )
            })?;
        let configured: BTreeSet<_> = admin.roles.keys().map(String::as_str).collect();
        let expected = BTreeSet::from(ROLES);
        if configured != expected
            || admin.default_role != "member"
            || admin.admin_roles.as_slice() != ["owner"]
        {
            return Err(AuthError::InvalidConfiguration(
                "owner-policy plugin requires OwnerPolicyPlugin::admin_config()".into(),
            ));
        }
        Ok(())
    }

    async fn authorize_sensitive(
        &self,
        operation: &SensitiveOperation<'_>,
    ) -> Result<(), AuthError> {
        if matches!(
            operation.operation,
            "admin" | "owner-administration" | "guest-capability.manage" | "audit.list"
        ) && !self.is_owner_session(operation.session)
        {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }

    async fn authorize_user_management(
        &self,
        store: &dyn AuthStore,
        operation: &UserManagementOperation<'_>,
    ) -> Result<UserManagementDecision, AuthError> {
        if !self.is_owner_session(operation.actor) {
            return Err(AuthError::Forbidden);
        }
        let mut decision = UserManagementDecision::default();
        match operation.action {
            UserManagementAction::Create { role } => Self::validate_role(role)?,
            UserManagementAction::ChangeRole { target, new_role } => {
                Self::validate_role(new_role)?;
                self.protect_final_owner(store, target, new_role != "owner")
                    .await?;
                decision.revoke_target_sessions = new_role == "owner" && target.role != "owner";
            }
            UserManagementAction::ChangeBan { target, banned } => {
                self.protect_final_owner(store, target, banned).await?;
            }
            UserManagementAction::Delete { target } => {
                self.protect_final_owner(store, target, true).await?;
            }
        }
        Ok(decision)
    }

    fn project_principal(&self, session: &SessionWithUser, principal: &mut crate::Principal) {
        principal.role = Some(session.user.role.clone());
    }
}

fn account_is_banned(user: &crate::AuthUser) -> bool {
    user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now())
}
