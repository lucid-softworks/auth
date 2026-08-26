use crate::{AuthError, SessionWithUser};
use std::collections::{BTreeMap, BTreeSet};

mod plugin;

pub use plugin::AdminPlugin;

#[derive(Debug, Clone)]
pub struct AdminCreateUser {
    pub email: String,
    pub password: Option<String>,
    pub name: String,
    pub roles: Vec<String>,
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminListOperator {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminSortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone)]
pub struct AdminListCondition {
    pub field: String,
    pub operator: AdminListOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AdminListUsersQuery {
    pub limit: usize,
    pub offset: usize,
    pub sort_by: Option<String>,
    pub sort_direction: AdminSortDirection,
    pub conditions: Vec<AdminListCondition>,
}

impl Default for AdminListUsersQuery {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: 0,
            sort_by: None,
            sort_direction: AdminSortDirection::Asc,
            conditions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AdminUserUpdate {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub image: Option<Option<String>>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<Option<String>>,
    pub ban_expires: Option<Option<chrono::DateTime<chrono::Utc>>>,
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

pub type AdminPermissionSet = BTreeMap<String, BTreeSet<String>>;

#[derive(Debug, Clone, Default)]
pub struct AdminRole {
    permissions: AdminPermissionSet,
}

impl AdminRole {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.permissions
            .entry(resource.into())
            .or_default()
            .extend(actions.into_iter().map(Into::into));
        self
    }

    pub fn administrator() -> Self {
        Self::new()
            .allow(
                "user",
                [
                    "create",
                    "list",
                    "set-role",
                    "ban",
                    "impersonate",
                    "delete",
                    "set-password",
                    "set-email",
                    "get",
                    "update",
                ],
            )
            .allow("session", ["list", "revoke", "delete"])
    }

    fn authorizes(&self, requested: &AdminPermissionSet) -> bool {
        requested.iter().all(|(resource, actions)| {
            self.permissions
                .get(resource)
                .is_some_and(|allowed| actions.iter().all(|action| allowed.contains(action)))
        })
    }
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub schema: AdminSchema,
    pub default_role: String,
    pub admin_roles: Vec<String>,
    pub roles: BTreeMap<String, AdminRole>,
    pub admin_user_ids: BTreeSet<String>,
    pub default_ban_reason: Option<String>,
    pub default_ban_expires_in_seconds: Option<i64>,
    pub impersonation_session_duration_seconds: i64,
    pub allow_impersonating_admins: bool,
    pub banned_user_message: String,
    custom_roles: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AdminSchema {
    pub user: crate::DatabaseModelSchema,
    pub session: crate::DatabaseModelSchema,
}

impl Default for AdminConfig {
    fn default() -> Self {
        let admin = AdminRole::administrator();
        Self {
            schema: AdminSchema::default(),
            default_role: "user".into(),
            admin_roles: vec!["admin".into()],
            roles: BTreeMap::from([
                ("admin".into(), admin),
                ("user".into(), AdminRole::new()),
            ]),
            admin_user_ids: BTreeSet::new(),
            default_ban_reason: None,
            default_ban_expires_in_seconds: None,
            impersonation_session_duration_seconds: 3_600,
            allow_impersonating_admins: false,
            banned_user_message: "You have been banned from this application. Please contact support if you believe this is an error.".into(),
            custom_roles: false,
        }
    }
}

impl AdminConfig {
    pub fn set_role(&mut self, name: impl Into<String>, role: AdminRole) {
        self.custom_roles = true;
        self.roles.insert(name.into(), role);
    }

    pub(crate) fn has_custom_roles(&self) -> bool {
        self.custom_roles
    }

    pub fn authorizes(&self, user_id: &str, roles: &str, requested: &AdminPermissionSet) -> bool {
        self.admin_user_ids.contains(user_id)
            || roles
                .split(',')
                .map(str::trim)
                .filter_map(|role| self.roles.get(role))
                .any(|role| role.authorizes(requested))
    }

    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        if self.default_role.trim().is_empty() || !self.roles.contains_key(&self.default_role) {
            return invalid("admin default role must name a configured role");
        }
        if self.admin_roles.is_empty()
            || self
                .admin_roles
                .iter()
                .any(|role| !self.roles.contains_key(role))
        {
            return invalid("every admin role must name a configured role");
        }
        if self.roles.keys().any(|role| {
            role.trim().is_empty() || role.contains(',') || role.chars().any(char::is_whitespace)
        }) {
            return invalid("admin role names must be non-empty comma-free identifiers");
        }
        if self.impersonation_session_duration_seconds <= 0 {
            return invalid("admin impersonation duration must be positive");
        }
        if self
            .default_ban_expires_in_seconds
            .is_some_and(|seconds| seconds <= 0)
        {
            return invalid("admin default ban expiry must be positive");
        }
        Ok(())
    }

    pub(crate) fn is_admin_target(&self, user_id: &str, roles: &str) -> bool {
        self.admin_user_ids.contains(user_id)
            || roles
                .split(',')
                .map(str::trim)
                .any(|role| self.admin_roles.iter().any(|admin| admin == role))
    }
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}

pub(crate) fn permission(resource: &str, actions: &[&str]) -> AdminPermissionSet {
    BTreeMap::from([(
        resource.to_owned(),
        actions.iter().map(|action| (*action).to_owned()).collect(),
    )])
}

pub(crate) fn sanitize_additional_fields(fields: &mut serde_json::Map<String, serde_json::Value>) {
    for reserved in [
        "id",
        "name",
        "email",
        "createdAt",
        "updatedAt",
        "username",
        "displayUsername",
        "isAnonymous",
        "role",
        "twoFactorEnabled",
    ] {
        fields.remove(reserved);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdminError {
    #[error("the administrator cannot create users")]
    CannotCreateUsers,
    #[error("the administrator cannot list users")]
    CannotListUsers,
    #[error("the administrator cannot get users")]
    CannotGetUser,
    #[error("the administrator cannot update users")]
    CannotUpdateUsers,
    #[error("the administrator cannot change user roles")]
    CannotSetRole,
    #[error("the administrator cannot ban users")]
    CannotBanUsers,
    #[error("the administrator cannot impersonate users")]
    CannotImpersonateUsers,
    #[error("the administrator cannot delete users")]
    CannotDeleteUsers,
    #[error("the administrator cannot set user passwords")]
    CannotSetPassword,
    #[error("the administrator cannot set user email addresses")]
    CannotSetEmail,
    #[error("the administrator cannot list user sessions")]
    CannotListSessions,
    #[error("the administrator cannot revoke user sessions")]
    CannotRevokeSessions,
    #[error("the configured role does not exist")]
    RoleNotFound,
    #[error("the role value has an invalid type")]
    InvalidRoleType,
    #[error("an administrator cannot ban themselves")]
    CannotBanSelf,
    #[error("an administrator cannot remove themselves")]
    CannotRemoveSelf,
    #[error("the target administrator cannot be impersonated")]
    CannotImpersonateAdmin,
    #[error("no user data was supplied")]
    NoDataToUpdate,
    #[error("passwords must use the set-user-password endpoint")]
    PasswordUpdateForbidden,
    #[error("the administrator target user was not found")]
    UserNotFound,
    #[error("an administrator-created user already has this email")]
    UserAlreadyExistsEmail,
}

pub(crate) fn require_permission(
    config: &AdminConfig,
    session: &SessionWithUser,
    resource: &str,
    actions: &[&str],
) -> Result<(), AuthError> {
    if config.authorizes(
        &session.user.id,
        &session.user.role,
        &permission(resource, actions),
    ) {
        Ok(())
    } else {
        Err(permission_error(resource, actions).into())
    }
}

fn permission_error(resource: &str, actions: &[&str]) -> AdminError {
    match (resource, actions.first().copied()) {
        ("user", Some("create")) => AdminError::CannotCreateUsers,
        ("user", Some("list")) => AdminError::CannotListUsers,
        ("user", Some("get")) => AdminError::CannotGetUser,
        ("user", Some("update")) => AdminError::CannotUpdateUsers,
        ("user", Some("set-role")) => AdminError::CannotSetRole,
        ("user", Some("ban")) => AdminError::CannotBanUsers,
        ("user", Some("impersonate")) => AdminError::CannotImpersonateUsers,
        ("user", Some("delete")) => AdminError::CannotDeleteUsers,
        ("user", Some("set-password")) => AdminError::CannotSetPassword,
        ("user", Some("set-email")) => AdminError::CannotSetEmail,
        ("session", Some("list")) => AdminError::CannotListSessions,
        _ => AdminError::CannotRevokeSessions,
    }
}
