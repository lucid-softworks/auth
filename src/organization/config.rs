use super::{Organization, OrganizationInvitation, OrganizationMember, OrganizationPermissions};
use crate::{AuthError, AuthUser};
use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};

#[async_trait]
pub trait OrganizationCreationPolicy: Send + Sync {
    async fn allow(&self, user: &AuthUser) -> Result<bool, AuthError>;
}

#[derive(Debug, Clone)]
pub struct OrganizationInvitationEmail {
    pub invitation: OrganizationInvitation,
    pub organization: Organization,
    pub inviter: OrganizationMember,
    pub inviter_user: AuthUser,
}

#[async_trait]
pub trait OrganizationInvitationEmailSender: Send + Sync {
    async fn send(&self, email: OrganizationInvitationEmail) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct OrganizationTeamsConfig {
    pub enabled: bool,
    pub default_team_enabled: bool,
    pub maximum_teams: Option<usize>,
    pub maximum_members_per_team: Option<usize>,
    pub allow_removing_all_teams: bool,
}

impl Default for OrganizationTeamsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_team_enabled: true,
            maximum_teams: None,
            maximum_members_per_team: None,
            allow_removing_all_teams: false,
        }
    }
}

#[derive(Clone, Default)]
pub struct OrganizationDynamicAccessControlConfig {
    pub enabled: bool,
    pub maximum_roles_per_organization: Option<usize>,
}

#[derive(Clone)]
pub struct OrganizationPluginConfig {
    pub allow_user_to_create_organization: bool,
    pub creation_policy: Option<Arc<dyn OrganizationCreationPolicy>>,
    pub organization_limit: Option<usize>,
    pub creator_role: String,
    pub membership_limit: usize,
    pub roles: BTreeMap<String, OrganizationPermissions>,
    pub teams: OrganizationTeamsConfig,
    pub dynamic_access_control: OrganizationDynamicAccessControlConfig,
    pub invitation_expires_in_seconds: i64,
    pub invitation_limit: usize,
    pub cancel_pending_invitations_on_reinvite: bool,
    pub require_email_verification_on_invitation: Option<bool>,
    pub invitation_email_sender: Option<Arc<dyn OrganizationInvitationEmailSender>>,
    pub disable_organization_deletion: bool,
    pub hooks: Option<Arc<dyn super::OrganizationLifecycleHooks>>,
}

impl Default for OrganizationPluginConfig {
    fn default() -> Self {
        Self {
            allow_user_to_create_organization: true,
            creation_policy: None,
            organization_limit: None,
            creator_role: "owner".into(),
            membership_limit: 100,
            roles: default_roles(),
            teams: OrganizationTeamsConfig::default(),
            dynamic_access_control: OrganizationDynamicAccessControlConfig::default(),
            invitation_expires_in_seconds: 60 * 60 * 48,
            invitation_limit: 100,
            cancel_pending_invitations_on_reinvite: false,
            require_email_verification_on_invitation: None,
            invitation_email_sender: None,
            disable_organization_deletion: false,
            hooks: None,
        }
    }
}

fn default_roles() -> BTreeMap<String, OrganizationPermissions> {
    BTreeMap::from([
        ("owner".into(), full_permissions()),
        (
            "admin".into(),
            permissions(&[
                ("organization", &["update"]),
                ("member", &["create", "update", "delete"]),
                ("invitation", &["create", "cancel"]),
                ("team", &["create", "update", "delete"]),
                ("ac", &["create", "read", "update", "delete"]),
            ]),
        ),
        ("member".into(), permissions(&[("ac", &["read"])])),
    ])
}

fn full_permissions() -> OrganizationPermissions {
    permissions(&[
        ("organization", &["update", "delete"]),
        ("member", &["create", "update", "delete"]),
        ("invitation", &["create", "cancel"]),
        ("team", &["create", "update", "delete"]),
        ("ac", &["create", "read", "update", "delete"]),
    ])
}

fn permissions(entries: &[(&str, &[&str])]) -> OrganizationPermissions {
    entries
        .iter()
        .map(|(resource, actions)| {
            (
                (*resource).to_owned(),
                actions.iter().map(|action| (*action).to_owned()).collect(),
            )
        })
        .collect()
}
