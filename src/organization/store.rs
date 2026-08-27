use super::{
    Organization, OrganizationInvitation, OrganizationInvitationStatus, OrganizationMember,
    OrganizationRole, OrganizationTeam, OrganizationTeamMember,
};
use crate::{AuthError, DatabaseIdSupplier};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationCreateOutcome {
    Created,
    SlugTaken,
    LimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationMemberWriteOutcome {
    Written,
    AlreadyMember,
    LimitReached,
    LastOwner,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationInvitationWriteOutcome {
    Written,
    AlreadyInvited,
    AlreadyMember,
    LimitReached,
    Expired,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationTeamWriteOutcome {
    Written,
    AlreadyExists,
    LimitReached,
    LastTeam,
    NotFound,
}

pub trait OrganizationStore:
    OrganizationDataStore
    + OrganizationMemberStore
    + OrganizationInvitationStore
    + OrganizationTeamStore
    + OrganizationRoleStore
    + Send
    + Sync
{
}

impl<T> OrganizationStore for T where
    T: OrganizationDataStore
        + OrganizationMemberStore
        + OrganizationInvitationStore
        + OrganizationTeamStore
        + OrganizationRoleStore
        + Send
        + Sync
{
}

#[async_trait]
pub trait OrganizationDataStore: Send + Sync {
    /// Raw insert used only by Better Auth's privileged Test Utils plugin.
    async fn raw_insert_organization(
        &self,
        organization: Organization,
        id: &dyn DatabaseIdSupplier,
    ) -> Result<Organization, AuthError>;
    /// Ordered raw deletion used only by Better Auth's privileged Test Utils plugin.
    async fn raw_delete_organization(&self, id: &str) -> Result<(), AuthError>;

    async fn create_organization(
        &self,
        organization: &mut Organization,
        organization_id: &dyn DatabaseIdSupplier,
        owner: &mut OrganizationMember,
        owner_id: &dyn DatabaseIdSupplier,
        default_team: Option<(
            &mut OrganizationTeam,
            &dyn DatabaseIdSupplier,
            &mut OrganizationTeamMember,
            &dyn DatabaseIdSupplier,
        )>,
        organization_limit: Option<usize>,
    ) -> Result<OrganizationCreateOutcome, AuthError>;
    async fn find_organization_by_id(&self, id: &str) -> Result<Option<Organization>, AuthError>;
    async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AuthError>;
    async fn list_organizations(&self, user_id: &str) -> Result<Vec<Organization>, AuthError>;
    async fn update_organization(
        &self,
        organization: Organization,
    ) -> Result<Option<Organization>, AuthError>;
    async fn delete_organization(&self, id: &str) -> Result<Option<Organization>, AuthError>;
}

#[async_trait]
pub trait OrganizationMemberStore: Send + Sync {
    /// Raw insert used only by Better Auth's privileged Test Utils plugin.
    async fn raw_insert_member(
        &self,
        member: OrganizationMember,
        id: &dyn DatabaseIdSupplier,
    ) -> Result<OrganizationMember, AuthError>;

    async fn find_member_by_id(&self, id: &str) -> Result<Option<OrganizationMember>, AuthError>;
    async fn find_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, AuthError>;
    async fn list_members(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationMember>, AuthError>;
    async fn add_member(
        &self,
        member: &mut OrganizationMember,
        id: &dyn DatabaseIdSupplier,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError>;
    async fn update_member_role(
        &self,
        member_id: &str,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError>;
    async fn remove_member(
        &self,
        member_id: &str,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError>;
}

#[async_trait]
pub trait OrganizationInvitationStore: Send + Sync {
    async fn create_invitation(
        &self,
        invitation: &mut OrganizationInvitation,
        id: &dyn DatabaseIdSupplier,
        invitation_limit: usize,
        membership_limit: usize,
        cancel_pending: bool,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError>;
    async fn find_invitation(&self, id: &str) -> Result<Option<OrganizationInvitation>, AuthError>;
    async fn list_invitations(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError>;
    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError>;
    async fn set_invitation_status(
        &self,
        id: &str,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError>;
    async fn resend_invitation(
        &self,
        organization_id: &str,
        email: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, AuthError>;
    async fn accept_invitation(
        &self,
        invitation_id: &str,
        user_id: &str,
        now: DateTime<Utc>,
        membership_limit: usize,
        member_id: &dyn DatabaseIdSupplier,
        team_member_id: &dyn DatabaseIdSupplier,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError>;
}

#[async_trait]
pub trait OrganizationTeamStore: Send + Sync {
    async fn create_team(
        &self,
        team: &mut OrganizationTeam,
        id: &dyn DatabaseIdSupplier,
        maximum_teams: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError>;
    async fn find_team(&self, id: &str) -> Result<Option<OrganizationTeam>, AuthError>;
    async fn list_teams(&self, organization_id: &str) -> Result<Vec<OrganizationTeam>, AuthError>;
    async fn update_team(
        &self,
        team: OrganizationTeam,
    ) -> Result<Option<OrganizationTeam>, AuthError>;
    async fn remove_team(
        &self,
        id: &str,
        allow_removing_all: bool,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError>;
    async fn add_team_member(
        &self,
        member: &mut OrganizationTeamMember,
        id: &dyn DatabaseIdSupplier,
        maximum_members: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError>;
    async fn remove_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError>;
    async fn list_team_members(
        &self,
        team_id: &str,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError>;
    async fn list_user_teams(&self, user_id: &str) -> Result<Vec<OrganizationTeam>, AuthError>;
}

#[async_trait]
pub trait OrganizationRoleStore: Send + Sync {
    async fn create_role(
        &self,
        role: &mut OrganizationRole,
        id: &dyn DatabaseIdSupplier,
        maximum_roles: Option<usize>,
    ) -> Result<bool, AuthError>;
    async fn find_role(&self, id: &str) -> Result<Option<OrganizationRole>, AuthError>;
    async fn find_role_by_name(
        &self,
        organization_id: &str,
        role: &str,
    ) -> Result<Option<OrganizationRole>, AuthError>;
    async fn list_roles(&self, organization_id: &str) -> Result<Vec<OrganizationRole>, AuthError>;
    async fn update_role(
        &self,
        role: OrganizationRole,
    ) -> Result<Option<OrganizationRole>, AuthError>;
    async fn delete_role(&self, id: &str) -> Result<bool, AuthError>;
}
