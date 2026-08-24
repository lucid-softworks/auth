use super::{
    Organization, OrganizationInvitation, OrganizationMember, OrganizationTeam,
    OrganizationTeamMember,
};
use crate::{AuthError, AuthUser};
use async_trait::async_trait;

#[async_trait]
pub trait OrganizationLifecycleHooks: Send + Sync {
    async fn before_create(
        &self,
        value: Organization,
        _user: &AuthUser,
    ) -> Result<Organization, AuthError> {
        Ok(value)
    }
    async fn after_create(
        &self,
        _value: &Organization,
        _member: &OrganizationMember,
        _user: &AuthUser,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_update(
        &self,
        value: Organization,
        _member: &OrganizationMember,
        _user: &AuthUser,
    ) -> Result<Organization, AuthError> {
        Ok(value)
    }
    async fn after_update(
        &self,
        _value: &Organization,
        _member: &OrganizationMember,
        _user: &AuthUser,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_delete(
        &self,
        _value: &Organization,
        _user: &AuthUser,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_delete(&self, _value: &Organization, _user: &AuthUser) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before_add_member(
        &self,
        value: OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<OrganizationMember, AuthError> {
        Ok(value)
    }
    async fn after_add_member(
        &self,
        _value: &OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_remove_member(
        &self,
        _value: &OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_remove_member(
        &self,
        _value: &OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_update_member_role(
        &self,
        role: String,
        _member: &OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<String, AuthError> {
        Ok(role)
    }
    async fn after_update_member_role(
        &self,
        _member: &OrganizationMember,
        _previous_role: &str,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before_create_invitation(
        &self,
        value: OrganizationInvitation,
        _inviter: &AuthUser,
        _organization: &Organization,
    ) -> Result<OrganizationInvitation, AuthError> {
        Ok(value)
    }
    async fn after_create_invitation(
        &self,
        _value: &OrganizationInvitation,
        _inviter: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_accept_invitation(
        &self,
        _value: &OrganizationInvitation,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_accept_invitation(
        &self,
        _value: &OrganizationInvitation,
        _member: &OrganizationMember,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_reject_invitation(
        &self,
        _value: &OrganizationInvitation,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_reject_invitation(
        &self,
        _value: &OrganizationInvitation,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_cancel_invitation(
        &self,
        _value: &OrganizationInvitation,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_cancel_invitation(
        &self,
        _value: &OrganizationInvitation,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before_create_team(
        &self,
        value: OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<OrganizationTeam, AuthError> {
        Ok(value)
    }
    async fn after_create_team(
        &self,
        _value: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_update_team(
        &self,
        value: OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<OrganizationTeam, AuthError> {
        Ok(value)
    }
    async fn after_update_team(
        &self,
        _value: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_delete_team(
        &self,
        _value: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_delete_team(
        &self,
        _value: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_add_team_member(
        &self,
        value: OrganizationTeamMember,
        _team: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<OrganizationTeamMember, AuthError> {
        Ok(value)
    }
    async fn after_add_team_member(
        &self,
        _value: &OrganizationTeamMember,
        _team: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn before_remove_team_member(
        &self,
        _value: &OrganizationTeamMember,
        _team: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
    async fn after_remove_team_member(
        &self,
        _value: &OrganizationTeamMember,
        _team: &OrganizationTeam,
        _user: &AuthUser,
        _organization: &Organization,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}
