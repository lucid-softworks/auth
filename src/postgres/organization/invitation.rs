use super::{member::lock_organization, storage_error};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, postgres::PostgresStore,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

mod acceptance;
mod query;

use acceptance::{InvitationAcceptanceContext, accept_invitation_transaction};
use query::*;

#[async_trait]
impl OrganizationInvitationStore for PostgresStore {
    async fn create_invitation(
        &self,
        mut invitation: OrganizationInvitation,
        invitation_limit: usize,
        membership_limit: usize,
        cancel_pending: bool,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let organization = self.physical_model("organization")?;
        let member = self.physical_model("member")?;
        let invitation_model = self.physical_model("invitation")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut transaction, &organization, invitation.organization_id).await?;
        if count_by_organization(&mut transaction, &member, invitation.organization_id).await?
            >= membership_limit as i64
        {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        let pending = pending_count(
            &mut transaction,
            &invitation_model,
            invitation.organization_id,
            Some(&invitation.email),
        )
        .await?;
        if pending > 0 && !cancel_pending {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyInvited);
        }
        if cancel_pending {
            cancel_pending_for_email(
                &mut transaction,
                &invitation_model,
                invitation.organization_id,
                &invitation.email,
            )
            .await?;
        }
        if pending_count(
            &mut transaction,
            &invitation_model,
            invitation.organization_id,
            None,
        )
        .await?
            >= invitation_limit as i64
        {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        invitation.email = invitation.email.to_lowercase();
        invitation.status = OrganizationInvitationStatus::Pending;
        insert_invitation(&mut transaction, &invitation_model, &invitation).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }

    async fn find_invitation(&self, id: Uuid) -> Result<Option<OrganizationInvitation>, AuthError> {
        let model = self.physical_model("invitation")?;
        find(&self.pool, &model, [("id", uuid_value(id))], false).await
    }

    async fn list_invitations(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let model = self.physical_model("invitation")?;
        list(
            &self.pool,
            &model,
            "organizationId",
            uuid_value(organization_id),
            false,
        )
        .await
    }

    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let model = self.physical_model("invitation")?;
        list(&self.pool, &model, "email", json!(email), true).await
    }

    async fn set_invitation_status(
        &self,
        id: Uuid,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let model = self.physical_model("invitation")?;
        let mut query = status_update_query(&model, id, status)?;
        decode_optional(
            &model,
            query
                .build()
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?,
        )
    }

    async fn resend_invitation(
        &self,
        organization_id: Uuid,
        email: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let model = self.physical_model("invitation")?;
        let mut query = resend_query(&model, organization_id, email, expires_at)?;
        decode_optional(
            &model,
            query
                .build()
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_error)?,
        )
    }

    async fn accept_invitation(
        &self,
        invitation_id: Uuid,
        user_id: &str,
        now: DateTime<Utc>,
        membership_limit: usize,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let organization = self.physical_model("organization")?;
        let invitation_model = self.physical_model("invitation")?;
        let member_model = self.physical_model("member")?;
        let team_models = if invitation_model.has_field("teamId") {
            Some((
                self.physical_model("team")?,
                self.physical_model("teamMember")?,
            ))
        } else {
            None
        };
        accept_invitation_transaction(InvitationAcceptanceContext {
            pool: &self.pool,
            organization: &organization,
            invitation: &invitation_model,
            member: &member_model,
            teams: team_models.as_ref().map(|(team, member)| (team, member)),
            invitation_id,
            user_id,
            now,
            membership_limit,
        })
        .await
    }
}
