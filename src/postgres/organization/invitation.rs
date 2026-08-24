use super::{member::lock_organization, rows::InvitationRow, storage_error};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, postgres::PostgresStore,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const COLUMNS: &str =
    "id, organization_id, email, role, status, team_id, inviter_id, expires_at, created_at";

#[async_trait]
impl OrganizationInvitationStore for PostgresStore {
    async fn create_invitation(
        &self,
        invitation: OrganizationInvitation,
        invitation_limit: usize,
        membership_limit: usize,
        cancel_pending: bool,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut tx, invitation.organization_id).await?;
        let members = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM lucid_auth_organization_members WHERE organization_id=$1",
        )
        .bind(invitation.organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_error)?;
        if members >= membership_limit as i64 {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        let pending = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lucid_auth_organization_invitations WHERE organization_id=$1 AND lower(email)=lower($2) AND status='pending'")
            .bind(invitation.organization_id).bind(&invitation.email).fetch_one(&mut *tx).await.map_err(storage_error)?;
        if pending > 0 && !cancel_pending {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyInvited);
        }
        if cancel_pending {
            sqlx::query("UPDATE lucid_auth_organization_invitations SET status='canceled' WHERE organization_id=$1 AND lower(email)=lower($2) AND status='pending'")
                .bind(invitation.organization_id).bind(&invitation.email).execute(&mut *tx).await.map_err(storage_error)?;
        }
        let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lucid_auth_organization_invitations WHERE organization_id=$1 AND status='pending'")
            .bind(invitation.organization_id).fetch_one(&mut *tx).await.map_err(storage_error)?;
        if count >= invitation_limit as i64 {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        sqlx::query("INSERT INTO lucid_auth_organization_invitations (id,organization_id,email,role,status,team_id,inviter_id,expires_at,created_at) VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8)")
            .bind(invitation.id).bind(invitation.organization_id).bind(invitation.email.to_lowercase()).bind(invitation.role).bind(invitation.team_id).bind(invitation.inviter_id).bind(invitation.expires_at).bind(invitation.created_at)
            .execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }

    async fn find_invitation(&self, id: Uuid) -> Result<Option<OrganizationInvitation>, AuthError> {
        let row = sqlx::query_as::<_, InvitationRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_invitations WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_invitations(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        rows(sqlx::query_as::<_, InvitationRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_invitations WHERE organization_id=$1 ORDER BY created_at,id")).bind(organization_id).fetch_all(&self.pool).await.map_err(storage_error)?)
    }

    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        rows(sqlx::query_as::<_, InvitationRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_invitations WHERE lower(email)=lower($1) ORDER BY created_at,id")).bind(email).fetch_all(&self.pool).await.map_err(storage_error)?)
    }

    async fn set_invitation_status(
        &self,
        id: Uuid,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let status = status_name(status);
        let row = sqlx::query_as::<_, InvitationRow>(&format!("UPDATE lucid_auth_organization_invitations SET status=$2 WHERE id=$1 RETURNING {COLUMNS}")).bind(id).bind(status).fetch_optional(&self.pool).await.map_err(storage_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn resend_invitation(
        &self,
        organization_id: Uuid,
        email: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let row = sqlx::query_as::<_, InvitationRow>(&format!("UPDATE lucid_auth_organization_invitations SET expires_at=$3 WHERE id=(SELECT id FROM lucid_auth_organization_invitations WHERE organization_id=$1 AND lower(email)=lower($2) AND status='pending' ORDER BY created_at DESC LIMIT 1) RETURNING {COLUMNS}"))
            .bind(organization_id).bind(email).bind(expires_at).fetch_optional(&self.pool).await.map_err(storage_error)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn accept_invitation(
        &self,
        invitation_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
        membership_limit: usize,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let Some(invitation) = sqlx::query_as::<_, InvitationRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_invitations WHERE id=$1 FOR UPDATE"
        ))
        .bind(invitation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        else {
            return Ok(OrganizationInvitationWriteOutcome::NotFound);
        };
        if invitation.status != "pending" {
            return Ok(OrganizationInvitationWriteOutcome::NotFound);
        }
        if invitation.expires_at <= now {
            return Ok(OrganizationInvitationWriteOutcome::Expired);
        }
        lock_organization(&mut tx, invitation.organization_id).await?;
        if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM lucid_auth_organization_members WHERE organization_id=$1 AND user_id=$2)").bind(invitation.organization_id).bind(user_id).fetch_one(&mut *tx).await.map_err(storage_error)? {
            return Ok(OrganizationInvitationWriteOutcome::AlreadyMember);
        }
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM lucid_auth_organization_members WHERE organization_id=$1",
        )
        .bind(invitation.organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_error)?;
        if count >= membership_limit as i64 {
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        sqlx::query("INSERT INTO lucid_auth_organization_members (id,organization_id,user_id,role,created_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4()).bind(invitation.organization_id).bind(user_id).bind(&invitation.role).bind(now).execute(&mut *tx).await.map_err(storage_error)?;
        for team_id in invitation
            .team_id
            .as_deref()
            .into_iter()
            .flat_map(|ids| ids.split(','))
            .filter_map(|id| Uuid::parse_str(id).ok())
        {
            sqlx::query("INSERT INTO lucid_auth_organization_team_members (id,team_id,user_id,created_at) SELECT $1,$2,$3,$4 WHERE EXISTS (SELECT 1 FROM lucid_auth_organization_teams WHERE id=$2 AND organization_id=$5) ON CONFLICT (team_id,user_id) DO NOTHING")
                .bind(Uuid::new_v4()).bind(team_id).bind(user_id).bind(now).bind(invitation.organization_id).execute(&mut *tx).await.map_err(storage_error)?;
        }
        sqlx::query("UPDATE lucid_auth_organization_invitations SET status='accepted' WHERE id=$1")
            .bind(invitation_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }
}

fn rows(rows: Vec<InvitationRow>) -> Result<Vec<OrganizationInvitation>, AuthError> {
    rows.into_iter().map(TryInto::try_into).collect()
}

fn status_name(status: OrganizationInvitationStatus) -> &'static str {
    match status {
        OrganizationInvitationStatus::Pending => "pending",
        OrganizationInvitationStatus::Accepted => "accepted",
        OrganizationInvitationStatus::Rejected => "rejected",
        OrganizationInvitationStatus::Canceled => "canceled",
    }
}
