use crate::{
    AuthError, Organization, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationMember, OrganizationRole, OrganizationTeam, OrganizationTeamMember,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct OrganizationRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

impl From<OrganizationRow> for Organization {
    fn from(row: OrganizationRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            slug: row.slug,
            logo: row.logo,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct MemberRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<MemberRow> for OrganizationMember {
    fn from(row: MemberRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            role: row.role,
            created_at: row.created_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct InvitationRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub status: String,
    pub team_id: Option<String>,
    pub inviter_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<InvitationRow> for OrganizationInvitation {
    type Error = AuthError;

    fn try_from(row: InvitationRow) -> Result<Self, Self::Error> {
        let status = match row.status.as_str() {
            "pending" => OrganizationInvitationStatus::Pending,
            "accepted" => OrganizationInvitationStatus::Accepted,
            "rejected" => OrganizationInvitationStatus::Rejected,
            "canceled" => OrganizationInvitationStatus::Canceled,
            value => {
                return Err(AuthError::Storage(format!(
                    "invalid organization invitation status: {value}"
                )));
            }
        };
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            email: row.email,
            role: row.role,
            status,
            team_id: row.team_id,
            inviter_id: row.inviter_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct TeamRow {
    pub id: Uuid,
    pub name: String,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl From<TeamRow> for OrganizationTeam {
    fn from(row: TeamRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            organization_id: row.organization_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct TeamMemberRow {
    pub id: Uuid,
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

impl From<TeamMemberRow> for OrganizationTeamMember {
    fn from(row: TeamMemberRow) -> Self {
        Self {
            id: row.id,
            team_id: row.team_id,
            user_id: row.user_id,
            created_at: row.created_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct RoleRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub role: String,
    pub permission: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl TryFrom<RoleRow> for OrganizationRole {
    type Error = AuthError;

    fn try_from(row: RoleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            role: row.role,
            permission: serde_json::from_value(row.permission)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}
