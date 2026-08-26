use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub type OrganizationPermissions = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone)]
pub struct NewOrganization {
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub keep_current_active_organization: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OrganizationUpdate {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<Option<String>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct OrganizationCreation {
    pub organization: Organization,
    pub member: OrganizationMember,
}

#[derive(Debug, Clone)]
pub struct NewOrganizationInvitation {
    pub email: String,
    pub role: String,
    pub organization_id: Option<Uuid>,
    pub team_ids: Vec<Uuid>,
    pub resend: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInvitationAcceptance {
    pub invitation: OrganizationInvitation,
    pub member: OrganizationMember,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInvitationDetails {
    #[serde(flatten)]
    pub invitation: OrganizationInvitation,
    pub organization_name: String,
    pub organization_slug: String,
    pub inviter_email: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMember {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationInvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub status: OrganizationInvitationStatus,
    pub team_id: Option<String>,
    pub inviter_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationTeam {
    pub id: Uuid,
    pub name: String,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationTeamMember {
    pub id: Uuid,
    pub team_id: Uuid,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub role: String,
    pub permission: OrganizationPermissions,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMemberWithUser {
    #[serde(flatten)]
    pub member: OrganizationMember,
    pub user: crate::AuthUser,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullOrganization {
    #[serde(flatten)]
    pub organization: Organization,
    pub members: Vec<OrganizationMemberWithUser>,
    pub invitations: Vec<OrganizationInvitation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<OrganizationTeam>>,
}
