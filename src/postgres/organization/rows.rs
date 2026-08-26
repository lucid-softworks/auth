use super::super::{PostgresModel, PostgresWrite};
use crate::{
    AuthError, Organization, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationMember, OrganizationRole, OrganizationTeam, OrganizationTeamMember,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;

pub(super) fn organization_writes<'a>(
    model: &'a PostgresModel<'_>,
    organization: &Organization,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", uuid_value(organization.id)),
        ("name", json!(organization.name)),
        ("slug", json!(organization.slug)),
        ("logo", optional_string(organization.logo.clone())),
        ("metadata", optional_json(organization.metadata.as_ref())?),
        ("createdAt", date_value(organization.created_at)),
    ])
}

pub(super) fn decode_organization(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<Organization, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(Organization {
        id: required_uuid(&mut values, "id")?,
        name: required_string(&mut values, "name")?,
        slug: required_string(&mut values, "slug")?,
        logo: optional_string_value(&mut values, "logo")?,
        metadata: optional_json_value(&mut values, "metadata")?,
        created_at: required_date(&mut values, "createdAt")?,
    })
}

pub(super) fn member_writes<'a>(
    model: &'a PostgresModel<'_>,
    member: &OrganizationMember,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", uuid_value(member.id)),
        ("organizationId", uuid_value(member.organization_id)),
        ("userId", json!(member.user_id)),
        ("role", json!(member.role)),
        ("createdAt", date_value(member.created_at)),
    ])
}

pub(super) fn decode_member(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OrganizationMember, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(OrganizationMember {
        id: required_uuid(&mut values, "id")?,
        organization_id: required_uuid(&mut values, "organizationId")?,
        user_id: required_string(&mut values, "userId")?,
        role: required_string(&mut values, "role")?,
        created_at: required_date(&mut values, "createdAt")?,
    })
}

pub(super) fn invitation_writes<'a>(
    model: &'a PostgresModel<'_>,
    invitation: &OrganizationInvitation,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = vec![
        ("id", uuid_value(invitation.id)),
        ("organizationId", uuid_value(invitation.organization_id)),
        ("email", json!(invitation.email.to_lowercase())),
        ("role", json!(invitation.role)),
        ("status", json!(status_name(invitation.status))),
        ("inviterId", json!(invitation.inviter_id)),
        ("expiresAt", date_value(invitation.expires_at)),
        ("createdAt", date_value(invitation.created_at)),
    ];
    if model.has_field("teamId") {
        values.push(("teamId", optional_string(invitation.team_id.clone())));
    } else if invitation.team_id.is_some() {
        return Err(AuthError::InvalidConfiguration(
            "organization invitation teamId requires Better Auth team support".into(),
        ));
    }
    model.encode_fields(values)
}

pub(super) fn decode_invitation(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OrganizationInvitation, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(OrganizationInvitation {
        id: required_uuid(&mut values, "id")?,
        organization_id: required_uuid(&mut values, "organizationId")?,
        email: required_string(&mut values, "email")?,
        role: required_string(&mut values, "role")?,
        status: invitation_status(&required_string(&mut values, "status")?)?,
        team_id: if model.has_field("teamId") {
            optional_string_value(&mut values, "teamId")?
        } else {
            None
        },
        inviter_id: required_string(&mut values, "inviterId")?,
        expires_at: required_date(&mut values, "expiresAt")?,
        created_at: required_date(&mut values, "createdAt")?,
    })
}

pub(super) fn team_writes<'a>(
    model: &'a PostgresModel<'_>,
    team: &OrganizationTeam,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = vec![
        ("id", uuid_value(team.id)),
        ("name", json!(team.name)),
        ("organizationId", uuid_value(team.organization_id)),
        ("createdAt", date_value(team.created_at)),
        ("updatedAt", optional_date(team.updated_at)),
    ];
    if model.has_field("memberCount") {
        values.push(("memberCount", json!(0)));
    }
    model.encode_fields(values)
}

pub(super) fn decode_team(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OrganizationTeam, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(OrganizationTeam {
        id: required_uuid(&mut values, "id")?,
        name: required_string(&mut values, "name")?,
        organization_id: required_uuid(&mut values, "organizationId")?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: optional_date_value(&mut values, "updatedAt")?,
    })
}

pub(super) fn team_member_writes<'a>(
    model: &'a PostgresModel<'_>,
    member: &OrganizationTeamMember,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = vec![
        ("id", uuid_value(member.id)),
        ("teamId", uuid_value(member.team_id)),
        ("userId", json!(member.user_id)),
        ("createdAt", date_value(member.created_at)),
    ];
    if model.has_field("membershipKey") {
        values.push((
            "membershipKey",
            json!(membership_key(member.team_id, &member.user_id)),
        ));
    }
    model.encode_fields(values)
}

pub(super) fn decode_team_member(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OrganizationTeamMember, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(OrganizationTeamMember {
        id: required_uuid(&mut values, "id")?,
        team_id: required_uuid(&mut values, "teamId")?,
        user_id: required_string(&mut values, "userId")?,
        created_at: required_date(&mut values, "createdAt")?,
    })
}

pub(super) fn role_writes<'a>(
    model: &'a PostgresModel<'_>,
    role: &OrganizationRole,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", uuid_value(role.id)),
        ("organizationId", uuid_value(role.organization_id)),
        ("role", json!(role.role)),
        (
            "permission",
            json!(serde_json::to_string(&role.permission).map_err(storage_error)?),
        ),
        ("createdAt", date_value(role.created_at)),
        ("updatedAt", optional_date(role.updated_at)),
    ])
}

pub(super) fn decode_role(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OrganizationRole, AuthError> {
    let mut values = model.decode_all(row)?;
    let permission = required_string(&mut values, "permission")?;
    Ok(OrganizationRole {
        id: required_uuid(&mut values, "id")?,
        organization_id: required_uuid(&mut values, "organizationId")?,
        role: required_string(&mut values, "role")?,
        permission: serde_json::from_str(&permission).map_err(storage_error)?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: optional_date_value(&mut values, "updatedAt")?,
    })
}

pub(super) fn status_name(status: OrganizationInvitationStatus) -> &'static str {
    match status {
        OrganizationInvitationStatus::Pending => "pending",
        OrganizationInvitationStatus::Accepted => "accepted",
        OrganizationInvitationStatus::Rejected => "rejected",
        OrganizationInvitationStatus::Canceled => "canceled",
    }
}

fn invitation_status(value: &str) -> Result<OrganizationInvitationStatus, AuthError> {
    match value {
        "pending" => Ok(OrganizationInvitationStatus::Pending),
        "accepted" => Ok(OrganizationInvitationStatus::Accepted),
        "rejected" => Ok(OrganizationInvitationStatus::Rejected),
        "canceled" => Ok(OrganizationInvitationStatus::Canceled),
        value => Err(AuthError::Storage(format!(
            "invalid organization invitation status: {value}"
        ))),
    }
}

fn membership_key(team_id: uuid::Uuid, user_id: &str) -> String {
    let input = serde_json::to_vec(&[team_id.to_string(), user_id.to_owned()])
        .expect("membership strings always serialize");
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

fn optional_json(value: Option<&Value>) -> Result<Value, AuthError> {
    value
        .map(|value| serde_json::to_string(value).map(Value::String))
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
        .map_err(storage_error)
}

fn optional_json_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<Value>, AuthError> {
    optional_string_value(values, field)?
        .map(|value| serde_json::from_str(&value).map_err(storage_error))
        .transpose()
}

fn uuid_value(value: uuid::Uuid) -> Value {
    Value::String(value.to_string())
}

fn date_value(value: chrono::DateTime<chrono::Utc>) -> Value {
    Value::String(value.to_rfc3339())
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, date_value)
}

fn required_uuid(values: &mut Map<String, Value>, field: &str) -> Result<uuid::Uuid, AuthError> {
    super::super::rows::required_uuid(values, field)
}

fn required_string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    super::super::rows::required_string(values, field)
}

fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    super::super::rows::optional_string_value(values, field)
}

fn required_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    super::super::rows::required_date(values, field)
}

fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AuthError> {
    super::super::rows::optional_date_value(values, field)
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_keys_match_better_auth_sha256_base64url() {
        let team = uuid::Uuid::nil();
        let user = uuid::Uuid::from_u128(1);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(
            br#"["00000000-0000-0000-0000-000000000000","00000000-0000-0000-0000-000000000001"]"#,
        ));
        assert_eq!(membership_key(team, &user.to_string()), expected);
    }

    #[test]
    fn metadata_round_trips_through_better_auth_string_storage() {
        let value = json!({"plan": "pro"});
        let encoded = optional_json(Some(&value)).unwrap();
        let mut values = Map::from_iter([("metadata".into(), encoded)]);
        assert_eq!(
            optional_json_value(&mut values, "metadata").unwrap(),
            Some(value)
        );
    }
}
