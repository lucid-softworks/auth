use super::{rows, test_support};
use crate::{
    Organization, OrganizationInvitation, OrganizationInvitationStatus, OrganizationMember,
    OrganizationRole, OrganizationTeam, OrganizationTeamMember, PreparedDatabaseId,
    postgres::{PostgresModel, PostgresWrite},
};
use chrono::{Duration, Utc};
use std::collections::BTreeMap;

#[test]
fn every_organization_model_omits_deferred_ids_and_returns_typed_rows() {
    let physical = test_support::physical_schema();
    let records = deferred_records();
    let organization = physical.model("organization").unwrap();
    assert_deferred_insert(
        &organization,
        rows::organization_writes(&organization, &records.0, &PreparedDatabaseId::Deferred)
            .unwrap(),
    );
    let member = physical.model("member").unwrap();
    assert_deferred_insert(
        &member,
        rows::member_writes(&member, &records.1, &PreparedDatabaseId::Deferred).unwrap(),
    );
    let invitation = physical.model("invitation").unwrap();
    assert_deferred_insert(
        &invitation,
        rows::invitation_writes(&invitation, &records.2, &PreparedDatabaseId::Deferred).unwrap(),
    );
    let team = physical.model("team").unwrap();
    assert_deferred_insert(
        &team,
        rows::team_writes(&team, &records.3, &PreparedDatabaseId::Deferred).unwrap(),
    );
    let team_member = physical.model("teamMember").unwrap();
    assert_deferred_insert(
        &team_member,
        rows::team_member_writes(&team_member, &records.4, &PreparedDatabaseId::Deferred).unwrap(),
    );
    let role = physical.model("organizationRole").unwrap();
    assert_deferred_insert(
        &role,
        rows::role_writes(&role, &records.5, &PreparedDatabaseId::Deferred).unwrap(),
    );
}

fn assert_deferred_insert(model: &PostgresModel<'_>, writes: Vec<PostgresWrite<'_>>) {
    assert!(writes.iter().all(|write| write.logical() != "id"));
    let query = crate::postgres::rows::insert_query(model, writes);
    assert!(query.sql().contains(" RETURNING "));
    assert!(query.sql().ends_with(&model.all_projection()));
}

#[allow(clippy::type_complexity)]
fn deferred_records() -> (
    Organization,
    OrganizationMember,
    OrganizationInvitation,
    OrganizationTeam,
    OrganizationTeamMember,
    OrganizationRole,
) {
    let now = Utc::now();
    (
        Organization {
            id: String::new(),
            name: "Deferred".into(),
            slug: "deferred".into(),
            logo: None,
            metadata: None,
            created_at: now,
        },
        OrganizationMember {
            id: String::new(),
            organization_id: "organization-id".into(),
            user_id: "user-id".into(),
            role: "member".into(),
            created_at: now,
        },
        invitation(now),
        OrganizationTeam {
            id: String::new(),
            name: "Deferred".into(),
            organization_id: "organization-id".into(),
            created_at: now,
            updated_at: None,
        },
        OrganizationTeamMember {
            id: String::new(),
            team_id: "team-id".into(),
            user_id: "user-id".into(),
            created_at: now,
        },
        OrganizationRole {
            id: String::new(),
            organization_id: "organization-id".into(),
            role: "auditor".into(),
            permission: BTreeMap::new(),
            created_at: now,
            updated_at: None,
        },
    )
}

fn invitation(now: chrono::DateTime<Utc>) -> OrganizationInvitation {
    OrganizationInvitation {
        id: String::new(),
        organization_id: "organization-id".into(),
        email: "deferred@example.com".into(),
        role: "member".into(),
        status: OrganizationInvitationStatus::Pending,
        team_id: Some("team-id".into()),
        inviter_id: "inviter-id".into(),
        expires_at: now + Duration::hours(1),
        created_at: now,
    }
}
