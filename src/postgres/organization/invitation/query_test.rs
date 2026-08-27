use super::*;
use chrono::Duration;
use uuid::Uuid;

#[test]
fn invitation_queries_remap_filters_sort_count_status_and_resend() {
    let physical = super::super::super::test_support::physical_schema();
    let invitation = physical.model("invitation").unwrap();
    let organization_id = Uuid::from_u128(31).to_string();

    let filter = filter_query(&invitation, [("email", json!("secret@example.com"))], true).unwrap();
    assert!(filter.sql().contains("FROM \"org\"\"invitations\""));
    assert!(
        filter
            .sql()
            .contains("lower(\"invitee email\") = lower($1)")
    );
    assert!(!filter.sql().contains("secret@example.com"));

    let mut sorted = filter_query(
        &invitation,
        [("organizationId", json!(organization_id))],
        false,
    )
    .unwrap();
    sorted
        .push(" ORDER BY ")
        .push(invitation.quoted_column("createdAt").unwrap())
        .push(" ASC, \"id\" ASC");
    assert!(sorted.sql().contains("ORDER BY \"issued time\" ASC"));

    let count = count_query(&invitation, &organization_id).unwrap();
    assert!(count.sql().contains("WHERE \"tenant id\" = $1"));
    let status = status_update_query(
        &invitation,
        &Uuid::from_u128(32).to_string(),
        OrganizationInvitationStatus::Rejected,
    )
    .unwrap();
    assert!(status.sql().contains("SET \"invite status\" = $1"));
    assert!(status.sql().contains("\"team ids\" AS \"teamId\""));
    assert!(
        status
            .sql()
            .ends_with(&format!(" RETURNING {}", invitation.all_projection()))
    );

    let resend = resend_query(
        &invitation,
        &organization_id,
        "secret@example.com",
        Utc::now() + Duration::hours(1),
    )
    .unwrap();
    assert!(resend.sql().contains("SET \"expiry time\" = $1"));
    assert!(resend.sql().contains("ORDER BY \"issued time\" DESC"));
    assert!(!resend.sql().contains("secret@example.com"));
}
