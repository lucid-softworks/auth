use super::*;

#[test]
fn member_queries_remap_filters_sorting_counts_and_team_cleanup_join() {
    let physical = super::super::super::test_support::physical_schema();
    let member = physical.model("member").unwrap();
    let team = physical.model("team").unwrap();
    let team_member = physical.model("teamMember").unwrap();
    let organization_id = Uuid::from_u128(21);
    let user_id = Uuid::from_u128(22);

    let filter = filter_query(
        &member,
        [
            ("organizationId", uuid_value(organization_id)),
            ("userId", uuid_value(user_id)),
        ],
    )
    .unwrap();
    assert!(filter.sql().contains("FROM \"org\"\"members\""));
    assert!(filter.sql().contains("\"tenant id\" = $1"));
    assert!(filter.sql().contains("\"person id\" = $2"));

    let list = list_query(&member, organization_id).unwrap();
    assert!(list.sql().contains("ORDER BY \"joined time\" ASC"));
    let count = count_query(&member, organization_id).unwrap();
    assert_eq!(count.sql().matches('$').count(), 1);

    let cleanup = delete_team_members_query(&team, &team_member, organization_id, user_id).unwrap();
    assert!(
        cleanup
            .sql()
            .contains("DELETE FROM \"org\"\"team members\"")
    );
    assert!(cleanup.sql().contains("FROM \"org\"\"teams\""));
}
