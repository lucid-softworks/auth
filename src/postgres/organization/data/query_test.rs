use super::*;
use chrono::Utc;
use serde_json::json;

#[test]
fn organization_queries_remap_create_find_sort_count_update_and_delete() {
    let physical = super::super::super::test_support::physical_schema();
    let organization_model = physical.model("organization").unwrap();
    let member_model = physical.model("member").unwrap();
    let id = Uuid::from_u128(11);
    let organization = Organization {
        id,
        name: "private name".into(),
        slug: "private-slug".into(),
        logo: None,
        metadata: Some(json!({"secret": true})),
        created_at: Utc::now(),
    };

    let writes = rows::organization_writes(&organization_model, &organization).unwrap();
    let insert = crate::postgres::rows::insert_query_prefix(&organization_model, writes);
    assert!(insert.sql().starts_with("INSERT INTO \"org\"\"records\""));
    assert!(insert.sql().contains("\"display name\""));
    assert!(insert.sql().contains("\"private metadata\""));
    assert!(!insert.sql().contains("private name"));

    let find = crate::postgres::rows::select_query(&organization_model);
    assert!(find.sql().contains("\"public\"\"slug\" AS \"slug\""));

    let list = list_query(&organization_model, &member_model, Uuid::from_u128(12)).unwrap();
    assert!(list.sql().contains("FROM \"org\"\"members\""));
    assert!(
        list.sql()
            .contains("\"tenant id\" = \"org\"\"records\".\"id\"")
    );
    assert!(list.sql().contains("ORDER BY \"created time\" ASC"));

    let count = count_query(&member_model, "organizationId", id).unwrap();
    assert_eq!(
        count.sql(),
        "SELECT count(*) FROM \"org\"\"members\" WHERE \"tenant id\" = $1"
    );

    let update = update_query(&organization_model, &organization).unwrap();
    assert!(update.sql().starts_with("UPDATE \"org\"\"records\" SET"));
    assert!(update.sql().contains("\"public\"\"slug\" AS \"slug\""));
    assert!(update.sql().ends_with(&format!(
        ") RETURNING {}",
        organization_model.all_projection()
    )));
    assert!(!update.sql().contains("private-slug"));

    let delete = delete_query(&organization_model, id).unwrap();
    assert!(delete.sql().starts_with("DELETE FROM \"org\"\"records\""));
    assert!(delete.sql().contains("\"display name\" AS \"name\""));
    assert!(delete.sql().ends_with(&format!(
        " RETURNING {}",
        organization_model.all_projection()
    )));
}
