use crate::mssql::{
    MssqlFilter, MssqlFindOptions, MssqlJoin, MssqlJoinRelation, MssqlStore,
};
use serde_json::json;

pub(super) async fn assert_joins(store: &MssqlStore) {
    let joined = store
        .find_record_with_options(
            "group",
            &[MssqlFilter::equal("id", json!("group-one"))],
            &MssqlFindOptions {
                select: vec!["name".into()],
                joins: vec![MssqlJoin {
                    model: "counter".into(),
                    local_field: "id".into(),
                    foreign_field: "groupId".into(),
                    relation: MssqlJoinRelation::OneToMany,
                    limit: Some(1),
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined["name"], json!("Example"));
    assert_eq!(joined["counter"].as_array().unwrap().len(), 1);
    assert_eq!(joined["counter"][0]["groupId"], json!("group-one"));

    let joined_parent = store
        .find_record_with_options(
            "counter",
            &[MssqlFilter::equal("id", json!("two"))],
            &MssqlFindOptions {
                joins: vec![MssqlJoin {
                    model: "group".into(),
                    local_field: "groupId".into(),
                    foreign_field: "id".into(),
                    relation: MssqlJoinRelation::OneToOne,
                    limit: None,
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined_parent["group"]["name"], json!("Example"));

    let missing_parent = store
        .find_record_with_options(
            "counter",
            &[MssqlFilter::equal("id", json!("one"))],
            &MssqlFindOptions {
                joins: vec![MssqlJoin {
                    model: "group".into(),
                    local_field: "groupId".into(),
                    foreign_field: "id".into(),
                    relation: MssqlJoinRelation::OneToOne,
                    limit: None,
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(missing_parent["group"].is_null());
}
