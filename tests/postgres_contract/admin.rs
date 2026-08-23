use lucid_auth::{
    AdminCreateUser, AdminListCondition, AdminListOperator, AdminListUsersQuery,
    AdminSortDirection, AdminUserUpdate, AuthService, SessionWithUser,
};
use serde_json::{Map, Value};

pub async fn assert_query_and_update(
    service: &AuthService,
    actor: &SessionWithUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Map::new();
    data.insert("username".into(), Value::String("postgres_admin".into()));
    data.insert("department".into(), Value::String("support".into()));
    let user = service
        .create_admin_user(
            actor,
            AdminCreateUser {
                email: "postgres.admin@example.com".into(),
                password: None,
                name: "PostgreSQL Admin Query".into(),
                roles: Vec::new(),
                data,
            },
        )
        .await?;
    let query = AdminListUsersQuery {
        limit: 10,
        offset: 0,
        sort_by: Some("department".into()),
        sort_direction: AdminSortDirection::Desc,
        conditions: vec![AdminListCondition {
            field: "department".into(),
            operator: AdminListOperator::In,
            value: Value::Array(vec![
                Value::String("support".into()),
                Value::String("operations".into()),
            ]),
        }],
    };
    let (users, total) = service.list_users(actor, query).await?;
    assert_eq!(total, 1);
    assert_eq!(users.as_slice(), std::slice::from_ref(&user));
    let updated = service
        .admin_update_user(
            actor,
            user.id,
            AdminUserUpdate {
                name: Some("Updated PostgreSQL Admin Query".into()),
                email_verified: Some(true),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.name, "Updated PostgreSQL Admin Query");
    assert!(updated.email_verified);
    service.remove_user(actor, user.id).await?;
    Ok(())
}
