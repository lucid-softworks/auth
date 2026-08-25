use lucid_auth::{
    AuthConfig, AuthService, AuthStore, OrganizationPlugin, TestOrganizationOverrides,
    TestUserOverrides, TestUtilsPlugin, postgres::PostgresStore,
};
use std::sync::Arc;

pub(crate) async fn assert_persistence(
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AuthConfig::new([91_u8; 32])?;
    config.set_base_url("https://test-utils.example.com")?;
    config.add_plugin(OrganizationPlugin::new(store.clone()))?;
    config.add_plugin(TestUtilsPlugin::default())?;
    let service = AuthService::new(store.clone(), config);
    let test = service.test().expect("Test Utils is installed");

    let user = test
        .save_user(test.create_user(TestUserOverrides {
            email: Some("POSTGRES-Test-Utils@Example.com".into()),
            ..TestUserOverrides::default()
        }))
        .await?;
    assert_eq!(user.email, "postgres-test-utils@example.com");
    let login = test.login(user.id).await?;
    assert!(store.find_session(&login.token).await?.is_some());
    let headers = test.get_auth_headers(user.id).await?;
    let cookies = test.get_cookies(user.id, None).await?;
    assert_ne!(headers["cookie"], login.headers["cookie"]);
    assert_ne!(cookies[0].value, login.cookies[0].value);
    assert_eq!(cookies[0].domain, "test-utils.example.com");

    let organizations = test.organization().expect("Organization is installed");
    let organization = organizations
        .save_organization(
            organizations.create_organization(TestOrganizationOverrides {
                slug: Some("postgres-test-utils".into()),
                ..TestOrganizationOverrides::default()
            }),
        )
        .await?;
    let member = organizations
        .add_member(user.id, organization.id, None)
        .await?;
    assert_eq!(member.role, "member");
    sqlx::query("INSERT INTO lucid_auth_organization_invitations (id,organization_id,email,role,status,team_id,inviter_id,expires_at,created_at) VALUES ($1,$2,$3,'member','pending',NULL,$4,NOW() + INTERVAL '1 hour',NOW())")
        .bind(uuid::Uuid::new_v4())
        .bind(organization.id)
        .bind("delete-order@example.com")
        .bind(user.id)
        .execute(pool)
        .await?;
    organizations.delete_organization(organization.id).await?;
    for table in [
        "lucid_auth_organization_members",
        "lucid_auth_organization_invitations",
        "lucid_auth_organizations",
    ] {
        let count = sqlx::query_scalar::<_, i64>(&format!(
            "SELECT count(*) FROM {table} WHERE {}=$1",
            if table == "lucid_auth_organizations" {
                "id"
            } else {
                "organization_id"
            }
        ))
        .bind(organization.id)
        .fetch_one(pool)
        .await?;
        assert_eq!(count, 0);
    }

    test.delete_user(user.id).await?;
    test.delete_user(user.id).await?;
    Ok(())
}
