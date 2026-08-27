use super::{
    database::StrategyDatabase,
    organization_round_trip::{exercise, organization_input, persisted_actor},
};
use chrono::{Duration, Utc};
use lucid_auth::{
    AuthSession, AuthStore, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerator, OrganizationTeamStore, SessionWithUser,
};
use std::sync::Arc;

pub(super) async fn assert_round_trip(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_database_defaults(database, "database").await?;
    let owner = persisted_actor(database, "database_org_owner").await?;
    let ids = exercise(database, "database-org", &owner, None, "text").await?;
    for id in ids.all() {
        assert!(id.starts_with("database-"), "unexpected database ID: {id}");
    }
    Ok(())
}

pub(super) async fn assert_empty_callback_defer() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(
        DatabaseIdGeneration::Callback(Arc::new(EmptyIds)),
        "empty_callback",
    )
    .await?;
    sqlx::query(
        r#"INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt")
           VALUES ('empty-owner', 'Empty Owner', 'empty-owner@example.com', false, NOW(), NOW())"#,
    )
    .execute(&database.pool)
    .await?;
    configure_organization_defaults(&database, "empty").await?;
    let owner = session_for_user(
        database
            .store
            .find_user_by_id("empty-owner")
            .await?
            .unwrap(),
        "empty-session",
    );
    let created = database
        .service
        .create_organization(&owner, organization_input("empty-callback"))
        .await?;
    assert_eq!(created.organization.id, "empty-organization-1");
    assert_eq!(created.member.id, "empty-member-1");
    let team = database
        .store
        .list_teams(&created.organization.id)
        .await?
        .remove(0);
    assert_eq!(team.id, "empty-team-1");
    assert_eq!(
        database
            .store
            .list_team_members(&team.id)
            .await?
            .remove(0)
            .id,
        "empty-team-member-1"
    );
    database.close().await
}

async fn configure_database_defaults(
    database: &StrategyDatabase,
    prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(&format!(
        r#"CREATE SEQUENCE {prefix}_org_user_id;
           CREATE SEQUENCE {prefix}_org_account_id;
           CREATE SEQUENCE {prefix}_org_session_id;
           ALTER TABLE "user" ALTER COLUMN id SET DEFAULT
             ('{prefix}-user-' || nextval('{prefix}_org_user_id')::text);
           ALTER TABLE "account" ALTER COLUMN id SET DEFAULT
             ('{prefix}-account-' || nextval('{prefix}_org_account_id')::text);
           ALTER TABLE "session" ALTER COLUMN id SET DEFAULT
             ('{prefix}-session-' || nextval('{prefix}_org_session_id')::text);"#,
    ))
    .execute(&database.pool)
    .await?;
    configure_organization_defaults(database, prefix).await
}

async fn configure_organization_defaults(
    database: &StrategyDatabase,
    prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut statements = String::new();
    for (table, sequence, label) in [
        ("organization", "organization", "organization"),
        ("member", "member", "member"),
        ("team", "team", "team"),
        ("teamMember", "team_member", "team-member"),
        ("organizationRole", "organization_role", "organization-role"),
        ("invitation", "invitation", "invitation"),
    ] {
        statements.push_str(&format!(
            "CREATE SEQUENCE {prefix}_{sequence}_id; \
             ALTER TABLE \"{table}\" ALTER COLUMN id SET DEFAULT \
             ('{prefix}-{label}-' || nextval('{prefix}_{sequence}_id')::text); "
        ));
    }
    sqlx::raw_sql(&statements).execute(&database.pool).await?;
    Ok(())
}

fn session_for_user(user: lucid_auth::AuthUser, session_id: &str) -> SessionWithUser {
    let now = Utc::now();
    SessionWithUser {
        session: AuthSession {
            id: session_id.into(),
            user_id: user.id.clone(),
            token: format!("token-{session_id}"),
            actor_user_id: None,
            authentication_method: None,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields: Default::default(),
        },
        user,
    }
}

#[derive(Debug)]
struct EmptyIds;

impl DatabaseIdGenerator for EmptyIds {
    fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Id(String::new())
    }
}
