use super::{
    database::StrategyDatabase,
    oauth_provider_round_trip::{MODELS, OAuthIds, exercise},
};

pub(super) async fn assert_round_trip(
    database: &StrategyDatabase,
) -> Result<OAuthIds, Box<dyn std::error::Error>> {
    let mut statements = String::new();
    for (model, sequence, label) in MODELS
        .into_iter()
        .zip([
            ("resource", "resource"),
            ("client", "client"),
            ("client_resource", "client-resource"),
            ("consent", "consent"),
            ("refresh", "refresh"),
            ("access", "access"),
            ("assertion", "assertion"),
        ])
        .map(|(model, (sequence, label))| (model, sequence, label))
    {
        statements.push_str(&format!(
            "CREATE SEQUENCE database_{sequence}_oauth_id; \
             ALTER TABLE \"{model}\" ALTER COLUMN id SET DEFAULT \
             ('database-oauth-{label}-' || nextval('database_{sequence}_oauth_id')::text); "
        ));
    }
    sqlx::raw_sql(&statements).execute(&database.pool).await?;
    let (user_id, session_id) = sqlx::query_as::<_, (String, String)>(
        r#"SELECT u.id::text, s.id::text FROM "user" u
             JOIN "session" s ON s."userId" = u.id ORDER BY s."createdAt" LIMIT 1"#,
    )
    .fetch_one(&database.pool)
    .await?;
    exercise(
        database,
        "database-oauth",
        &user_id,
        &session_id,
        None,
        "text",
    )
    .await
}
