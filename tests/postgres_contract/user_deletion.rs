use lucid_auth::{AuthService, EmailSignUpInput};

pub(super) async fn assert_transactional(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let signup = service
        .sign_up_email(
            EmailSignUpInput {
                name: "PostgreSQL deleted user".into(),
                email: "postgres-delete@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: Some("postgres_delete".into()),
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await?;
    let session = service
        .session(signup.token.as_deref().unwrap())
        .await?
        .unwrap();
    service
        .delete_current_user(
            &session,
            Some("correct horse battery staple".into()),
            None,
            None,
        )
        .await?;
    for table in [
        "lucid_auth_users",
        "lucid_auth_accounts",
        "lucid_auth_sessions",
    ] {
        let user_column = if table == "lucid_auth_users" {
            "id"
        } else {
            "user_id"
        };
        let count = sqlx::query_scalar::<_, i64>(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {user_column} = $1"
        ))
        .bind(signup.user.id)
        .fetch_one(pool)
        .await?;
        assert_eq!(count, 0, "{table} retained deleted user data");
    }
    Ok(())
}
