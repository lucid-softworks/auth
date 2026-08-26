use lucid_auth::{AuthError, AuthService, EmailSignUpInput, UsernameError};

pub(super) async fn email_is_case_insensitive(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let signup = |email: &str| EmailSignUpInput {
        name: "PostgreSQL email user".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: None,
        display_username: None,
        additional_fields: serde_json::Map::new(),
    };
    let (left, right) = tokio::join!(
        service.sign_up_email(signup("Case.Variant@Example.com"), None, None),
        service.sign_up_email(signup("case.variant@example.com"), None, None)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let error = left.err().or_else(|| right.err()).unwrap();
    assert!(matches!(error, AuthError::UserAlreadyExistsEmail));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM \"user\" WHERE LOWER(\"email\") = 'case.variant@example.com'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

pub(super) async fn username_is_atomic(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let signup = |email: &str, username: &str| EmailSignUpInput {
        name: "PostgreSQL username user".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: Some(username.into()),
        display_username: None,
        additional_fields: serde_json::Map::new(),
    };
    let (left, right) = tokio::join!(
        service.sign_up_email(
            signup("postgres-username-left@example.com", "Postgres_User"),
            None,
            None,
        ),
        service.sign_up_email(
            signup("postgres-username-right@example.com", "postgres_user"),
            None,
            None,
        )
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let error = left.err().or_else(|| right.err()).unwrap();
    assert!(matches!(
        error,
        AuthError::Username(UsernameError::AlreadyTaken)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM \"user\" WHERE \"username\" = 'postgres_user'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}
