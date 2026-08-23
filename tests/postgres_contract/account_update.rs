use lucid_auth::{AuthError, AuthService, AuthStore, UserProfileUpdate, postgres::PostgresStore};
use serde_json::{Map, json};

pub(super) async fn assert_persistence(
    service: &AuthService,
    store: &PostgresStore,
    session: &lucid_auth::SessionWithUser,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'lucid_auth_sessions' \
             AND column_name = 'additional_fields'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    let user = service
        .update_current_user(
            session,
            UserProfileUpdate {
                additional_fields: Map::from_iter([("timezone".into(), json!("UTC"))]),
                ..UserProfileUpdate::default()
            },
        )
        .await?;
    assert_eq!(user.additional_fields["timezone"], "UTC");
    let updated_session = service
        .update_current_session(session, Map::from_iter([("theme".into(), json!("dark"))]))
        .await?;
    assert_eq!(updated_session.additional_fields["theme"], "dark");
    let persisted = store
        .find_session(&session.session.token_hash)
        .await?
        .unwrap();
    assert_eq!(persisted.0.additional_fields["theme"], "dark");

    let other = service
        .provision_password_user(lucid_auth::NewPasswordUser {
            username: "email_target".into(),
            name: "Email Target".into(),
            email: Some("email-target@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "member".into(),
        })
        .await?;
    let duplicate = store
        .update_user_email(session.user.id, &session.user.email, &other.email, true)
        .await
        .unwrap_err();
    assert!(matches!(duplicate, AuthError::UserAlreadyExistsEmail));
    Ok(())
}
