use super::*;

pub(super) async fn assert_lifecycle(
    service: &AuthService,
    store: &PostgresStore,
) -> Result<(), AuthError> {
    let anonymous = service
        .sign_in_anonymous(Some("127.0.0.1".into()), Some("postgres contract".into()))
        .await?;
    let user_id = anonymous.session.user.id.clone();
    assert!(anonymous.session.user.is_anonymous);
    assert_eq!(store.list_sessions(&user_id).await?.len(), 1);
    service.delete_anonymous_user(&anonymous.session).await?;
    assert!(store.find_user_by_id(&user_id).await?.is_none());
    assert!(store.list_sessions(&user_id).await?.is_empty());
    Ok(())
}
