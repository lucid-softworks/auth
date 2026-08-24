use lucid_auth::{AuthError, AuthService, AuthStore, postgres::PostgresStore};
use std::sync::Arc;

pub(super) async fn assert_atomic(
    service: &AuthService,
    store: &Arc<PostgresStore>,
) -> Result<(), AuthError> {
    let session = service
        .sign_in_username("owner", "correct horse battery staple".into(), None, None)
        .await?;
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::days(7);
    let refreshed = store
        .refresh_session(&session.token, expires_at, now)
        .await?
        .expect("an existing PostgreSQL session refreshes");
    assert_eq!(refreshed.expires_at, expires_at);
    assert_eq!(refreshed.updated_at, now);

    store.delete_session(&session.token).await?;
    assert!(
        store
            .refresh_session(&session.token, expires_at, now)
            .await?
            .is_none(),
        "the atomic update must not recreate a concurrently deleted session"
    );
    Ok(())
}
