use lucid_auth::{AuthService, AuthStore, OperatorSecurityStore, postgres::PostgresStore};
use sqlx::PgPool;

pub async fn assert_table_absent(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('lucid_auth_operator_temporary_passwords') IS NOT NULL",
        )
        .fetch_one(pool)
        .await?
    );
    Ok(())
}

pub async fn assert_atomic(
    service: &AuthService,
    store: &PostgresStore,
    signed_in: &lucid_auth::SignInResult,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    service
        .operator_security()
        .unwrap()
        .local_recover_sole_owner("owner", "operator recovered password".into())
        .await?;
    assert!(service.session(&signed_in.token).await?.is_none());
    assert!(store.list_passkeys(user_id).await?.is_empty());
    assert!(store.is_temporary_password(user_id).await?);
    assert!(
        service
            .sign_in_username("owner", "operator recovered password".into(), None, None)
            .await
            .is_ok()
    );
    Ok(())
}
