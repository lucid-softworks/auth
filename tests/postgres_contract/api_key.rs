use lucid_auth::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyPlugin, ApiKeyRateLimitConfig, AuthConfig, AuthError,
    AuthService, NewApiKey, SessionWithUser,
};
use std::sync::Arc;

pub(crate) async fn assert_table_absent(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('lucid_auth_api_keys')::TEXT")
            .fetch_one(pool)
            .await?,
        None
    );
    Ok(())
}

pub(crate) fn register(config: &mut AuthConfig) -> Result<ApiKeyConfiguration, AuthError> {
    let configuration = ApiKeyConfiguration {
        rate_limit: ApiKeyRateLimitConfig {
            enabled: true,
            time_window_milliseconds: 60_000,
            max_requests: 4,
        },
        ..ApiKeyConfiguration::default()
    };
    config.add_plugin(ApiKeyPlugin::new(configuration.clone()))?;
    Ok(configuration)
}

pub(crate) async fn assert_limits_are_atomic(
    service: &Arc<AuthService>,
    configuration: &ApiKeyConfiguration,
    actor: &SessionWithUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let issued = service
        .issue_api_key(
            actor,
            configuration,
            NewApiKey {
                config_id: "default".into(),
                name: None,
                prefix: None,
                expires_at: None,
                permissions: None,
                metadata: None,
                remaining: Some(32),
                refill_amount: None,
                refill_interval: None,
                rate_limit_enabled: true,
                rate_limit_time_window: Some(60_000),
                rate_limit_max: Some(4),
            },
        )
        .await?;
    let mut claims = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let service = service.clone();
        let configuration = configuration.clone();
        let key = issued.key.clone();
        claims.spawn(async move {
            service
                .verify_api_key(&key, &[configuration], Some("default"), None)
                .await
        });
    }
    let mut allowed = 0;
    let mut limited = 0;
    while let Some(outcome) = claims.join_next().await {
        match outcome? {
            Ok(_) => allowed += 1,
            Err(AuthError::ApiKey(ApiKeyError::RateLimited { .. })) => limited += 1,
            result => return Err(format!("unexpected API-key claim result: {result:?}").into()),
        }
    }
    assert_eq!(allowed, 4);
    assert_eq!(limited, 28);
    Ok(())
}
