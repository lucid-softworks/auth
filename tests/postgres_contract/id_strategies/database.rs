use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, DatabaseIdGeneration, DeviceAuthorizationConfig,
    DeviceAuthorizationPlugin, JwtConfig, JwtPlugin, OAuthProviderPlugin,
    OAuthProviderPluginConfig, OrganizationDynamicAccessControlConfig, OrganizationPlugin,
    OrganizationPluginConfig, OrganizationTeamsConfig, PasskeyConfig, PasskeyPlugin, SiweConfig,
    SiweMessageVerifier, SiweNonceGenerator, SiwePlugin, SiweVerificationRequest, TwoFactorConfig,
    TwoFactorPlugin, UsernamePlugin,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

struct Nonce(AtomicU64);

#[async_trait]
impl SiweNonceGenerator for Nonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(format!(
            "strategy{:08}",
            self.0.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

struct Verifier;

#[async_trait]
impl SiweMessageVerifier for Verifier {
    async fn verify(&self, _: SiweVerificationRequest) -> Result<bool, AuthError> {
        Ok(true)
    }
}

pub(super) struct StrategyDatabase {
    pub(super) pool: sqlx::PgPool,
    pub(super) service: Arc<AuthService>,
    pub(super) store: Arc<PostgresStore>,
    pub(super) strategy: DatabaseIdGeneration,
    admin: sqlx::PgPool,
    schema: String,
}

impl StrategyDatabase {
    pub(super) async fn start(
        strategy: DatabaseIdGeneration,
        label: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")?;
        let (admin, pool, schema) = isolated_pool(&database_url, label).await?;
        let store = Arc::new(PostgresStore::new(
            pool.clone(),
            PostgresAdapterConfig::default(),
        ));
        let config = strategy_config(strategy.clone(), store.clone())?;
        let service = Arc::new(AuthService::try_new(store.clone(), config)?);
        store.migrate().await?;
        Ok(Self {
            pool,
            service,
            store,
            strategy,
            admin,
            schema,
        })
    }

    pub(super) async fn close(self) -> Result<(), Box<dyn std::error::Error>> {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}

async fn isolated_pool(
    database_url: &str,
    label: &str,
) -> Result<(sqlx::PgPool, sqlx::PgPool, String), Box<dyn std::error::Error>> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let schema = format!("lucid_id_{label}_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await?;
    let search_path = format!("SET search_path TO \"{schema}\"");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await?;
    Ok((admin, pool, schema))
}

fn strategy_config(
    strategy: DatabaseIdGeneration,
    store: Arc<PostgresStore>,
) -> Result<AuthConfig, Box<dyn std::error::Error>> {
    let mut config = AuthConfig::new([b'P'; 32])?;
    config.database_id_generation = strategy;
    config.email_and_password.enabled = true;
    config.add_plugin(UsernamePlugin::default())?;
    config.add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))?;
    add_organization_plugin(&mut config, &store)?;
    config.add_plugin(TwoFactorPlugin::new(
        store.clone(),
        TwoFactorConfig::default(),
    ))?;
    config.add_plugin(JwtPlugin::new(JwtConfig::default()))?;
    config.add_plugin(DeviceAuthorizationPlugin::postgres(
        DeviceAuthorizationConfig::default(),
        (*store).clone(),
    ))?;
    add_oauth_provider_plugin(&mut config, &store)?;
    config.add_plugin(SiwePlugin::new(store, siwe_config()))?;
    Ok(config)
}

fn add_organization_plugin(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    config.add_plugin(OrganizationPlugin::with_config(
        store.clone(),
        OrganizationPluginConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..OrganizationTeamsConfig::default()
            },
            dynamic_access_control: OrganizationDynamicAccessControlConfig {
                enabled: true,
                ..OrganizationDynamicAccessControlConfig::default()
            },
            ..OrganizationPluginConfig::default()
        },
    ))?;
    Ok(())
}

fn add_oauth_provider_plugin(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut oauth_provider = OAuthProviderPluginConfig::new("/login", "/consent");
    oauth_provider.disable_jwt_plugin = true;
    config.add_plugin(OAuthProviderPlugin::postgres(
        oauth_provider,
        (**store).clone(),
    )?)?;
    Ok(())
}

fn siwe_config() -> SiweConfig {
    let mut config = SiweConfig::new(
        "example.com",
        Arc::new(Nonce(AtomicU64::new(1))),
        Arc::new(Verifier),
    );
    config.email_domain_name = Some("example.com".into());
    config
}
