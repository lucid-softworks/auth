use chrono::{Duration, Utc};
use lucid_auth::{
    AuthConfig, AuthService, EmailSignUpInput, OAuthProviderPlugin, OAuthProviderPluginConfig,
    postgres::{PostgresOAuthProviderStore, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "oauth_provider_schema/atomic.rs"]
mod atomic;
#[path = "oauth_provider_schema/fixtures.rs"]
mod fixtures;
#[path = "oauth_provider_schema/round_trip.rs"]
mod round_trip;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn bound_schema_and_queries_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let database_schema = format!("lucid_auth_oauth_schema_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {database_schema}"))
        .execute(&admin)
        .await?;

    let search_path = format!("SET search_path TO {database_schema}");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;
    let store = Arc::new(PostgresStore::new(pool.clone(), Default::default()));

    let provider_config = mapped_config();
    let provider = OAuthProviderPlugin::postgres(provider_config.clone(), (*store).clone())?;
    let mut auth_config = AuthConfig::new([193_u8; 32])?;
    auth_config.email_and_password.enabled = true;
    auth_config.add_plugin(provider)?;
    let service = AuthService::try_new(store.clone(), auth_config)?;
    let migrations = service.plugin_migrations();
    assert!(migrations.is_empty());
    store.migrate_all(&migrations).await?;
    store.migrate_all(&migrations).await?;

    let mapped = PostgresOAuthProviderStore::new((*store).clone());
    round_trip::all_seven_models(&service, &mapped).await?;
    atomic::one_time_operations(&service, &mapped).await?;

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {database_schema} CASCADE"))
        .execute(&admin)
        .await?;
    Ok(())
}

fn mapped_config() -> OAuthProviderPluginConfig {
    let mut config = OAuthProviderPluginConfig::new("/login", "/consent");
    config.disable_jwt_plugin = true;
    map_model(
        &mut config.schema.oauth_client,
        "oauthClientRecords",
        &[("clientId", "clientKey")],
    );
    map_model(
        &mut config.schema.oauth_resource,
        "oauthResourceRecords",
        &[("identifier", "resourceKey")],
    );
    map_model(
        &mut config.schema.oauth_client_resource,
        "oauthClientResourceRecords",
        &[
            ("clientId", "linkedClient"),
            ("resourceId", "linkedResource"),
        ],
    );
    map_model(
        &mut config.schema.oauth_refresh_token,
        "oauthRefreshRecords",
        &[("token", "refreshValue"), ("revoked", "refreshRevoked")],
    );
    map_model(
        &mut config.schema.oauth_access_token,
        "oauthAccessRecords",
        &[("token", "accessValue"), ("refreshId", "parentRefresh")],
    );
    map_model(
        &mut config.schema.oauth_consent,
        "oauthConsentRecords",
        &[("clientId", "consentClient"), ("scopes", "grantedScopes")],
    );
    map_model(
        &mut config.schema.oauth_client_assertion,
        "oauthAssertionRecords",
        &[("expiresAt", "expiresOn")],
    );
    config
}

fn map_model(
    model: &mut lucid_auth::OAuthProviderModelSchema,
    name: &str,
    fields: &[(&str, &str)],
) {
    model.model_name = Some(name.into());
    for (logical, physical) in fields {
        model.fields.insert((*logical).into(), (*physical).into());
    }
}

async fn provision_user(service: &AuthService) -> Result<Uuid, lucid_auth::AuthError> {
    service
        .sign_up_email(
            EmailSignUpInput {
                name: "OAuth storage owner".into(),
                email: format!("oauth-storage-{}@example.com", Uuid::new_v4().simple()),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await
        .map(|result| result.user.id)
}

fn now() -> chrono::DateTime<Utc> {
    chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("current timestamp is representable")
        + Duration::seconds(1)
}
