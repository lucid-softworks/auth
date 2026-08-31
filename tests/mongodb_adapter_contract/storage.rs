use crate::support::configured_store;
use chrono::{Duration, Utc};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyPlugin, AuthConfig, AuthSession, AuthStore, AuthUser,
    DatabaseCreate, DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerator, DatabaseIdInput, DatabaseIdPlan, Organization, OrganizationDataStore,
    OrganizationPlugin,
    mongodb::{MongoAdapterConfig, MongoStore},
};
use mongodb::bson::{Bson, Document, spec::BinarySubtype};
use serde_json::Map;
use std::sync::Arc;

#[derive(Debug)]
struct FixedId;

impl DatabaseIdGenerator for FixedId {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Id(format!("custom-{}", request.model))
    }
}

fn user(now: chrono::DateTime<Utc>) -> AuthUser {
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "Mongo User".into(),
        email: "USER@EXAMPLE.COM".into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

fn create<T>(strategy: DatabaseIdGeneration, model: &str, value: T) -> DatabaseCreate<T> {
    DatabaseCreate::new(
        value,
        DatabaseIdPlan::new(strategy, model, DatabaseIdInput::Absent, false),
    )
}

async fn store_with(mut config: AuthConfig) -> MongoStore {
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    configured_store(
        "MONGODB_STANDALONE_URI",
        MongoAdapterConfig {
            transaction: Some(false),
            ..Default::default()
        },
        config,
    )
    .await
}

#[tokio::test]
#[ignore = "requires MongoDB in MONGODB_STANDALONE_URI"]
async fn core_and_representative_plugin_records_round_trip() {
    let mut config = AuthConfig::new([65; 32]).unwrap();
    let store = configured_store(
        "MONGODB_STANDALONE_URI",
        MongoAdapterConfig {
            transaction: Some(false),
            ..Default::default()
        },
        {
            let placeholder = MongoStore::connect(
                &std::env::var("MONGODB_STANDALONE_URI").unwrap(),
                "lucid_auth_plugin_placeholder",
                MongoAdapterConfig {
                    transaction: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            config
                .add_plugin(OrganizationPlugin::new(Arc::new(placeholder)))
                .unwrap();
            config
        },
    )
    .await;
    let now = Utc::now();
    let stored = assert_user_and_session(&store, now).await;
    assert!(mongodb::bson::oid::ObjectId::parse_str(&stored.id).is_ok());
    assert_organization(&store, now).await;
}

async fn assert_user_and_session(store: &MongoStore, now: chrono::DateTime<Utc>) -> AuthUser {
    let stored = store
        .create_user_without_account(create(DatabaseIdGeneration::Default, "user", user(now)))
        .await
        .unwrap();
    assert_eq!(stored.id.len(), 24);
    assert_eq!(stored.email, "user@example.com");
    let raw = store
        .database()
        .collection::<Document>("user")
        .find_one(Document::new())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(raw.get("_id"), Some(Bson::ObjectId(_))));

    let session = AuthSession {
        id: String::new(),
        user_id: stored.id.clone(),
        token: "token-1".into(),
        actor_user_id: None,
        authentication_method: None,
        expires_at: now + Duration::hours(1),
        created_at: now,
        updated_at: now,
        ip_address: None,
        user_agent: None,
        additional_fields: Map::new(),
    };
    store
        .create_session(create(DatabaseIdGeneration::Default, "session", session))
        .await
        .unwrap();
    assert_eq!(
        store.find_session("token-1").await.unwrap().unwrap().1,
        stored
    );
    stored
}

async fn assert_organization(store: &MongoStore, now: chrono::DateTime<Utc>) {
    let id = || {
        Ok(lucid_auth::PreparedDatabaseId::Value(
            lucid_auth::DatabaseIdValue::String("org-1".into()),
        ))
    };
    let organization = store
        .raw_insert_organization(
            Organization {
                id: String::new(),
                name: "Mongo Org".into(),
                slug: "mongo-org".into(),
                logo: None,
                metadata: Some(serde_json::json!({"plan": "pro"})),
                created_at: now,
            },
            &id,
        )
        .await
        .unwrap();
    assert_eq!(
        organization.metadata,
        Some(serde_json::json!({"plan": "pro"}))
    );
}

#[tokio::test]
#[ignore = "requires MongoDB in MONGODB_STANDALONE_URI"]
async fn uuid_and_callback_strategies_use_distinct_bson_forms() {
    let mut uuid_config = AuthConfig::new([66; 32]).unwrap();
    uuid_config.database_id_generation = DatabaseIdGeneration::Uuid;
    let uuid_store = store_with(uuid_config).await;
    let uuid_user = uuid_store
        .create_user_without_account(create(DatabaseIdGeneration::Uuid, "user", user(Utc::now())))
        .await
        .unwrap();
    assert!(uuid::Uuid::parse_str(&uuid_user.id).is_ok());
    let raw = uuid_store
        .database()
        .collection::<Document>("user")
        .find_one(Document::new())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(raw.get("_id"), Some(Bson::Binary(binary)) if binary.subtype == BinarySubtype::Uuid)
    );

    let generator = Arc::new(FixedId);
    let mut callback_config = AuthConfig::new([67; 32]).unwrap();
    callback_config.database_id_generation = DatabaseIdGeneration::Callback(generator.clone());
    let callback_store = store_with(callback_config).await;
    let callback_user = callback_store
        .create_user_without_account(create(
            DatabaseIdGeneration::Callback(generator),
            "user",
            user(Utc::now()),
        ))
        .await
        .unwrap();
    assert_eq!(callback_user.id, "custom-user");
    let raw = callback_store
        .database()
        .collection::<Document>("user")
        .find_one(Document::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.get_str("_id").unwrap(), "custom-user");
}
