#![cfg(feature = "mysql")]

use crate::support::pool;
use chrono::{Duration, Timelike, Utc};
use lucid_auth::mysql::{MySqlAdapterConfig, MySqlStore};
use lucid_auth::{
    AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentAuthConfig,
    AgentAuthPlugin, AgentAuthStore, AgentCapabilityGrant, AgentGrantStatus, AgentHost,
    AgentHostRotationOutcome, AgentHostStatus, AgentIdentity, AgentMode, AgentRegistrationBundle,
    AgentRegistrationOutcome, AgentStatus, AgentStoreCreateOutcome, AuthConfig, AuthService,
    DatabaseIdValue, JwtPlugin, OAuthProviderPlugin, OAuthProviderPluginConfig,
    OAuthProviderResource, OAuthProviderResourceStore, Organization, OrganizationDataStore,
    OrganizationPlugin, PreparedDatabaseId,
};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn oauth_provider_resource_rows_use_the_plugin_catalog() {
    let store = MySqlStore::new(pool(4).await, MySqlAdapterConfig::default());
    let mut config = AuthConfig::new([94; 32]).unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config
        .add_plugin(OAuthProviderPlugin::new(
            OAuthProviderPluginConfig::new("/login", "/consent"),
            store.clone(),
        ))
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let id = || {
        Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
            "resource-1".into(),
        )))
    };
    let resource = OAuthProviderResource {
        id: String::new(),
        identifier: "https://resource.example".into(),
        name: "Resource".into(),
        access_token_ttl: Some(900),
        refresh_token_ttl: None,
        signing_algorithm: None,
        signing_key_id: None,
        allowed_scopes: Some(vec!["read".into()]),
        custom_claims: Some(serde_json::json!({"aud": "resource"})),
        dpop_bound_access_tokens_required: false,
        disabled: false,
        created_at: Some(Utc::now()),
        updated_at: None,
        policy_version: 1,
        metadata: Some(serde_json::json!({"tier": "internal"})),
    };
    let stored = store
        .create_oauth_resource(&id, resource)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, "resource-1");
    assert_eq!(stored.allowed_scopes, Some(vec!["read".into()]));
    assert_eq!(
        store
            .find_oauth_resource("https://resource.example")
            .await
            .unwrap(),
        Some(stored)
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn organization_metadata_uses_better_auth_string_storage() {
    let store = MySqlStore::new(pool(4).await, MySqlAdapterConfig::default());
    let mut config = AuthConfig::new([93; 32]).unwrap();
    config
        .add_plugin(OrganizationPlugin::new(Arc::new(store.clone())))
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let now = Utc::now();
    let id = || {
        Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
            "organization-1".into(),
        )))
    };
    let organization = store
        .raw_insert_organization(
            Organization {
                id: String::new(),
                name: "MySQL Org".into(),
                slug: "mysql-org".into(),
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
    assert_eq!(
        store.find_organization_by_slug("mysql-org").await.unwrap(),
        Some(organization)
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn agent_auth_models_and_atomic_lifecycle_use_mysql() {
    let store = agent_auth_store().await;
    let now = Utc::now();
    let now = now
        .with_nanosecond(now.timestamp_subsec_millis() * 1_000_000)
        .unwrap();
    let (host, agent, grant, approval) = agent_auth_records(now);
    let outcome = store
        .register_agent_bundle(AgentRegistrationBundle {
            host: Some(host.clone()),
            agent: agent.clone(),
            grants: vec![grant.clone()],
            approval: Some(approval.clone()),
        })
        .await
        .unwrap();
    assert!(matches!(outcome, AgentRegistrationOutcome::Registered(_)));
    assert_agent_auth_records(&store, &host, &agent, &grant, &approval).await;
    assert!(matches!(
        store
            .create_host(AgentHost {
                id: "agent-host-duplicate".into(),
                ..host
            })
            .await
            .unwrap(),
        AgentStoreCreateOutcome::UniqueConflict
    ));
    assert!(matches!(
        store
            .rotate_host_key(
                &host.id,
                "agent-host-2",
                "rotated-host-public-key".into(),
                Some("rotated-host-kid".into()),
                now + Duration::seconds(1),
            )
            .await
            .unwrap(),
        AgentHostRotationOutcome::Rotated(_)
    ));
    assert_eq!(
        store.find_agent(&agent.id).await.unwrap().unwrap().host_id,
        "agent-host-2"
    );
    assert_eq!(
        store
            .find_approval(&approval.id)
            .await
            .unwrap()
            .unwrap()
            .host_id
            .as_deref(),
        Some("agent-host-2")
    );
    let revoked = store
        .revoke_agent_cascade(&agent.id, now + Duration::seconds(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.grants_revoked, 1);
    assert_eq!(
        store.find_agent(&agent.id).await.unwrap().unwrap().status,
        AgentStatus::Revoked
    );
}

async fn agent_auth_store() -> MySqlStore {
    let store = MySqlStore::new(pool(4).await, MySqlAdapterConfig::default());
    let mut config = AuthConfig::new([98; 32]).unwrap();
    config
        .add_plugin(AgentAuthPlugin::new(AgentAuthConfig::default(), store.clone()).unwrap())
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    store
}

fn agent_auth_records(
    now: chrono::DateTime<Utc>,
) -> (
    AgentHost,
    AgentIdentity,
    AgentCapabilityGrant,
    AgentApprovalRequest,
) {
    let host = agent_host(now);
    let agent = agent_identity(now, &host.id);
    let grant = agent_grant(now, &agent.id);
    let approval = agent_approval(now, &host.id, &agent.id);
    (host, agent, grant, approval)
}

fn agent_host(now: chrono::DateTime<Utc>) -> AgentHost {
    AgentHost {
        id: "agent-host-1".into(),
        name: Some("Host".into()),
        user_id: None,
        default_capabilities: vec!["files.read".into()],
        public_key: Some("host-public-key".into()),
        kid: Some("host-kid".into()),
        jwks_url: None,
        enrollment_token_hash: None,
        enrollment_token_expires_at: None,
        status: AgentHostStatus::Active,
        activated_at: Some(now),
        expires_at: None,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn agent_identity(now: chrono::DateTime<Utc>, host_id: &str) -> AgentIdentity {
    AgentIdentity {
        id: "agent-1".into(),
        name: "MySQL Agent".into(),
        user_id: None,
        host_id: host_id.into(),
        status: AgentStatus::Active,
        mode: AgentMode::Autonomous,
        public_key: "agent-public-key".into(),
        kid: Some("agent-kid".into()),
        jwks_url: None,
        last_used_at: None,
        activated_at: Some(now),
        expires_at: None,
        metadata: Some(serde_json::Map::from_iter([(
            "runtime".into(),
            serde_json::json!("mysql"),
        )])),
        created_at: now,
        updated_at: now,
    }
}

fn agent_grant(now: chrono::DateTime<Utc>, agent_id: &str) -> AgentCapabilityGrant {
    AgentCapabilityGrant {
        id: "agent-grant-1".into(),
        agent_id: agent_id.into(),
        capability: "files.read".into(),
        constraints: None,
        denied_by: None,
        granted_by: None,
        expires_at: None,
        status: AgentGrantStatus::Active,
        reason: None,
        created_at: now,
        updated_at: now,
    }
}

fn agent_approval(
    now: chrono::DateTime<Utc>,
    host_id: &str,
    agent_id: &str,
) -> AgentApprovalRequest {
    AgentApprovalRequest {
        id: "agent-approval-1".into(),
        method: AgentApprovalMethod::DeviceAuthorization,
        agent_id: Some(agent_id.into()),
        host_id: Some(host_id.into()),
        user_id: None,
        capabilities: Some("files.read".into()),
        status: AgentApprovalStatus::Pending,
        user_code_hash: Some("agent-code-hash".into()),
        login_hint: None,
        binding_message: None,
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: None,
        interval: 5.0,
        last_polled_at: None,
        expires_at: now + Duration::minutes(5),
        created_at: now,
        updated_at: now,
    }
}

async fn assert_agent_auth_records(
    store: &MySqlStore,
    host: &AgentHost,
    agent: &AgentIdentity,
    grant: &AgentCapabilityGrant,
    approval: &AgentApprovalRequest,
) {
    assert_eq!(
        store.find_host_by_kid("host-kid").await.unwrap(),
        Some(host.clone())
    );
    assert_eq!(
        store.find_agent_by_kid("agent-kid").await.unwrap(),
        Some(agent.clone())
    );
    assert_eq!(
        store.find_grant_by_id(&grant.id).await.unwrap(),
        Some(grant.clone())
    );
    assert_eq!(
        store
            .find_approval_by_user_code_hash("agent-code-hash")
            .await
            .unwrap(),
        Some(approval.clone())
    );
}
