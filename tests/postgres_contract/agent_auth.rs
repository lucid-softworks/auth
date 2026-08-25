use lucid_auth::{
    AgentAuthSchema, AgentAuthStore, AgentCapabilityGrant, AgentGrantStatus, AgentHost,
    AgentHostStatus, AgentHostSwitchOutcome, AgentIdentity, AgentMode, AgentStatus,
    PostgresAgentAuthStore,
};
use uuid::Uuid;

pub(super) async fn assert_switch_contract(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = PostgresAgentAuthStore::new(pool.clone(), &AgentAuthSchema::default())?;
    sqlx::raw_sql(store.migration_sql()).execute(pool).await?;
    let now = chrono::Utc::now();
    let activated_at = now - chrono::Duration::hours(1);
    seed_switch(&store, now, activated_at).await?;
    let outcome = store
        .switch_host_account_cascade("pg-switch-host", user_id, now)
        .await?
        .expect("host exists");
    assert_outcome(&store, outcome, activated_at).await?;
    drop_agent_auth_tables(pool).await?;
    Ok(())
}

async fn seed_switch(
    store: &PostgresAgentAuthStore,
    now: chrono::DateTime<chrono::Utc>,
    activated_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), lucid_auth::AuthError> {
    store
        .create_host(AgentHost {
            id: "pg-switch-host".into(),
            name: Some("PostgreSQL switch host".into()),
            user_id: None,
            default_capabilities: vec![],
            public_key: Some("host-key".into()),
            kid: None,
            jwks_url: None,
            enrollment_token_hash: None,
            enrollment_token_expires_at: None,
            status: AgentHostStatus::Rejected,
            activated_at: Some(activated_at),
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        })
        .await?;
    store
        .create_agent(AgentIdentity {
            id: "pg-autonomous".into(),
            name: "PostgreSQL autonomous".into(),
            user_id: None,
            host_id: "pg-switch-host".into(),
            status: AgentStatus::Active,
            mode: AgentMode::Autonomous,
            public_key: "agent-key".into(),
            kid: None,
            jwks_url: None,
            last_used_at: None,
            activated_at: Some(now),
            expires_at: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        })
        .await?;
    seed_grants(store, now).await
}

async fn seed_grants(
    store: &PostgresAgentAuthStore,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), lucid_auth::AuthError> {
    for (id, capability, status) in [
        ("pg-active", "mail.read", AgentGrantStatus::Active),
        ("pg-denied", "mail.write", AgentGrantStatus::Denied),
    ] {
        store
            .create_grant(AgentCapabilityGrant {
                id: id.into(),
                agent_id: "pg-autonomous".into(),
                capability: capability.into(),
                constraints: None,
                denied_by: None,
                granted_by: None,
                expires_at: None,
                status,
                reason: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
    }
    Ok(())
}

async fn assert_outcome(
    store: &PostgresAgentAuthStore,
    outcome: AgentHostSwitchOutcome,
    activated_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), lucid_auth::AuthError> {
    assert_eq!(outcome.host.status, AgentHostStatus::Rejected);
    assert_eq!(
        outcome
            .host
            .activated_at
            .map(|value| value.timestamp_micros()),
        Some(activated_at.timestamp_micros())
    );
    assert_eq!(outcome.claimed_agents.len(), 1);
    assert_eq!(outcome.claimed_agents[0].agent.id, "pg-autonomous");
    assert_eq!(outcome.claimed_agents[0].agent.status, AgentStatus::Claimed);
    assert_eq!(outcome.claimed_agents[0].capabilities, ["mail.read"]);
    assert_eq!(
        store.find_grant_by_id("pg-active").await?.unwrap().status,
        AgentGrantStatus::Revoked
    );
    assert_eq!(
        store.find_grant_by_id("pg-denied").await?.unwrap().status,
        AgentGrantStatus::Revoked
    );
    Ok(())
}

async fn drop_agent_auth_tables(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        "DROP TABLE lucid_auth_agent_approval_requests, lucid_auth_agent_capability_grants, lucid_auth_agents, lucid_auth_agent_hosts",
    )
    .execute(pool)
    .await?;
    Ok(())
}
