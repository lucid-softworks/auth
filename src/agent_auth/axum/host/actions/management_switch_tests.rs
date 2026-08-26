use super::*;
use crate::{
    AgentAuthConfig, AgentAuthStore, AgentAutonomousClaimedCallback, AgentAutonomousClaimedContext,
    AgentCapabilityGrant, AgentEndpointContext, AgentGrantStatus, AgentIdentity, AgentMode,
    AgentStatus, MemoryAgentAuthStore, MemoryOrganizationStore, Organization,
    OrganizationCreateOutcome, OrganizationDataStore, OrganizationMember, OrganizationMemberStore,
    OrganizationMemberWriteOutcome, agent_auth::axum::host::events::test_support::EventRecorder,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

fn endpoint() -> AgentEndpointContext {
    AgentEndpointContext {
        method: "POST".into(),
        path: "/host/switch-account".into(),
        base_url: "https://auth.example.test/api/auth".into(),
        headers: BTreeMap::new(),
    }
}

fn state(config: AgentAuthConfig) -> (AgentAuthState, Arc<MemoryAgentAuthStore>) {
    let verifier = crate::agent_auth::axum::memory_verifier();
    let store = Arc::new(MemoryAgentAuthStore::default());
    (
        AgentAuthState {
            config: Arc::new(config),
            store: store.clone(),
            organization_store: None,
            host_auth: crate::agent_auth::axum::host::HostAuthState::from_verifier(
                verifier.clone(),
            ),
            verifier,
        },
        store,
    )
}

async fn create_host(state: &AgentAuthState, user: &str, kid: &str) -> String {
    let created = super::super::registration::create_for_user(
        state,
        user,
        crate::agent_auth::axum::host::model::CreateHostBody {
            name: None,
            public_key: Some(json!({"kty":"OKP","crv":"Ed25519","x":"key","kid":kid})),
            jwks_url: None,
            default_capabilities: Some(vec![]),
        },
        endpoint(),
        Utc::now(),
    )
    .await
    .unwrap();
    created["hostId"].as_str().unwrap().to_owned()
}

async fn install_shared_organization(
    state: &mut AgentAuthState,
    member: &str,
    owner: &str,
    now: DateTime<Utc>,
) {
    let store = Arc::new(MemoryOrganizationStore::default());
    let organization_id = Uuid::new_v4();
    let organization = Organization {
        id: organization_id,
        name: "Shared".into(),
        slug: format!("shared-{organization_id}"),
        logo: None,
        metadata: None,
        created_at: now,
    };
    let membership = |user_id: &str, role: &str| OrganizationMember {
        id: Uuid::new_v4(),
        organization_id,
        user_id: user_id.to_owned(),
        role: role.into(),
        created_at: now,
    };
    assert_eq!(
        store
            .create_organization(organization, membership(owner, "owner"), None, None)
            .await
            .unwrap(),
        OrganizationCreateOutcome::Created
    );
    assert_eq!(
        store
            .add_member(membership(member, "member"), 100)
            .await
            .unwrap(),
        OrganizationMemberWriteOutcome::Written
    );
    state.organization_store = Some(store);
}

async fn assert_management_access(
    state: &AgentAuthState,
    member: &str,
    ids: &[String; 3],
    now: DateTime<Utc>,
    allowed: bool,
) {
    let update = update_for_user(
        state,
        member,
        UpdateHostBody {
            host_id: ids[0].clone(),
            name: Some("Updated".into()),
            public_key: None,
            jwks_url: None,
            default_capabilities: None,
        },
        now,
    )
    .await;
    let switched = switch_to_user(state, member, &ids[1], endpoint(), now).await;
    let revoked = revoke_authorized(
        state,
        HostAuthorization::User(member.to_owned()),
        Some(ids[2].clone()),
        now,
    )
    .await;
    assert_eq!(update.is_ok(), allowed);
    assert_eq!(switched.is_ok(), allowed);
    assert_eq!(revoked.is_ok(), allowed);
}

#[tokio::test]
async fn shared_organization_members_match_host_management_authorization() {
    let (mut state, _) = state(AgentAuthConfig::default());
    let owner = Uuid::new_v4().to_string();
    let member = Uuid::new_v4().to_string();
    let now = Utc::now();
    let ids = [
        create_host(&state, &owner, "org-update").await,
        create_host(&state, &owner, "org-switch").await,
        create_host(&state, &owner, "org-revoke").await,
    ];
    assert_management_access(&state, &member, &ids, now, false).await;
    install_shared_organization(&mut state, &member, &owner, now).await;
    assert_management_access(&state, &member, &ids, now, true).await;
}

#[derive(Clone, Default)]
struct AutonomousClaimRecorder(Arc<Mutex<Vec<AgentAutonomousClaimedContext>>>);

#[async_trait]
impl AgentAutonomousClaimedCallback for AutonomousClaimRecorder {
    async fn call(&self, context: AgentAutonomousClaimedContext) {
        self.0.lock().await.push(context);
    }
}

async fn seed_autonomous_claim(
    state: &AgentAuthState,
    store: &MemoryAgentAuthStore,
    user: &str,
    now: DateTime<Utc>,
) -> (String, DateTime<Utc>) {
    let host_id = create_host(state, user, "claim-host").await;
    let activated_at = now - chrono::Duration::hours(1);
    let mut host = store.find_host(&host_id).await.unwrap().unwrap();
    host.user_id = None;
    host.status = AgentHostStatus::Rejected;
    host.activated_at = Some(activated_at);
    store.update_host(host).await.unwrap();
    store
        .create_agent(AgentIdentity {
            id: "autonomous".into(),
            name: "Autonomous".into(),
            user_id: None,
            host_id: host_id.clone(),
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
        .await
        .unwrap();
    seed_grants(store, now).await;
    (host_id, activated_at)
}

async fn seed_grants(store: &MemoryAgentAuthStore, now: DateTime<Utc>) {
    for (id, capability, status) in [
        ("active-grant", "mail.read", AgentGrantStatus::Active),
        ("denied-grant", "mail.write", AgentGrantStatus::Denied),
    ] {
        store
            .create_grant(AgentCapabilityGrant {
                id: id.into(),
                agent_id: "autonomous".into(),
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
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn switch_preserves_lifecycle_and_emits_autonomous_claim_contract() {
    let events = EventRecorder::default();
    let claims = AutonomousClaimRecorder::default();
    let config = AgentAuthConfig {
        on_event: Some(Arc::new(events.clone())),
        on_autonomous_agent_claimed: Some(Arc::new(claims.clone())),
        ..AgentAuthConfig::default()
    };
    let (state, store) = state(config);
    let now = Utc::now();
    let user = Uuid::new_v4().to_string();
    let (host_id, activated_at) = seed_autonomous_claim(&state, &store, &user, now).await;
    events.wait_for(1).await;
    events.clear().await;

    let response = switch_to_user(&state, &user, &host_id, endpoint(), now)
        .await
        .unwrap();
    assert_eq!(response["status"], "rejected");
    assert_preserved_host(&store, &host_id, activated_at).await;
    assert_claim_callback(&claims, &host_id).await;
    assert_claim_event(&events, &user, &host_id).await;
}

async fn assert_preserved_host(
    store: &MemoryAgentAuthStore,
    host_id: &str,
    activated_at: DateTime<Utc>,
) {
    let host = store.find_host(host_id).await.unwrap().unwrap();
    assert_eq!(host.status, AgentHostStatus::Rejected);
    assert_eq!(host.activated_at, Some(activated_at));
}

async fn assert_claim_callback(claims: &AutonomousClaimRecorder, host_id: &str) {
    let recorded = claims.0.lock().await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].agent.id, "autonomous");
    assert_eq!(recorded[0].agent.status, AgentStatus::Claimed);
    assert_eq!(recorded[0].host.id, host_id);
    assert_eq!(recorded[0].host.status, AgentHostStatus::Rejected);
    assert_eq!(recorded[0].capabilities, ["mail.read"]);
}

async fn assert_claim_event(events: &EventRecorder, user: &str, host_id: &str) {
    let emitted = events.wait_for(2).await;
    let expected = json!({
        "type": "agent.claimed",
        "actorId": user,
        "agentId": "autonomous",
        "hostId": host_id,
        "metadata": {"capabilities": ["mail.read"]}
    });
    assert!(
        emitted
            .iter()
            .any(|event| serde_json::to_value(event).unwrap() == expected)
    );
}
