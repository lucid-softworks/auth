use super::*;
use crate::agent_auth::axum::host::events::test_support::EventRecorder;
use crate::{AgentAuthConfig, AgentEndpointContext, MemoryAgentAuthStore};
use std::{collections::BTreeMap, sync::Arc};

fn public_key(kid: &str) -> Value {
    json!({"kty":"OKP","crv":"Ed25519","x":"public-key","kid":kid})
}

fn endpoint() -> AgentEndpointContext {
    AgentEndpointContext {
        method: "POST".into(),
        path: "/host/create".into(),
        base_url: "https://auth.example.test/api/auth".into(),
        headers: BTreeMap::new(),
    }
}

async fn active_host(kid: &str) -> (AgentAuthState, EventRecorder, Uuid, DateTime<Utc>, String) {
    let recorder = EventRecorder::default();
    let verifier = crate::agent_auth::axum::memory_verifier();
    let config = AgentAuthConfig {
        on_event: Some(Arc::new(recorder.clone())),
        ..AgentAuthConfig::default()
    };
    let state = AgentAuthState {
        config: Arc::new(config),
        store: Arc::new(MemoryAgentAuthStore::default()),
        organization_store: None,
        host_auth: crate::agent_auth::axum::host::HostAuthState::from_verifier(verifier.clone()),
        verifier,
    };
    let user = Uuid::new_v4();
    let now = Utc::now();
    let created = super::super::registration::create_for_user(
        &state,
        user,
        crate::agent_auth::axum::host::model::CreateHostBody {
            name: None,
            public_key: Some(public_key(kid)),
            jwks_url: None,
            default_capabilities: Some(vec![]),
        },
        endpoint(),
        now,
    )
    .await
    .unwrap();
    let host_id = created["hostId"].as_str().unwrap().to_owned();
    recorder.wait_for(1).await;
    recorder.clear().await;
    (state, recorder, user, now, host_id)
}

#[tokio::test]
async fn lists_gets_and_updates_with_exact_wire_casing() {
    let (state, recorder, user, now, host_id) = active_host("host-key").await;
    let listed = list_for_user(&state, user, Some(AgentHostStatus::Active))
        .await
        .unwrap();
    assert_eq!(
        listed["hosts"][0]["name"],
        format!("Device {}", prefix(&host_id))
    );
    let got = get_for_user(&state, user, &host_id).await.unwrap();
    assert!(got.get("default_capabilities").is_some());
    assert!(got.get("defaultCapabilities").is_none());
    let updated = update_for_user(
        &state,
        user,
        UpdateHostBody {
            host_id: host_id.clone(),
            name: Some("Renamed".into()),
            public_key: None,
            jwks_url: None,
            default_capabilities: Some(vec!["mail.read".into()]),
        },
        now,
    )
    .await
    .unwrap();
    assert_eq!(updated["id"], host_id);
    assert_eq!(updated["jwks_url"], Value::Null);
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.updated",
            "actorId": user,
            "hostId": host_id,
            "metadata": {"name": "Renamed", "defaultCapabilities": ["mail.read"]}
        })
    );
}

#[tokio::test]
async fn revokes_once_and_emits_the_exact_event() {
    let (state, recorder, user, now, host_id) = active_host("revoke-key").await;
    let revoked = revoke_authorized(
        &state,
        HostAuthorization::User(user),
        Some(host_id.clone()),
        now,
    )
    .await
    .unwrap();
    assert_eq!(revoked["host_id"], host_id);
    assert_eq!(revoked["agents_revoked"], 0);
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.revoked",
            "actorId": user,
            "hostId": host_id,
            "metadata": {"agentsRevoked": 0}
        })
    );
    let repeated = revoke_authorized(&state, HostAuthorization::User(user), Some(host_id), now)
        .await
        .unwrap();
    assert_eq!(repeated["agents_revoked"], 0);
    tokio::task::yield_now().await;
    assert_eq!(recorder.wait_for(1).await.len(), 1);
}

#[tokio::test]
async fn emits_exact_host_key_rotated_and_claimed_events() {
    let recorder = EventRecorder::default();
    let verifier = crate::agent_auth::axum::memory_verifier();
    let config = AgentAuthConfig {
        on_event: Some(Arc::new(recorder.clone())),
        ..AgentAuthConfig::default()
    };
    let state = AgentAuthState {
        config: Arc::new(config),
        store: Arc::new(MemoryAgentAuthStore::default()),
        organization_store: None,
        host_auth: crate::agent_auth::axum::host::HostAuthState::from_verifier(verifier.clone()),
        verifier,
    };
    let user = Uuid::new_v4();
    let created = super::super::registration::create_for_user(
        &state,
        user,
        crate::agent_auth::axum::host::model::CreateHostBody {
            name: Some("Laptop".into()),
            public_key: Some(public_key("old-key")),
            jwks_url: None,
            default_capabilities: Some(vec![]),
        },
        endpoint(),
        Utc::now(),
    )
    .await
    .unwrap();
    let old_id = created["hostId"].as_str().unwrap().to_owned();
    recorder.wait_for(1).await;
    recorder.clear().await;

    let old_host = state.store.find_host(&old_id).await.unwrap().unwrap();
    let rotated = rotate_authorized(&state, old_host, public_key("new-key"), Utc::now())
        .await
        .unwrap();
    let new_id = rotated["host_id"].as_str().unwrap().to_owned();
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.key_rotated",
            "actorType": "system",
            "hostId": new_id,
            "metadata": {"previousHostId": old_id}
        })
    );
    recorder.clear().await;

    switch_to_user(&state, user, &new_id, endpoint(), Utc::now())
        .await
        .unwrap();
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.claimed",
            "actorId": user,
            "hostId": new_id,
            "metadata": {
                "previousUserId": user,
                "newUserId": user,
                "agentsRevoked": 0
            }
        })
    );
}
