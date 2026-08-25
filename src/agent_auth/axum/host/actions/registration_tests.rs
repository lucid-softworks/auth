use super::*;
use crate::agent_auth::axum::host::events::test_support::EventRecorder;
use crate::{AgentAuthConfig, AgentCapability, MemoryAgentAuthStore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{collections::BTreeMap, sync::Arc};

fn state(config: AgentAuthConfig) -> AgentAuthState {
    let verifier = crate::agent_auth::axum::memory_verifier();
    AgentAuthState {
        config: Arc::new(config),
        store: Arc::new(MemoryAgentAuthStore::default()),
        organization_store: None,
        host_auth: crate::agent_auth::axum::host::HostAuthState::from_verifier(verifier.clone()),
        verifier,
    }
}

fn public_key(kid: &str) -> Value {
    json!({"kty":"OKP","crv":"Ed25519","x":"public-key","kid":kid})
}

fn endpoint(path: &str) -> AgentEndpointContext {
    AgentEndpointContext {
        method: "POST".into(),
        path: path.into(),
        base_url: "https://auth.example.test/api/auth".into(),
        headers: BTreeMap::new(),
    }
}

#[tokio::test]
async fn creates_and_consumes_hash_only_enrollment_tokens() {
    let recorder = EventRecorder::default();
    let config = AgentAuthConfig {
        on_event: Some(Arc::new(recorder.clone())),
        ..AgentAuthConfig::default()
    };
    let state = state(config);
    let user = Uuid::new_v4();
    let now = Utc::now();
    let created = create_for_user(
        &state,
        user,
        CreateHostBody {
            name: Some("Laptop".into()),
            public_key: None,
            jwks_url: None,
            default_capabilities: None,
        },
        endpoint("/host/create"),
        now,
    )
    .await
    .unwrap();
    assert_eq!(created["status"], "pending_enrollment");
    let token = created["enrollmentToken"].as_str().unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(token).unwrap().len(), 32);
    let host_id = created["hostId"].as_str().unwrap();
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.created",
            "actorId": user,
            "hostId": host_id,
            "metadata": {
                "defaultCapabilities": [],
                "status": "pending_enrollment"
            }
        })
    );
    let stored = state.store.find_host(host_id).await.unwrap().unwrap();
    assert_eq!(
        stored.enrollment_token_hash.as_deref(),
        Some(hash_token(token).as_str())
    );
    assert_ne!(stored.enrollment_token_hash.as_deref(), Some(token));

    let enrolled = enroll_with_token(
        &state,
        EnrollHostBody {
            token: token.into(),
            public_key: public_key("host-key"),
            name: None,
        },
        endpoint("/host/enroll"),
        now + ChronoDuration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(enrolled["hostId"], host_id);
    assert_eq!(enrolled["status"], "active");
    let stored = state.store.find_host(host_id).await.unwrap().unwrap();
    assert_eq!(stored.enrollment_token_hash, None);
    assert_eq!(stored.enrollment_token_expires_at, None);
    let events = recorder.wait_for(2).await;
    assert_eq!(
        serde_json::to_value(&events[1]).unwrap(),
        json!({
            "type": "host.enrolled",
            "actorType": "system",
            "hostId": host_id,
            "metadata": {"name": "Laptop"}
        })
    );
}

#[tokio::test]
async fn emits_the_exact_host_reactivated_event() {
    let recorder = EventRecorder::default();
    let config = AgentAuthConfig {
        on_event: Some(Arc::new(recorder.clone())),
        ..AgentAuthConfig::default()
    };
    let state = state(config);
    let user = Uuid::new_v4();
    let key = public_key("reactivated-key");
    let body = |name: &str| CreateHostBody {
        name: Some(name.into()),
        public_key: Some(key.clone()),
        jwks_url: None,
        default_capabilities: Some(vec!["mail.read".into()]),
    };
    create_for_user(
        &state,
        user,
        body("Original"),
        endpoint("/host/create"),
        Utc::now(),
    )
    .await
    .unwrap();
    recorder.wait_for(1).await;
    recorder.clear().await;

    let reactivated = create_for_user(
        &state,
        user,
        body("Reactivated"),
        endpoint("/host/create"),
        Utc::now(),
    )
    .await
    .unwrap();
    let events = recorder.wait_for(1).await;
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        json!({
            "type": "host.reactivated",
            "actorId": user,
            "hostId": reactivated["hostId"],
            "metadata": {"defaultCapabilities": ["mail.read"]}
        })
    );
}

#[tokio::test]
async fn rejects_blocked_unknown_and_wrong_algorithm_host_creation() {
    let config = AgentAuthConfig {
        blocked_capabilities: vec!["admin.*".into()],
        capabilities: vec![AgentCapability::new("mail.read", "Read mail")],
        ..AgentAuthConfig::default()
    };
    let state = state(config);
    let body = |capability: &str, key: Value| CreateHostBody {
        name: None,
        public_key: Some(key),
        jwks_url: None,
        default_capabilities: Some(vec![capability.into()]),
    };
    for (capability, kid, expected) in [
        ("admin.delete", "one", "capability_blocked"),
        ("unknown", "two", "invalid_capabilities"),
    ] {
        assert_eq!(
            create_for_user(
                &state,
                Uuid::new_v4(),
                body(capability, public_key(kid)),
                endpoint("/host/create"),
                Utc::now(),
            )
            .await
            .unwrap_err()
            .code,
            expected
        );
    }
    let ec = json!({"kty":"EC","crv":"P-256","x":"x","y":"y"});
    assert_eq!(
        create_for_user(
            &state,
            Uuid::new_v4(),
            body("mail.read", ec),
            endpoint("/host/create"),
            Utc::now(),
        )
        .await
        .unwrap_err()
        .code,
        "unsupported_algorithm"
    );
}
