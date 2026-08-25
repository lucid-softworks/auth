use super::*;
use crate::agent_auth::axum::{
    agent::model::{ListQuery, RegisterBody},
    approval::model::{ApproveCapabilityBody, GrantCapabilityBody},
    capability::batch::BatchBody,
    host::model::{CreateHostBody, UpdateHostBody},
};
use serde_json::{Value, json};

async fn message<T: AgentInput + std::fmt::Debug>(value: Value, scope: &str) -> String {
    let response = deserialize_validated::<T>(value, scope).unwrap_err();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice::<Value>(&body).unwrap()["message"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn size_number_and_url_checks_match_the_pinned_oracle() {
    assert_eq!(
        message::<RegisterBody>(json!({"name":""}), "body").await,
        "[body.name] Too small: expected string to have >=1 characters"
    );
    assert_eq!(
        message::<ListQuery>(json!({"limit":"0","offset":"-1"}), "query").await,
        "[query.limit] Too small: expected number to be >0; [query.offset] Too small: expected number to be >=0"
    );
    assert_eq!(
        message::<ApproveCapabilityBody>(json!({"action":"approve","ttl":0}), "body").await,
        "[body.ttl] Too small: expected number to be >0"
    );
    assert_eq!(
        message::<GrantCapabilityBody>(
            json!({"agent_id":"agent","capabilities":["files.read"],"ttl":0}),
            "body",
        )
        .await,
        "[body.ttl] Too small: expected number to be >0"
    );
    assert_eq!(
        message::<CreateHostBody>(json!({"jwks_url":"not-url"}), "body").await,
        "[body.jwks_url] Invalid URL"
    );
    assert_eq!(
        message::<UpdateHostBody>(json!({"host_id":"host","jwks_url":"not-url"}), "body").await,
        "[body.jwks_url] Invalid URL"
    );
    assert_eq!(
        message::<BatchBody>(json!({"requests":[]}), "body").await,
        "[body.requests] Too small: expected array to have >=1 items"
    );
    assert_eq!(
        message::<BatchBody>(
            json!({"requests":vec![json!({"capability":"x"}); 51]}),
            "body"
        )
        .await,
        "[body.requests] Too big: expected array to have <=50 items"
    );
}
