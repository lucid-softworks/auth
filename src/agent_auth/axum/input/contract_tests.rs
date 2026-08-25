use super::*;
use crate::agent_auth::axum::{
    agent::model::{
        ClaimBody, GetQuery, ListQuery as AgentListQuery, ReactivateBody, RegisterBody, RevokeBody,
        RotateKeyBody, StatusQuery, UpdateBody,
    },
    approval::model::{
        ApproveCapabilityBody, CibaAuthorizeBody, DeviceCodeBody, GrantCapabilityBody,
        RequestCapabilityBody, RevokeCapabilityBody,
    },
    auth::introspect::IntrospectionRequest,
    capability::{
        batch::BatchBody,
        catalog::{DescribeQuery, ListQuery as CapabilityListQuery},
        execute::ExecuteBody,
    },
    host::model::{
        CreateHostBody, EnrollHostBody, GetHostQuery, ListHostsQuery, RevokeHostBody,
        RotateHostKeyBody, SwitchHostAccountBody, UpdateHostBody,
    },
};
use serde_json::{Value, json};
use std::fmt::Debug;

fn wrong_type(scope: &str, field: &str, expected: &str, received: &str) -> String {
    format!("[{scope}.{field}] Invalid input: expected {expected}, received {received}")
}

fn wrong_enum(scope: &str, field: &str, options: &str) -> String {
    format!("[{scope}.{field}] Invalid option: expected one of {options}")
}

async fn response_json(response: Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn expect_message(response: AgentInputError, message: String) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response.into_response()).await,
        json!({"message": message, "code": "VALIDATION_ERROR"})
    );
}

async fn check_body<T>(baseline: &Value, field: &str, wrong: Value, message: String)
where
    T: AgentInput + Debug,
{
    let mut value = baseline.clone();
    value.as_object_mut().unwrap().insert(field.into(), wrong);
    let response = deserialize_validated::<T>(value, "body").unwrap_err();
    expect_message(response, message).await;
}

async fn check_query<T>(baseline: &Value, field: &str, wrong: Value, message: String)
where
    T: AgentInput + Debug,
{
    let mut value = baseline.clone();
    value.as_object_mut().unwrap().insert(field.into(), wrong);
    let response = deserialize_validated::<T>(value, "query").unwrap_err();
    expect_message(response, message).await;
}

async fn check_required_body<T>()
where
    T: AgentInput + Debug,
{
    let response = parse_json::<T>(&Bytes::new()).unwrap_err();
    expect_message(
        response,
        "[body] Invalid input: expected object, received undefined".into(),
    )
    .await;
}

macro_rules! body_schema {
    ($type:ty, $baseline:expr, $($field:literal => ($wrong:expr, $expected:expr, $received:expr)),+ $(,)?) => {{
        check_required_body::<$type>().await;
        let baseline = $baseline;
        $(check_body::<$type>(
            &baseline,
            $field,
            $wrong,
            wrong_type("body", $field, $expected, $received),
        ).await;)+
    }};
}

macro_rules! query_schema {
    ($type:ty, $baseline:expr, $($field:literal => ($wrong:expr, $expected:expr, $received:expr)),+ $(,)?) => {{
        let baseline = $baseline;
        $(check_query::<$type>(
            &baseline,
            $field,
            $wrong,
            wrong_type("query", $field, $expected, $received),
        ).await;)+
    }};
}

#[tokio::test]
async fn agent_and_approval_body_schemas_match_the_pinned_oracle() {
    body_schema!(RegisterBody, json!({"name":"agent"}),
        "name" => (json!(7), "string", "number"),
        "capabilities" => (json!("wrong"), "array", "string"),
        "reason" => (json!(7), "string", "number"),
        "preferred_method" => (json!(7), "string", "number"),
        "host_name" => (json!(7), "string", "number"),
        "login_hint" => (json!(7), "string", "number"),
        "binding_message" => (json!(7), "string", "number"),
        "force_approval" => (json!(7), "boolean", "number"),
    );
    check_body::<RegisterBody>(
        &json!({"name":"agent"}),
        "mode",
        json!("not-an-option"),
        wrong_enum("body", "mode", "\"delegated\"|\"autonomous\""),
    )
    .await;
}

#[tokio::test]
async fn agent_management_body_schemas_match_the_pinned_oracle() {
    body_schema!(UpdateBody, json!({"agent_id":"agent"}),
        "agent_id" => (json!(7), "string", "number"),
        "name" => (json!(7), "string", "number"),
        "metadata" => (json!("wrong"), "record", "string"),
    );
    body_schema!(RevokeBody, json!({}), "agent_id" => (json!(7), "string", "number"));
    body_schema!(RotateKeyBody, json!({"agent_id":"agent","public_key":{}}),
        "agent_id" => (json!(7), "string", "number"),
        "public_key" => (json!("wrong"), "record", "string"),
    );
    body_schema!(ReactivateBody, json!({"agent_id":"agent"}),
        "agent_id" => (json!(7), "string", "number"),
    );
    body_schema!(RequestCapabilityBody, json!({"capabilities":["files.read"]}),
        "capabilities" => (json!("wrong"), "array", "string"),
        "reason" => (json!(7), "string", "number"),
        "preferred_method" => (json!(7), "string", "number"),
        "login_hint" => (json!(7), "string", "number"),
        "binding_message" => (json!(7), "string", "number"),
    );
    body_schema!(RevokeCapabilityBody, json!({"agent_id":"agent","capabilities":["files.read"]}),
        "agent_id" => (json!(7), "string", "number"),
        "capabilities" => (json!("wrong"), "array", "string"),
    );
    body_schema!(ApproveCapabilityBody, json!({"action":"approve"}),
        "agent_id" => (json!(7), "string", "number"),
        "approval_id" => (json!(7), "string", "number"),
        "user_code" => (json!(7), "string", "number"),
        "capabilities" => (json!("wrong"), "array", "string"),
        "ttl" => (json!("not-a-number"), "number", "string"),
        "reason" => (json!(7), "string", "number"),
        "webauthn_response" => (json!("wrong"), "record", "string"),
    );
    check_body::<ApproveCapabilityBody>(
        &json!({"action":"approve"}),
        "action",
        json!("not-an-option"),
        wrong_enum("body", "action", "\"approve\"|\"deny\""),
    )
    .await;
}

#[tokio::test]
async fn capability_host_and_flow_body_schemas_match_the_pinned_oracle() {
    body_schema!(ExecuteBody, json!({"capability":"files.read"}),
        "capability" => (json!(7), "string", "number"),
        "arguments" => (json!("wrong"), "record", "string"),
    );
    body_schema!(BatchBody, json!({"requests":[{"capability":"files.read"}]}),
        "requests" => (json!("wrong"), "array", "string"),
    );
    body_schema!(IntrospectionRequest, json!({"token":"token"}),
        "token" => (json!(7), "string", "number"),
    );
    body_schema!(GrantCapabilityBody, json!({"agent_id":"agent","capabilities":["files.read"]}),
        "agent_id" => (json!(7), "string", "number"),
        "capabilities" => (json!("wrong"), "array", "string"),
        "ttl" => (json!("not-a-number"), "number", "string"),
    );
    body_schema!(CreateHostBody, json!({}),
        "name" => (json!(7), "string", "number"),
        "public_key" => (json!("wrong"), "record", "string"),
        "jwks_url" => (json!(7), "string", "number"),
        "default_capabilities" => (json!("wrong"), "array", "string"),
    );
    body_schema!(EnrollHostBody, json!({"token":"token","public_key":{}}),
        "token" => (json!(7), "string", "number"),
        "public_key" => (json!("wrong"), "record", "string"),
        "name" => (json!(7), "string", "number"),
    );
    assert!(parse_json::<RevokeHostBody>(&Bytes::new()).is_ok());
    check_body::<RevokeHostBody>(
        &json!({}),
        "host_id",
        json!(7),
        wrong_type("body", "host_id", "string", "number"),
    )
    .await;
    body_schema!(SwitchHostAccountBody, json!({"host_id":"host"}),
        "host_id" => (json!(7), "string", "number"),
    );
    body_schema!(UpdateHostBody, json!({"host_id":"host"}),
        "host_id" => (json!(7), "string", "number"),
        "name" => (json!(7), "string", "number"),
        "public_key" => (json!("wrong"), "record", "string"),
        "jwks_url" => (json!(7), "string", "number"),
        "default_capabilities" => (json!("wrong"), "array", "string"),
    );
    body_schema!(RotateHostKeyBody, json!({"public_key":{}}),
        "public_key" => (json!("wrong"), "record", "string"),
    );
    body_schema!(CibaAuthorizeBody, json!({"login_hint":"agent@example.test"}),
        "login_hint" => (json!(7), "string", "number"),
        "capabilities" => (json!("wrong"), "array", "string"),
        "binding_message" => (json!(7), "string", "number"),
        "agent_id" => (json!(7), "string", "number"),
    );
    body_schema!(DeviceCodeBody, json!({"agent_id":"agent"}),
        "agent_id" => (json!(7), "string", "number"),
    );
    body_schema!(ClaimBody, json!({"agent_id":"agent"}),
        "agent_id" => (json!(7), "string", "number"),
        "preferred_method" => (json!(7), "string", "number"),
        "login_hint" => (json!(7), "string", "number"),
        "binding_message" => (json!(7), "string", "number"),
    );
}

#[tokio::test]
async fn nested_arrays_and_records_match_the_pinned_validation_oracle() {
    for invalid in [
        json!(7),
        json!({}),
        json!({"name":7}),
        json!({"name":"files.read","constraints":"wrong"}),
    ] {
        check_body::<RegisterBody>(
            &json!({"name":"agent"}),
            "capabilities",
            json!([invalid]),
            "[body.capabilities.0] Invalid input".into(),
        )
        .await;
    }
    for (requests, message) in [
        (
            json!([7]),
            "[body.requests.0] Invalid input: expected object, received number",
        ),
        (
            json!([{}]),
            "[body.requests.0.capability] Invalid input: expected string, received undefined",
        ),
        (
            json!([{"capability":7}]),
            "[body.requests.0.capability] Invalid input: expected string, received number",
        ),
        (
            json!([{"capability":"x","id":7}]),
            "[body.requests.0.id] Invalid input: expected string, received number",
        ),
        (
            json!([{"capability":"x","arguments":"wrong"}]),
            "[body.requests.0.arguments] Invalid input: expected record, received string",
        ),
    ] {
        check_body::<BatchBody>(
            &json!({"requests":[{"capability":"files.read"}]}),
            "requests",
            requests,
            message.into(),
        )
        .await;
    }
    check_body::<RevokeCapabilityBody>(
        &json!({"agent_id":"agent","capabilities":["files.read"]}),
        "capabilities",
        json!([7]),
        "[body.capabilities.0] Invalid input: expected string, received number".into(),
    )
    .await;
    check_body::<CreateHostBody>(
        &json!({}),
        "public_key",
        json!({"kty":{}}),
        "[body.public_key.kty] Invalid input".into(),
    )
    .await;
    for invalid in [json!([]), json!({})] {
        check_body::<UpdateBody>(
            &json!({"agent_id":"agent"}),
            "metadata",
            json!({"bad":invalid}),
            "[body.metadata.bad] Invalid input".into(),
        )
        .await;
    }
}

#[tokio::test]
async fn every_query_schema_matches_the_pinned_validation_oracle() {
    query_schema!(AgentListQuery, json!({}),
        "host_id" => (json!(7), "string", "number"),
        "limit" => (json!("not-a-number"), "number", "NaN"),
        "offset" => (json!("not-a-number"), "number", "NaN"),
    );
    check_query::<AgentListQuery>(
        &json!({}),
        "status",
        json!("not-an-option"),
        wrong_enum(
            "query",
            "status",
            "\"active\"|\"pending\"|\"expired\"|\"revoked\"|\"rejected\"|\"claimed\"",
        ),
    )
    .await;
    check_query::<AgentListQuery>(
        &json!({}),
        "mode",
        json!("not-an-option"),
        wrong_enum("query", "mode", "\"delegated\"|\"autonomous\""),
    )
    .await;
    query_schema!(GetQuery, json!({"agent_id":"value"}),
        "agent_id" => (json!(7), "string", "number"),
    );
    let missing = deserialize_validated::<GetQuery>(json!({}), "query").unwrap_err();
    expect_message(
        missing,
        wrong_type("query", "agent_id", "string", "undefined"),
    )
    .await;
    query_schema!(CapabilityListQuery, json!({}),
        "query" => (json!(7), "string", "number"),
        "cursor" => (json!(7), "string", "number"),
        "limit" => (json!("not-a-number"), "number", "NaN"),
    );
    query_schema!(DescribeQuery, json!({"name":"value"}),
        "name" => (json!(7), "string", "number"),
    );
    let missing = deserialize_validated::<DescribeQuery>(json!({}), "query").unwrap_err();
    expect_message(missing, wrong_type("query", "name", "string", "undefined")).await;
    query_schema!(StatusQuery, json!({}), "agent_id" => (json!(7), "string", "number"));
    check_query::<ListHostsQuery>(
        &json!({}),
        "status",
        json!("not-an-option"),
        wrong_enum(
            "query",
            "status",
            "\"active\"|\"pending\"|\"pending_enrollment\"|\"revoked\"|\"rejected\"",
        ),
    )
    .await;
    query_schema!(GetHostQuery, json!({"host_id":"value"}),
        "host_id" => (json!(7), "string", "number"),
    );
    let missing = deserialize_validated::<GetHostQuery>(json!({}), "query").unwrap_err();
    expect_message(
        missing,
        wrong_type("query", "host_id", "string", "undefined"),
    )
    .await;
}
