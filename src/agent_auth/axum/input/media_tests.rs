use super::*;
use crate::agent_auth::axum::agent::model::RegisterBody;
use axum::{body::Body, extract::FromRequest, http::Request};
use serde_json::{Value, json};

async fn response_json(response: AgentInputError) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn extractor_matches_malformed_json_and_media_type_contracts() {
    let request = Request::builder()
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .unwrap();
    let response = AgentJson::<RegisterBody>::from_request(request, &())
        .await
        .unwrap_err();
    assert_eq!(
        response_json(response).await,
        json!({"message":"Invalid JSON in request body","code":"BAD_REQUEST"})
    );
    raw_json_rejects_malformed_body().await;
    unsupported_media_types_are_exact().await;
}

async fn raw_json_rejects_malformed_body() {
    let request = Request::builder()
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .unwrap();
    let response = AgentRawJson::from_request(request, &()).await.unwrap_err();
    assert_eq!(
        response_json(response).await,
        json!({"message":"Invalid JSON in request body","code":"BAD_REQUEST"})
    );
}

async fn unsupported_media_types_are_exact() {
    for content_type in [None, Some("text/plain;charset=UTF-8")] {
        let mut builder = Request::builder().method("POST");
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        let request = builder.body(Body::from("{\"name\":\"agent\"}")).unwrap();
        let response = AgentJson::<RegisterBody>::from_request(request, &())
            .await
            .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let expected = content_type.map_or_else(
            || "Content-Type is required. Allowed types: application/json".to_owned(),
            |value| {
                format!("Content-Type \"{value}\" is not allowed. Allowed types: application/json")
            },
        );
        assert_eq!(
            response_json(response).await,
            json!({"message":expected,"code":"UNSUPPORTED_MEDIA_TYPE"})
        );
    }
}
