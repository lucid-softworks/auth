use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    parse::js_string,
    transport::{AgentOpenApiHttpResponse, into_bytes, into_stream},
};
use crate::{AgentExecuteResult, AgentStreamResult};

pub(super) async fn response_result(
    response: AgentOpenApiHttpResponse,
) -> Result<AgentExecuteResult, String> {
    let status = response.status;
    let content_type = header(&response.headers, "content-type").map(str::to_owned);
    if !(200..300).contains(&status) {
        let body = into_bytes(response.body).await?;
        return Err(format!(
            "Upstream API error {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    if status == 202 {
        let body = into_bytes(response.body).await?;
        let body: Value = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        let status_url = body
            .get("status_url")
            .filter(|value| !value.is_null())
            .map(js_string)
            .or_else(|| header(&response.headers, "location").map(str::to_owned))
            .unwrap_or_default();
        let retry_after = header(&response.headers, "retry-after").and_then(parse_integer_prefix);
        return Ok(AgentExecuteResult::Async {
            status_url,
            retry_after,
        });
    }
    if content_type
        .as_deref()
        .is_some_and(|value| value.contains("text/event-stream"))
    {
        return Ok(AgentExecuteResult::Stream(AgentStreamResult {
            body: into_stream(response.body),
            headers: BTreeMap::new(),
        }));
    }
    let body = into_bytes(response.body).await?;
    if content_type
        .as_deref()
        .is_some_and(|value| value.contains("application/json"))
    {
        return serde_json::from_slice(&body)
            .map(AgentExecuteResult::Data)
            .map_err(|error| error.to_string());
    }
    Ok(AgentExecuteResult::Data(Value::String(
        String::from_utf8_lossy(&body).into_owned(),
    )))
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_integer_prefix(value: &str) -> Option<u64> {
    let digits = value
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentExecuteResult;
    use serde_json::json;

    use crate::agent_auth::openapi::transport::AgentOpenApiResponseBody;

    #[tokio::test]
    async fn maps_json_text_async_and_sse_results() {
        let json_result = response_result(response(
            200,
            [("Content-Type", "application/json")],
            AgentOpenApiResponseBody::Bytes(br#"{"ok":true}"#.to_vec()),
        ))
        .await
        .unwrap();
        assert!(
            matches!(json_result, AgentExecuteResult::Data(value) if value == json!({"ok":true}))
        );

        let text_result = response_result(response(
            200,
            [("content-type", "text/plain")],
            AgentOpenApiResponseBody::Bytes(b"plain response".to_vec()),
        ))
        .await
        .unwrap();
        assert!(
            matches!(text_result, AgentExecuteResult::Data(Value::String(value)) if value == "plain response")
        );

        let async_result = response_result(response(
            202,
            [
                ("Location", "https://upstream.example/jobs/1"),
                ("Retry-After", "7 seconds"),
            ],
            AgentOpenApiResponseBody::Bytes(b"{}".to_vec()),
        ))
        .await
        .unwrap();
        assert!(
            matches!(async_result, AgentExecuteResult::Async { status_url, retry_after: Some(7) } if status_url == "https://upstream.example/jobs/1")
        );

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender.send(Ok(b"data: ready\n\n".to_vec())).await.unwrap();
        drop(sender);
        let stream_result = response_result(response(
            200,
            [("content-type", "text/event-stream; charset=utf-8")],
            AgentOpenApiResponseBody::Stream(receiver),
        ))
        .await
        .unwrap();
        let AgentExecuteResult::Stream(mut stream) = stream_result else {
            panic!("expected stream result");
        };
        assert_eq!(
            stream.body.recv().await.unwrap().unwrap(),
            b"data: ready\n\n"
        );
    }

    fn response(
        status: u16,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
        body: AgentOpenApiResponseBody,
    ) -> AgentOpenApiHttpResponse {
        AgentOpenApiHttpResponse {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            body,
        }
    }
}
