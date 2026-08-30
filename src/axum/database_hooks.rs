use crate::{
    DatabaseHookRequest,
    database_hooks::{DeferredHookQueue, scope_request},
};
use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::BTreeMap;

pub(super) async fn request_context(request: Request, next: Next) -> Response {
    let body = request
        .extensions()
        .get::<crate::plugin::CapturedPluginRequestBody>()
        .map(|body| body.0.clone());
    let context = DatabaseHookRequest {
        method: request.method().to_string(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().map(str::to_owned),
        headers: request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
    };
    let queue = DeferredHookQueue::default();
    let response = scope_request(context, body, queue.clone(), next.run(request)).await;
    apply_deferred_hooks(response, queue).await
}

async fn apply_deferred_hooks(mut response: Response, queue: DeferredHookQueue) -> Response {
    while let Some(future) = queue.pop() {
        let deferred = match future.await {
            Ok(deferred) => deferred,
            Err(_) => return super::api_error_empty(StatusCode::INTERNAL_SERVER_ERROR),
        };
        for (name, value) in deferred.into_headers() {
            let Ok(name) = HeaderName::try_from(name) else {
                return super::api_error_empty(StatusCode::INTERNAL_SERVER_ERROR);
            };
            let Ok(value) = HeaderValue::try_from(value) else {
                return super::api_error_empty(StatusCode::INTERNAL_SERVER_ERROR);
            };
            response.headers_mut().append(name, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthError, DeferredHookResponse, database_hooks::current_context};
    use axum::{
        body::{Body, to_bytes},
        http::header,
    };

    fn context() -> DatabaseHookRequest {
        DatabaseHookRequest {
            method: "POST".into(),
            path: "/deferred".into(),
            query: None,
            headers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn successful_work_appends_headers_after_the_handler() {
        let queue = DeferredHookQueue::default();
        let response = scope_request(context(), None, queue.clone(), async {
            assert!(
                current_context()
                    .try_defer_after_commit(async {
                        Ok(DeferredHookResponse::default()
                            .with_header("set-cookie", "dub_id=; Max-Age=0")
                            .with_header("x-deferred-order", "first"))
                    })
                    .is_ok()
            );
            assert!(
                current_context()
                    .try_defer_after_commit(async {
                        Ok(DeferredHookResponse::default()
                            .with_header("x-deferred-order", "second"))
                    })
                    .is_ok()
            );
            Response::builder()
                .header(header::SET_COOKIE, "better-auth.session_token=signed")
                .body(Body::from("ready"))
                .unwrap()
        })
        .await;

        let response = apply_deferred_hooks(response, queue).await;
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            cookies,
            ["better-auth.session_token=signed", "dub_id=; Max-Age=0"]
        );
        let order = response
            .headers()
            .get_all("x-deferred-order")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(order, ["first", "second"]);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            "ready"
        );
    }

    #[tokio::test]
    async fn rejected_work_discards_the_handler_response() {
        let queue = DeferredHookQueue::default();
        let response = scope_request(context(), None, queue.clone(), async {
            assert!(
                current_context()
                    .try_defer_after_commit(async {
                        Ok(DeferredHookResponse::default()
                            .with_header("x-deferred-before-error", "discard"))
                    })
                    .is_ok()
            );
            assert!(
                current_context()
                    .try_defer_after_commit(async {
                        Err(AuthError::Storage("deferred hook failed".into()))
                    })
                    .is_ok()
            );
            Response::builder()
                .header(header::SET_COOKIE, "better-auth.session_token=signed")
                .body(Body::from("must be discarded"))
                .unwrap()
        })
        .await;

        let response = apply_deferred_hooks(response, queue).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert!(!response.headers().contains_key("x-deferred-before-error"));
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert!(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
