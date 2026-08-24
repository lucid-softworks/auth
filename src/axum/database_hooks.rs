use crate::{DatabaseHookRequest, database_hooks::scope_request};
use axum::{extract::Request, middleware::Next, response::Response};
use std::collections::BTreeMap;

pub(super) async fn request_context(request: Request, next: Next) -> Response {
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
    scope_request(context, next.run(request)).await
}
