use crate::{
    AuditEvent, AuthError, AuthService, AxumPluginRoute,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) fn routes(_service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new(
        "/access/audit",
        get(list_audit_events),
    )]
}

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AuditEventsResponse {
    events: Vec<AuditEvent>,
}

async fn list_audit_events(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .list_audit_events(&actor, query.limit.unwrap_or(100))
        .await
    {
        Ok(events) => Json(AuditEventsResponse { events }).into_response(),
        Err(error) => auth_error(error),
    }
}
