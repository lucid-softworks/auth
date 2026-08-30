use super::{route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPlugin, SessionWithUser};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::sync::Arc;

mod support;
use support::*;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route("/events/list", get(list).layer(Extension(plugin.clone()))),
        route(
            "/events/audit-logs",
            get(audit_logs).layer(Extension(plugin.clone())),
        ),
        route(
            "/events/all-audit-logs",
            get(all_audit_logs).layer(Extension(plugin.clone())),
        ),
        route("/events/types", get(types).layer(Extension(plugin))),
    ]
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "You must be signed in to view your events",
        );
    };
    if !configured(&plugin) {
        return events_not_configured();
    }
    let paging = Paging::new(query.limit, query.offset);
    let response = fetch(
        &plugin,
        "/events/user",
        &[
            ("userId", session.user.id.as_str()),
            ("limit", paging.limit.as_str()),
            ("offset", paging.offset.as_str()),
        ],
    )
    .await;
    let Some(page) = page_or_log(response, "events") else {
        return remote_error("Failed to fetch events");
    };
    Json(page.response(truthy(query.event_type.as_deref()), None, false)).into_response()
}

async fn types(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    if crate::axum::http::current_session(&service, &headers)
        .await
        .is_none()
    {
        return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    }
    if !configured(&plugin) {
        return events_not_configured();
    }
    Json(json!({
        "user": crate::user_event_types(),
        "organization": crate::organization_event_types(),
        "all": crate::all_event_types(),
    }))
    .into_response()
}

async fn audit_logs(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "You must be signed in to view audit logs",
        );
    };
    if !configured(&plugin) {
        return events_not_configured();
    }
    let resolved_user_id = match resolved_audit_user(&query, &session) {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let paging = Paging::new(query.limit, query.offset);
    let (page, organization_scope) = match audit_page(
        &service,
        &plugin,
        &session,
        &query,
        resolved_user_id,
        &paging,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return response,
    };
    let event_type = truthy(query.event_type.as_deref());
    let filter = organization_scope.then_some(OrganizationFilter {
        user_id: resolved_user_id,
        identifier: truthy(query.identifier.as_deref()),
    });
    Json(page.response(
        event_type,
        filter,
        organization_scope || event_type.is_some(),
    ))
    .into_response()
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route handler"
)]
fn resolved_audit_user<'a>(
    query: &'a EventQuery,
    session: &'a SessionWithUser,
) -> Result<&'a str, Response> {
    if query
        .user_id
        .as_deref()
        .filter(|user_id| !user_id.is_empty())
        .is_some_and(|user_id| user_id != session.user.id)
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Not allowed to access another user's audit logs",
        ));
    }
    Ok(truthy(query.user_id.as_deref()).unwrap_or(&session.user.id))
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route handler"
)]
async fn audit_page(
    service: &AuthService,
    plugin: &DashPlugin,
    session: &SessionWithUser,
    query: &EventQuery,
    user_id: &str,
    paging: &Paging,
) -> Result<(RemotePage, bool), Response> {
    let organization_id = truthy(query.organization_id.as_deref());
    let response = if let Some(organization_id) = organization_id {
        match service
            .dash_event_organization_access(&session.user.id, organization_id)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(error(
                    StatusCode::FORBIDDEN,
                    "FORBIDDEN",
                    "Not allowed to access this organization",
                ));
            }
            Err(error) => return Err(route_error(error)),
        }
        fetch(
            plugin,
            "/events/organization",
            &[
                ("organizationId", organization_id),
                ("limit", paging.limit.as_str()),
                ("offset", paging.offset.as_str()),
            ],
        )
        .await
    } else {
        fetch(
            plugin,
            "/events/user",
            &[
                ("userId", user_id),
                ("limit", paging.limit.as_str()),
                ("offset", paging.offset.as_str()),
            ],
        )
        .await
    };
    let failure = if organization_id.is_some() {
        "Failed to fetch organization audit logs"
    } else {
        "Failed to fetch user audit logs"
    };
    page_or_log(response, "audit logs")
        .map(|page| (page, organization_id.is_some()))
        .ok_or_else(|| remote_error(failure))
}

async fn all_audit_logs(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "You must be signed in to view activity logs",
        );
    };
    if !configured(&plugin) {
        return events_not_configured();
    }
    let paging = Paging::new(query.limit, query.offset);
    let owned_query = match activity_query(&service, &session, &query, paging).await {
        Ok(query) => query,
        Err(response) => return response,
    };
    let borrowed = owned_query
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();
    let response = fetch(&plugin, "/events/activity", &borrowed).await;
    let Some(page) = page_or_log(response, "activity logs") else {
        return remote_error("Failed to fetch activity logs");
    };
    Json(page.response(None, None, false)).into_response()
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route handler"
)]
async fn activity_query(
    service: &AuthService,
    session: &SessionWithUser,
    query: &EventQuery,
    paging: Paging,
) -> Result<Vec<(&'static str, String)>, Response> {
    let organization_id = trimmed(query.organization_id.as_deref());
    let user_id = trimmed(query.user_id.as_deref());
    if organization_id.is_some() && user_id.is_some() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Provide at most one of userId and organizationId.",
        ));
    }
    let elevated_ids = service
        .dash_elevated_organization_ids(&session.user.id)
        .await
        .map_err(route_error)?;
    authorize_activity_scope(service, session, organization_id, &elevated_ids).await?;

    let mut output = vec![("limit", paging.limit), ("offset", paging.offset)];
    if let Some(organization_id) = organization_id {
        output.push(("organizationIds", organization_id.to_owned()));
    } else {
        if let Some(user_id) = user_id {
            output.push(("userId", user_id.to_owned()));
        }
        output.push(("organizationIds", elevated_ids.join(",")));
    }
    if let Some(event_type) = trimmed(query.event_type.as_deref()) {
        output.push(("eventType", event_type.to_owned()));
    }
    if let Some(identifier) = trimmed(query.identifier.as_deref()) {
        output.push(("identifier", identifier.to_owned()));
    }
    Ok(output)
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route handler"
)]
async fn authorize_activity_scope(
    service: &AuthService,
    session: &SessionWithUser,
    organization_id: Option<&str>,
    elevated_ids: &[String],
) -> Result<(), Response> {
    if let Some(organization_id) = organization_id {
        match service
            .dash_elevated_organization_access(&session.user.id, organization_id)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(elevated_forbidden()),
            Err(error) => Err(route_error(error)),
        }
    } else if elevated_ids.is_empty() {
        Err(elevated_forbidden())
    } else {
        Ok(())
    }
}
