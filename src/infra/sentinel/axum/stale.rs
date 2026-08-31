use super::http;
use crate::infra::{
    dash::DashPlugin,
    sentinel::{SecurityAction, SentinelPlugin},
};
use axum::{http::StatusCode, response::Response};

#[derive(Clone, Copy, Debug)]
pub(super) struct StaleAccountBlocked;

pub(super) async fn process(
    service: &crate::AuthService,
    plugin: &SentinelPlugin,
    request: &crate::PluginRequestContext,
    identification: &crate::infra::dash::IdentificationContext,
    response: Response,
) -> Response {
    let Some(options) = plugin
        .options()
        .security
        .stale_users
        .as_ref()
        .filter(|options| options.enabled)
    else {
        return response;
    };
    if response.status().is_client_error() || response.status().is_server_error() {
        return response;
    }
    let Some(session) = response
        .extensions()
        .get::<crate::axum::http::BoundSession>()
        .map(|session| session.0.clone())
    else {
        return response;
    };
    let tracks_activity = service
        .plugins()
        .find::<DashPlugin>()
        .is_some_and(|dash| dash.options().activity_tracking.enabled);
    let last_active_at = tracks_activity
        .then(|| session.user.additional_fields.get("lastActiveAt"))
        .flatten()
        .and_then(|value| value.as_str());
    let stale = plugin
        .security_client()
        .check_stale_user(&session.user.id, last_active_at)
        .await;
    if !stale.is_stale {
        return response;
    }
    notify(plugin, options, &session.user, &stale, identification).await;
    if stale.action != Some(SecurityAction::Block) {
        return response;
    }
    if let Err(error) = service.sign_out(&session.session.token).await {
        tracing::warn!(error = %error, "[Sentinel] Failed to delete stale-blocked session");
    }
    let mut blocked = http::error(
        StatusCode::FORBIDDEN,
        "STALE_ACCOUNT",
        "This account has been inactive for an extended period. Please contact support to reactivate.",
    );
    blocked.extensions_mut().insert(StaleAccountBlocked);
    let headers = request_headers(request);
    crate::axum::http::clear_session_cookie_from_request(service, &headers, blocked)
}

async fn notify(
    plugin: &SentinelPlugin,
    options: &crate::infra::sentinel::StaleUsersOptions,
    user: &crate::AuthUser,
    stale: &crate::infra::sentinel::StaleUserResult,
    identification: &crate::infra::dash::IdentificationContext,
) {
    let days = stale.days_since_last_active.unwrap_or(0);
    if stale.notify_user == Some(true) {
        plugin
            .security_client()
            .notify_stale_account_user(
                &user.email,
                (!user.name.is_empty()).then_some(user.name.as_str()),
                days,
                identification,
            )
            .await;
    }
    if stale.notify_admin == Some(true)
        && let Some(admin_email) = options.admin_email.as_deref()
    {
        plugin
            .security_client()
            .notify_stale_account_admin(
                admin_email,
                &user.id,
                &user.email,
                (!user.name.is_empty()).then_some(user.name.as_str()),
                days,
                identification,
            )
            .await;
    }
}

fn request_headers(request: &crate::PluginRequestContext) -> axum::http::HeaderMap {
    request
        .headers
        .iter()
        .filter_map(|(name, value)| Some((name.parse().ok()?, value.parse().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthSession, AuthUser, MemoryStore, PluginRequestContext, SessionWithUser,
        infra::{
            dash::InfraConnectionOptions,
            sentinel::{SecurityOptions, SentinelOptions, StaleUsersOptions},
        },
    };
    use axum::{Json, Router, body::Body, routing::post};
    use chrono::{Duration, Utc};
    use serde_json::{Map, json};
    use std::sync::Arc;

    async fn blocking_plugin() -> SentinelPlugin {
        async fn stale() -> Json<serde_json::Value> {
            Json(json!({
                "isStale": true,
                "daysSinceLastActive": 90,
                "action": "block",
                "notifyUser": false,
                "notifyAdmin": false
            }))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/security/stale-user", post(stale)),
            )
            .await
            .unwrap()
        });
        SentinelPlugin::new(SentinelOptions {
            connection: InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("key".into()),
                ..InfraConnectionOptions::default()
            },
            security: SecurityOptions {
                stale_users: Some(StaleUsersOptions {
                    enabled: true,
                    stale_days: None,
                    action: None,
                    notify_user: None,
                    notify_admin: None,
                    admin_email: None,
                }),
                ..SecurityOptions::default()
            },
        })
    }

    fn successful_session_response() -> Response {
        let now = Utc::now();
        let mut response = Response::new(Body::empty());
        response.extensions_mut().insert(crate::axum::http::BoundSession(
            SessionWithUser {
                session: AuthSession {
                    id: "session".into(),
                    user_id: "user".into(),
                    token: "token".into(),
                    actor_user_id: None,
                    authentication_method: None,
                    expires_at: now + Duration::hours(1),
                    created_at: now,
                    updated_at: now,
                    ip_address: None,
                    user_agent: None,
                    additional_fields: Map::new(),
                },
                user: AuthUser {
                    id: "user".into(),
                    username: None,
                    display_username: None,
                    name: "Person".into(),
                    email: "person@example.com".into(),
                    email_verified: true,
                    image: None,
                    additional_fields: Map::new(),
                    role: "user".into(),
                    is_anonymous: false,
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                    created_at: now,
                    updated_at: now,
                },
            },
        ));
        response
    }

    #[tokio::test]
    async fn stale_block_replaces_success_and_clears_session_cookies() {
        let plugin = blocking_plugin().await;
        let service = crate::AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new(vec![b'x'; 32]).unwrap(),
        );
        let blocked = process(
            &service,
            &plugin,
            &PluginRequestContext {
                method: "POST".into(),
                path: "/sign-in/email".into(),
                query: None,
                headers: Default::default(),
                body: None,
            },
            &Default::default(),
            successful_session_response(),
        )
        .await;

        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let cookies = blocked.headers().get_all("set-cookie");
        assert!(cookies.iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.contains("session_token=") && value.contains("Max-Age=0"))
        }));
        assert!(blocked.extensions().get::<StaleAccountBlocked>().is_some());
    }
}
