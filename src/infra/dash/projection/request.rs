use super::super::{DashPlugin, tracking::{EventLocation, EventObservation}};
use super::support::{data, login_method, route};
use crate::{AuthService, PluginRequestContext, SessionWithUser};
use serde_json::{Map, Value, json};

pub(super) async fn project(
    plugin: &DashPlugin,
    service: &AuthService,
    request: &PluginRequestContext,
    failed: bool,
    body: Option<&Map<String, Value>>,
    new_session: Option<SessionWithUser>,
) {
    let path = request.path.as_str();
    let location = EventLocation::from_headers(&request.headers);

    if !failed
        && ["/send-verification-email", "/dash/send-verification-email"]
            .iter()
            .any(|pattern| route(path, pattern))
    {
        let session = match new_session.clone() {
            Some(session) => Some(session),
            None => current_session(service, request).await,
        };
        if let Some(session) = session {
            plugin.track_event(
                verification_sent(&session, location.clone()),
                None,
            );
        }
    }

    if failed
        && ["/sign-in/email", "/sign-in/email-otp"]
            .iter()
            .any(|pattern| route(path, pattern))
        && let Some(email) = body
            .and_then(|body| body.get("email"))
            .and_then(Value::as_str)
    {
        let user = service.dash_event_user_by_email(email).await.ok().flatten();
        plugin.track_event(
            failed_sign_in(
                user.as_ref().map(|user| user.id.as_str()),
                user.as_ref().map(|user| user.name.as_str()),
                Some(email),
                login_method(path),
                location.clone(),
            ),
            None,
        );
    }

    if failed
        && route(path, "/sign-in/social")
        && body.and_then(|body| body.get("provider")).is_some()
        && body.and_then(|body| body.get("idToken")).is_some()
    {
        plugin.track_event(
            failed_sign_in(None, None, None, login_method(path), location.clone()),
            None,
        );
    }

    let failed_callback = request.method.eq_ignore_ascii_case("GET")
        && (route(path, "/callback/:id") || route(path, "/oauth2/callback/:providerId"))
        && new_session.is_none();
    if failed_callback {
        plugin.track_event(
            failed_sign_in(None, None, None, login_method(path), location),
            None,
        );
    }
}

async fn current_session(
    service: &AuthService,
    request: &PluginRequestContext,
) -> Option<SessionWithUser> {
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in &request.headers {
        if let (Ok(name), Ok(value)) = (name.parse::<axum::http::HeaderName>(), value.parse()) {
            headers.append(name, value);
        }
    }
    service
        .plugin_session(&headers)
        .await
        .ok()
        .flatten()
        .map(|session| session.session)
}

fn verification_sent(session: &SessionWithUser, location: EventLocation) -> EventObservation {
    EventObservation::new(
        "email_verification_sent",
        &session.user.id,
        "Verification email sent",
        data([
            ("userId", json!(session.user.id)),
            ("userName", json!(session.user.name)),
            ("userEmail", json!(session.user.email)),
            ("sessionId", json!(session.session.id)),
            ("triggeredBy", json!(session.user.id)),
            ("triggerContext", json!("user")),
        ]),
        location,
    )
}

fn failed_sign_in(
    user_id: Option<&str>,
    user_name: Option<&str>,
    user_email: Option<&str>,
    method: Option<&str>,
    location: EventLocation,
) -> EventObservation {
    let user_id = user_id.unwrap_or("unknown");
    EventObservation::new(
        "user_sign_in_failed",
        user_id,
        "User sign-in attempt failed",
        Value::Object(Map::from_iter([
            ("userId".into(), json!(user_id)),
            ("userName".into(), json!(user_name.unwrap_or("unknown"))),
            ("userEmail".into(), json!(user_email.unwrap_or("unknown"))),
            ("loginMethod".into(), json!(method)),
            ("triggeredBy".into(), json!(user_id)),
            ("triggerContext".into(), json!("user")),
        ])),
        location,
    )
}
