use super::super::{DashPlugin, tracking::EventObservation};
use super::support::{ProjectionContext, Trigger, login_method, route, trigger};
use crate::{AuthService, AuthSession, AuthUser, DatabaseHookContext};
use serde_json::{Map, Value, json};

pub(super) async fn created(
    plugin: &DashPlugin,
    service: &AuthService,
    session: &AuthSession,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    let user = service.dash_event_user(&session.user_id).await.ok().flatten();
    let method = login_method(&projection.path).unwrap_or("unknown");
    let sign_in = ["/sign-in", "/sign-up", "/callback/:id", "/oauth2/callback/:providerId"]
        .iter()
        .any(|path| route(&projection.path, path));
    let sign_in_trigger = Trigger {
        actor: session.user_id.clone(),
        context: "user",
    };
    let normal_trigger = trigger(service, context, &session.user_id).await;
    if sign_in {
        plugin.track_event(
            session_event(
                session,
                user.as_ref(),
                method,
                &sign_in_trigger,
                "user_signed_in",
                format!("Signed in via {method}"),
                projection.location.clone(),
            ),
            Some(context),
        );
    }
    plugin.track_event(
        session_event(
            session,
            user.as_ref(),
            method,
            &normal_trigger,
            "session_created",
            "Session created".into(),
            projection.location.clone(),
        ),
        Some(context),
    );
    if let Some(impersonator_id) = session.actor_user_id.as_deref() {
        let impersonator = service.dash_event_user(impersonator_id).await.ok().flatten();
        let trigger = Trigger {
            actor: impersonator_id.to_owned(),
            ..normal_trigger
        };
        plugin.track_event(
            impersonation_event(
                session,
                user.as_ref(),
                impersonator.as_ref(),
                method,
                &trigger,
                "user_impersonated",
                "User impersonated",
                projection.location,
            ),
            Some(context),
        );
    }
}

pub(super) async fn deleted(
    plugin: &DashPlugin,
    service: &AuthService,
    session: &AuthSession,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    let user = service.dash_event_user(&session.user_id).await.ok().flatten();
    let method = session
        .authentication_method
        .map(crate::AuthenticationMethod::as_str)
        .unwrap_or("unknown");
    let trigger = trigger(service, context, &session.user_id).await;
    let bulk = [
        "/revoke-sessions",
        "/admin/revoke-user-sessions",
        "/dash/sessions/revoke-all",
        "/dash/ban-user",
    ]
    .iter()
    .any(|path| route(&projection.path, path));
    if bulk {
        if crate::database_hooks::mark_request_observation("dash.all_sessions_revoked") {
            plugin.track_event(
                all_revoked_event(
                    session,
                    user.as_ref(),
                    &trigger,
                    projection.location.clone(),
                ),
                Some(context),
            );
        }
    } else {
        let (kind, display) = if route(&projection.path, "/sign-out") {
            ("user_signed_out", "User signed out")
        } else {
            ("session_revoked", "Session revoked")
        };
        plugin.track_event(
            session_event(
                session,
                user.as_ref(),
                method,
                &trigger,
                kind,
                display.into(),
                projection.location.clone(),
            ),
            Some(context),
        );
    }
    if let Some(impersonator_id) = session.actor_user_id.as_deref() {
        let impersonator = service.dash_event_user(impersonator_id).await.ok().flatten();
        plugin.track_event(
            impersonation_event(
                session,
                user.as_ref(),
                impersonator.as_ref(),
                method,
                &trigger,
                "user_impersonated_stopped",
                "User impersonation stopped",
                projection.location,
            ),
            Some(context),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn session_event(
    session: &AuthSession,
    user: Option<&AuthUser>,
    login_method: &str,
    trigger: &Trigger,
    event_type: &'static str,
    display: String,
    location: super::super::tracking::EventLocation,
) -> EventObservation {
    EventObservation::new(
        event_type,
        &session.user_id,
        display,
        session_data(session, user, login_method, trigger),
        location,
    )
}

fn session_data(
    session: &AuthSession,
    user: Option<&AuthUser>,
    login_method: &str,
    trigger: &Trigger,
) -> Value {
    let mut data = Map::from_iter([
        ("userId".into(), json!(session.user_id)),
        ("userName".into(), json!(user.map(|user| user.name.as_str()).unwrap_or("unknown"))),
        ("userEmail".into(), json!(user.map(|user| user.email.as_str()).unwrap_or("unknown"))),
        ("sessionId".into(), json!(session.id)),
        ("loginMethod".into(), json!(login_method)),
        ("triggeredBy".into(), json!(trigger.actor)),
        ("triggerContext".into(), json!(trigger.context)),
    ]);
    if let Some(user_agent) = &session.user_agent {
        data.insert("userAgent".into(), json!(user_agent));
    }
    Value::Object(data)
}

fn all_revoked_event(
    session: &AuthSession,
    user: Option<&AuthUser>,
    trigger: &Trigger,
    location: super::super::tracking::EventLocation,
) -> EventObservation {
    EventObservation::new(
        "all_sessions_revoked",
        &session.user_id,
        "All sessions revoked",
        Value::Object(Map::from_iter([
            ("userId".into(), json!(session.user_id)),
            ("userName".into(), json!(user.map(|user| user.name.as_str()).unwrap_or("unknown"))),
            ("userEmail".into(), json!(user.map(|user| user.email.as_str()).unwrap_or("unknown"))),
            ("triggeredBy".into(), json!(trigger.actor)),
            ("triggerContext".into(), json!(trigger.context)),
        ])),
        location,
    )
}

#[allow(clippy::too_many_arguments)]
fn impersonation_event(
    session: &AuthSession,
    user: Option<&AuthUser>,
    impersonator: Option<&AuthUser>,
    login_method: &str,
    trigger: &Trigger,
    event_type: &'static str,
    display: &'static str,
    location: super::super::tracking::EventLocation,
) -> EventObservation {
    let mut data = session_data(session, user, login_method, trigger)
        .as_object()
        .cloned()
        .unwrap_or_default();
    if let Some(impersonator_id) = &session.actor_user_id {
        data.insert(
            "impersonatedBy".into(),
            json!(impersonator
                .map(|user| if user.name.is_empty() { user.email.as_str() } else { user.name.as_str() })
                .unwrap_or(impersonator_id)),
        );
        data.insert("impersonatedById".into(), json!(impersonator_id));
    }
    EventObservation::new(
        event_type,
        &session.user_id,
        display,
        Value::Object(data),
        location,
    )
}
