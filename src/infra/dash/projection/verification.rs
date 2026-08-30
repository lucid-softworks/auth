use super::super::{DashPlugin, tracking::EventObservation};
use super::support::{ProjectionContext, data, route, trigger};
use crate::{AuthService, DatabaseHookContext, VerificationValue};
use serde_json::json;

pub(super) async fn created(
    plugin: &DashPlugin,
    service: &AuthService,
    verification: &VerificationValue,
    context: &DatabaseHookContext,
) {
    if route(&ProjectionContext::new(service, context).path, "/request-password-reset") {
        emit(plugin, service, verification, context, "password_reset_requested", "Password reset requested").await;
    }
}

pub(super) async fn deleted(
    plugin: &DashPlugin,
    service: &AuthService,
    verification: &VerificationValue,
    context: &DatabaseHookContext,
) {
    if route(&ProjectionContext::new(service, context).path, "/reset-password") {
        emit(plugin, service, verification, context, "password_reset_completed", "Password reset completed").await;
    }
}

async fn emit(
    plugin: &DashPlugin,
    service: &AuthService,
    verification: &VerificationValue,
    context: &DatabaseHookContext,
    event_type: &'static str,
    display: &'static str,
) {
    let projection = ProjectionContext::new(service, context);
    let trigger = trigger(service, context, &verification.value).await;
    let user = service.dash_event_user(&verification.value).await.ok().flatten();
    plugin.track_event(
        EventObservation::new(
            event_type,
            &verification.value,
            display,
            data([
                ("userId", json!(verification.value)),
                ("userName", json!(user.as_ref().map(|user| user.name.as_str()).unwrap_or("unknown"))),
                ("userEmail", json!(user.as_ref().map(|user| user.email.as_str()).unwrap_or("unknown"))),
                ("triggeredBy", json!(trigger.actor)),
                ("triggerContext", json!(trigger.context)),
            ]),
            projection.location,
        ),
        Some(context),
    );
}
