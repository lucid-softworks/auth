use super::super::{DashPlugin, tracking::EventObservation};
use super::support::{ProjectionContext, data, route, trigger};
use crate::{AuthService, DatabaseHookContext, OAuthAccount};
use serde_json::json;

pub(super) async fn linked(
    plugin: &DashPlugin,
    service: &AuthService,
    account: &OAuthAccount,
    context: &DatabaseHookContext,
) {
    emit(plugin, service, account, context, "account_linked", format!("Linked {} account", account.provider_id)).await;
}

pub(super) async fn unlinked(
    plugin: &DashPlugin,
    service: &AuthService,
    account: &OAuthAccount,
    context: &DatabaseHookContext,
) {
    emit(plugin, service, account, context, "account_unlinked", format!("Unlinked {} account", account.provider_id)).await;
}

pub(super) async fn password_changed(
    plugin: &DashPlugin,
    service: &AuthService,
    account: &OAuthAccount,
    context: &DatabaseHookContext,
) {
    let projection = ProjectionContext::new(service, context);
    if [
        "/change-password",
        "/set-password",
        "/reset-password",
        "/admin/set-user-password",
        "/dash/set-password",
    ]
    .iter()
    .any(|path| route(&projection.path, path))
    {
        emit(plugin, service, account, context, "password_changed", "Password changed".into()).await;
    }
}

async fn emit(
    plugin: &DashPlugin,
    service: &AuthService,
    account: &OAuthAccount,
    context: &DatabaseHookContext,
    event_type: &'static str,
    display: String,
) {
    let projection = ProjectionContext::new(service, context);
    let trigger = trigger(service, context, &account.user_id).await;
    let user = service.dash_event_user(&account.user_id).await.ok().flatten();
    plugin.track_event(
        EventObservation::new(
            event_type,
            &account.user_id,
            display,
            data([
                ("userId", json!(account.user_id)),
                ("userEmail", json!(user.as_ref().map(|user| user.email.as_str()).unwrap_or("unknown"))),
                ("userName", json!(user.as_ref().map(|user| user.name.as_str()).unwrap_or("unknown"))),
                ("accountId", json!(account.id)),
                ("providerId", json!(account.provider_id)),
                ("triggeredBy", json!(trigger.actor)),
                ("triggerContext", json!(trigger.context)),
            ]),
            projection.location,
        ),
        Some(context),
    );
}
