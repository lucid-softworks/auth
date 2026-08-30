use super::DashPlugin;
use crate::{AuthService, DatabaseHookContext, DatabaseRecord};

mod account;
mod organization;
#[cfg(feature = "axum")]
mod request;
mod session;
mod support;
mod user;
mod verification;

pub(super) fn organization(
    plugin: &DashPlugin,
    event: &crate::AfterOrganizationEvent<'_>,
) {
    organization::project(plugin, event);
}

#[cfg(feature = "axum")]
pub(super) async fn after_response(
    plugin: &DashPlugin,
    service: &AuthService,
    request: &crate::PluginRequestContext,
    failed: bool,
    body: Option<serde_json::Map<String, serde_json::Value>>,
    new_session: Option<crate::SessionWithUser>,
) {
    request::project(plugin, service, request, failed, body.as_ref(), new_session).await;
}

pub(super) async fn after_create(
    plugin: &DashPlugin,
    service: &AuthService,
    record: &DatabaseRecord,
    context: &DatabaseHookContext,
) {
    if context.request.is_none() {
        return;
    }
    match record {
        DatabaseRecord::User(user) => user::created(plugin, service, user, context).await,
        DatabaseRecord::Session(session) => {
            session::created(plugin, service, session, context).await;
        }
        DatabaseRecord::Account(account) => {
            account::linked(plugin, service, account, context).await;
        }
        DatabaseRecord::Verification(verification) => {
            verification::created(plugin, service, verification, context).await;
        }
    }
}

pub(super) async fn after_update(
    plugin: &DashPlugin,
    service: &AuthService,
    record: &DatabaseRecord,
    context: &DatabaseHookContext,
) {
    if context.request.is_none() {
        return;
    }
    match record {
        DatabaseRecord::User(user) => user::updated(plugin, service, user, context).await,
        DatabaseRecord::Account(account) => {
            account::password_changed(plugin, service, account, context).await;
        }
        DatabaseRecord::Session(_) | DatabaseRecord::Verification(_) => {}
    }
}

pub(super) async fn after_delete(
    plugin: &DashPlugin,
    service: &AuthService,
    record: &DatabaseRecord,
    context: &DatabaseHookContext,
) {
    if context.request.is_none() {
        return;
    }
    match record {
        DatabaseRecord::User(user) => user::deleted(plugin, service, user, context).await,
        DatabaseRecord::Session(session) => {
            session::deleted(plugin, service, session, context).await;
        }
        DatabaseRecord::Account(account) => {
            account::unlinked(plugin, service, account, context).await;
        }
        DatabaseRecord::Verification(verification) => {
            verification::deleted(plugin, service, verification, context).await;
        }
    }
}
