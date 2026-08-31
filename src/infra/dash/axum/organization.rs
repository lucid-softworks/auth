use super::{DashPlugin, route};
use crate::AxumPluginRoute;
use axum::{Extension, routing::{get, post}};
use std::sync::Arc;

mod core;
mod delete;
mod directory;
mod invitation;
mod member;
mod sso;
pub(super) mod support;
mod team;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route("/dash/list-organizations", get(core::list).layer(Extension(plugin.clone()))),
        route("/dash/export-organizations", get(core::export).layer(Extension(plugin.clone()))),
        route("/dash/organization/options", get(core::options).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}", get(core::get).layer(Extension(plugin.clone()))),
        route("/dash/organization/create", post(core::create).layer(Extension(plugin.clone()))),
        route("/dash/organization/update", post(core::update).layer(Extension(plugin.clone()))),
        route("/dash/organization/delete", post(delete::single).layer(Extension(plugin.clone()))),
        route("/dash/organization/delete-many", post(delete::many).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/members", get(member::list).layer(Extension(plugin.clone()))),
        route("/dash/organization/add-member", post(member::add).layer(Extension(plugin.clone()))),
        route("/dash/organization/remove-member", post(member::remove).layer(Extension(plugin.clone()))),
        route("/dash/organization/update-member-role", post(member::update_role).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/teams", get(team::list).layer(Extension(plugin.clone()))),
        route("/dash/organization/create-team", post(team::create).layer(Extension(plugin.clone()))),
        route("/dash/organization/update-team", post(team::update).layer(Extension(plugin.clone()))),
        route("/dash/organization/delete-team", post(team::delete).layer(Extension(plugin.clone()))),
        route("/dash/organization/{org_id}/teams/{team_id}/members", get(team::list_members).layer(Extension(plugin.clone()))),
        route("/dash/organization/add-team-member", post(team::add_member).layer(Extension(plugin.clone()))),
        route("/dash/organization/remove-team-member", post(team::remove_member).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/invitations", get(invitation::list).layer(Extension(plugin.clone()))),
        route("/dash/organization/invite-member", post(invitation::invite).layer(Extension(plugin.clone()))),
        route("/dash/organization/cancel-invitation", post(invitation::cancel).layer(Extension(plugin.clone()))),
        route("/dash/organization/resend-invitation", post(invitation::resend).layer(Extension(plugin.clone()))),
        route("/dash/organization/check-user-by-email", post(invitation::check_user_by_email).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/sso-providers", get(sso::list).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/sso-provider/request-verification-token", post(sso::domain::request_verification_token).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/sso-provider/verify-domain", post(sso::domain::verify).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/sso-provider/delete", post(sso::delete).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/sso-provider/mark-domain-verified", post(sso::mark_domain_verified).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories", get(directory::list).post(directory::create).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}", get(directory::get_one).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}/credentials/rotate", post(directory::rotate).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}/credentials/{credential_id}/revoke", post(directory::revoke).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}/events", get(directory::events).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}/decommission", post(directory::decommission).layer(Extension(plugin.clone()))),
        route("/dash/organization/{id}/directories/{provider_id}/unpair", post(directory::unpair).layer(Extension(plugin.clone()))),
        route("/dash/organization/directory/create", post(directory::legacy_unavailable).layer(Extension(plugin.clone()))),
        route("/dash/organization/directory/delete", post(directory::legacy_unavailable).layer(Extension(plugin.clone()))),
        route("/dash/organization/directory/regenerate-token", post(directory::legacy_unavailable).layer(Extension(plugin.clone()))),
        route("/dash/accept-invitation", get(invitation::accept).layer(Extension(plugin.clone()))),
        route("/dash/complete-invitation", post(invitation::complete).layer(Extension(plugin.clone()))),
        route("/dash/complete-invitation-handoff", get(invitation::handoff).layer(Extension(plugin.clone()))),
        route("/dash/complete-invitation-social", get(invitation::social).layer(Extension(plugin.clone()))),
        route("/dash/check-user-exists", post(invitation::check_user_exists).layer(Extension(plugin))),
    ]
}
