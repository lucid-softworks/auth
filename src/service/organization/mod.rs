mod creation_persistence;
mod crud;
mod events;
mod invitation;
mod member;
mod permission;
mod role;
mod session;
mod team;

use super::AuthService;
use crate::{AuthError, OrganizationPlugin, StripePlugin};

impl AuthService {
    pub(crate) fn organization_plugin(&self) -> Result<&OrganizationPlugin, AuthError> {
        self.plugins.find::<OrganizationPlugin>().ok_or_else(|| {
            AuthError::InvalidConfiguration("organization plugin is not enabled".into())
        })
    }

    pub(crate) fn organization_stripe_plugin(&self) -> Option<&StripePlugin> {
        self.plugins
            .find::<StripePlugin>()
            .filter(|plugin| plugin.organization_enabled())
    }
}
