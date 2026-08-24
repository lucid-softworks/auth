mod crud;
mod invitation;
mod member;
mod permission;
mod role;
mod session;
mod team;

use super::AuthService;
use crate::{AuthError, OrganizationPlugin};

impl AuthService {
    pub(crate) fn organization_plugin(&self) -> Result<&OrganizationPlugin, AuthError> {
        self.plugins.find::<OrganizationPlugin>().ok_or_else(|| {
            AuthError::InvalidConfiguration("organization plugin is not enabled".into())
        })
    }
}
