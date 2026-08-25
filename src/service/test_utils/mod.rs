mod auth;
mod organization;
mod user;

use super::AuthService;
use crate::{TestHelpers, TestOrganizationHelpers, TestOtpHelpers, TestUtilsPlugin};
use uuid::Uuid;

impl AuthService {
    /// Returns the privileged Test Utils API only when `TestUtilsPlugin` is installed.
    pub fn test(&self) -> Option<TestHelpers<'_>> {
        self.test_utils_plugin()
            .map(|_| TestHelpers { service: self })
    }

    pub(crate) fn generate_id(&self, model: &str) -> Uuid {
        self.config
            .id_generator
            .as_ref()
            .and_then(|generator| generator.generate(model))
            .unwrap_or_else(Uuid::new_v4)
    }

    fn test_utils_plugin(&self) -> Option<&TestUtilsPlugin> {
        self.plugins.find::<TestUtilsPlugin>()
    }

    fn test_organization_helpers(&self) -> Option<TestOrganizationHelpers<'_>> {
        self.plugins
            .find::<crate::OrganizationPlugin>()
            .map(|_| TestOrganizationHelpers { service: self })
    }

    fn test_otp_helpers(&self) -> Option<TestOtpHelpers<'_>> {
        self.test_utils_plugin()
            .filter(|plugin| plugin.options().capture_otp)
            .map(|plugin| TestOtpHelpers { plugin })
    }
}

impl<'a> TestHelpers<'a> {
    pub fn organization(&self) -> Option<TestOrganizationHelpers<'a>> {
        self.service.test_organization_helpers()
    }

    pub fn otp(&self) -> Option<TestOtpHelpers<'a>> {
        self.service.test_otp_helpers()
    }
}
