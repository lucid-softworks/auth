mod auth;
mod context_id;
mod organization;
mod user;

use super::AuthService;
use crate::{TestHelpers, TestOrganizationHelpers, TestOtpHelpers, TestUtilsPlugin};

impl AuthService {
    /// Returns the privileged Test Utils API only when `TestUtilsPlugin` is installed.
    pub fn test(&self) -> Option<TestHelpers<'_>> {
        self.test_utils_plugin()
            .map(|_| TestHelpers { service: self })
    }

    pub(crate) fn generate_test_id(&self, model: &str) -> String {
        context_id::generate(&self.config, model)
    }

    pub(crate) fn generate_organization_id(&self) -> String {
        self.generate_test_id("organization")
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
