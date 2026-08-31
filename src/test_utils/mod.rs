//! Better Auth-compatible privileged helpers for test-only auth instances.
//!
//! The plugin is safe to compile into an application, but it should be
//! registered only in a separate test configuration because its native helper
//! methods bypass ordinary route authorization.

pub(crate) mod factory;
mod otp;
mod types;

pub use types::{
    TestCookie, TestHelpers, TestLoginResult, TestOrganizationHelpers, TestOrganizationOverrides,
    TestOtpHelpers, TestUserOverrides, TestUtilsError, TestUtilsOptions,
};

use crate::{AuthConfig, AuthError, AuthPlugin, DatabaseHooks, DatabaseRecord, PluginDescriptor};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

/// Better Auth 1.7.2 `testUtils()` server plugin.
#[derive(Clone)]
pub struct TestUtilsPlugin {
    options: TestUtilsOptions,
    captured_otps: Arc<RwLock<BTreeMap<String, String>>>,
}

impl TestUtilsPlugin {
    pub fn new(options: TestUtilsOptions) -> Self {
        Self {
            options,
            captured_otps: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub const fn options(&self) -> TestUtilsOptions {
        self.options
    }

    pub(crate) fn get_otp(&self, identifier: &str) -> Option<String> {
        self.captured_otps
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(identifier)
            .cloned()
    }

    pub(crate) fn clear_otps(&self) {
        self.captured_otps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

impl Default for TestUtilsPlugin {
    fn default() -> Self {
        Self::new(TestUtilsOptions::default())
    }
}

#[async_trait]
impl DatabaseHooks for TestUtilsPlugin {
    async fn after_create(
        &self,
        record: &DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        let DatabaseRecord::Verification(verification) = record else {
            return Ok(());
        };
        if let Some((identifier, otp)) = otp::capture(verification) {
            self.captured_otps
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(identifier, otp);
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin for TestUtilsPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "test-utils",
            display_name: "Better Auth Test Utils",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("testUtils"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        self.options.capture_otp.then_some(self)
    }
}
