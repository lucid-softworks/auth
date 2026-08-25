mod checker;
mod options;

pub use checker::{PasswordBreachCheckError, PasswordBreachChecker, PwnedPasswordsChecker};
pub use options::HaveIBeenPwnedOptions;

use crate::{AuthConfig, AuthError, AuthPlugin, PluginDescriptor};
use std::sync::Arc;

pub const PASSWORD_COMPROMISED: &str = "PASSWORD_COMPROMISED";
pub const DEFAULT_PASSWORD_COMPROMISED_MESSAGE: &str =
    "The password you entered has been compromised. Please choose a different password.";

/// Better Auth 1.7.1's server-only `haveIBeenPwned()` plugin.
#[derive(Clone)]
pub struct HaveIBeenPwnedPlugin {
    options: HaveIBeenPwnedOptions,
    checker: Arc<dyn PasswordBreachChecker>,
}

impl HaveIBeenPwnedPlugin {
    pub fn new(options: HaveIBeenPwnedOptions) -> Self {
        Self::with_checker(options, Arc::new(PwnedPasswordsChecker::new()))
    }

    /// Supplies an in-process checker without changing Better Auth's public options.
    #[doc(hidden)]
    pub fn with_checker(
        options: HaveIBeenPwnedOptions,
        checker: Arc<dyn PasswordBreachChecker>,
    ) -> Self {
        Self { options, checker }
    }

    pub fn options(&self) -> &HaveIBeenPwnedOptions {
        &self.options
    }

    pub(crate) async fn check(&self, path: Option<&str>, password: &str) -> Result<(), AuthError> {
        if self.options.enabled == Some(false)
            || !path.is_some_and(|path| self.options.checks_path(path))
        {
            return Ok(());
        }
        match self.checker.is_compromised(password).await {
            Ok(false) => Ok(()),
            Ok(true) => Err(AuthError::PasswordCompromised(
                self.options.compromised_message().to_owned(),
            )),
            Err(PasswordBreachCheckError::Status(status)) => {
                Err(AuthError::PasswordCheckStatus(status))
            }
            Err(PasswordBreachCheckError::Unavailable) => Err(AuthError::PasswordCheckUnavailable),
        }
    }
}

impl Default for HaveIBeenPwnedPlugin {
    fn default() -> Self {
        Self::new(HaveIBeenPwnedOptions::default())
    }
}

#[async_trait::async_trait]
impl AuthPlugin for HaveIBeenPwnedPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "have-i-been-pwned",
            display_name: "Have I Been Pwned",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("haveIBeenPwned"),
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
}
