use super::AuthConfig;
use crate::AuthError;
use std::collections::HashSet;

/// A Better Auth secret version used for encrypted-at-rest data rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedSecret {
    pub version: u32,
    pub value: Vec<u8>,
}

impl AuthConfig {
    /// Configures Better Auth-compatible versioned secrets. The first entry is
    /// current and is used for new encryption; the remaining entries decrypt
    /// existing versioned envelopes. `legacy_secret` decrypts old bare-hex
    /// envelopes created before versioned secrets were enabled.
    pub fn set_versioned_secrets(
        &mut self,
        secrets: Vec<VersionedSecret>,
        legacy_secret: Option<Vec<u8>>,
    ) -> Result<(), AuthError> {
        if secrets.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "versioned secrets must contain at least one entry".into(),
            ));
        }
        let mut versions = HashSet::new();
        for secret in &secrets {
            if secret.value.is_empty() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "secret version {} must not be empty",
                    secret.version
                )));
            }
            if !versions.insert(secret.version) {
                return Err(AuthError::InvalidConfiguration(format!(
                    "secret version {} is duplicated",
                    secret.version
                )));
            }
        }
        self.secret = secrets[0].value.clone();
        self.versioned_secrets = secrets;
        self.legacy_secret = legacy_secret;
        Ok(())
    }

    pub(crate) fn versioned_secrets(&self) -> &[VersionedSecret] {
        &self.versioned_secrets
    }

    pub(crate) fn legacy_secret(&self) -> Option<&[u8]> {
        self.legacy_secret.as_deref()
    }
}
