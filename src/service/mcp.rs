use chrono::{DateTime, Utc};

use super::AuthService;
use crate::{AuthError, VerificationValue};

impl AuthService {
    pub(crate) fn mcp_resolved_base_url(&self) -> Option<String> {
        let mut url = self.config.base_url().cloned()?;
        if url.path() == "/" {
            url.set_path(self.config.base_path());
        }
        Some(url.as_str().trim_end_matches('/').to_owned())
    }

    pub(crate) async fn reserve_mcp_dpop_proof(
        &self,
        replay_key: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        self.reserve_verification_value(VerificationValue::new(
            format!("dpop-proof:{replay_key}"),
            replay_key,
            expires_at,
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn resolves_the_auth_base_path() {
        let mut config = crate::AuthConfig::new([7_u8; 32]).unwrap();
        config.set_base_url("https://auth.example.test").unwrap();
        let service = AuthService::new(Arc::new(crate::MemoryStore::default()), config);
        assert_eq!(
            service.mcp_resolved_base_url().as_deref(),
            Some("https://auth.example.test/api/auth")
        );
    }
}
