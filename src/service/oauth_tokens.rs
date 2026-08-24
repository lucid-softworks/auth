use super::AuthService;
use crate::{AuthError, oauth::crypto};

impl AuthService {
    pub(super) fn protect_oauth_token(
        &self,
        token: Option<String>,
    ) -> Result<Option<String>, AuthError> {
        if self.config.account.encrypt_oauth_tokens {
            crypto::encrypt(&self.config.secret, token)
        } else {
            Ok(token)
        }
    }

    pub(super) fn unprotect_oauth_token(
        &self,
        token: Option<&str>,
    ) -> Result<Option<String>, AuthError> {
        if self.config.account.encrypt_oauth_tokens {
            crypto::decrypt(&self.config.secret, token)
        } else {
            Ok(token.map(str::to_owned))
        }
    }
}
