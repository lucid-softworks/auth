use super::AuthService;

impl AuthService {
    pub(crate) fn jwt_plugin(&self) -> Option<&crate::JwtPlugin> {
        self.plugins.find::<crate::JwtPlugin>()
    }

    pub(crate) fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        self.store.jwk_store()
    }

    pub(crate) fn encrypt_jwt_private_key(&self, plaintext: &[u8]) -> Result<String, ()> {
        crate::symmetric_crypto::encrypt_versioned(
            &self.config.secret,
            self.config.versioned_secrets(),
            plaintext,
        )
    }

    pub(crate) fn decrypt_jwt_private_key(&self, envelope: &str) -> Result<Vec<u8>, ()> {
        crate::symmetric_crypto::decrypt_versioned(
            &self.config.secret,
            self.config.versioned_secrets(),
            self.config.legacy_secret(),
            envelope,
        )
    }

    pub(crate) fn jwt_default_origin(&self) -> Option<String> {
        self.config
            .base_url()
            .map(|url| url.origin().ascii_serialization())
    }
}
