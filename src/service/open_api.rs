use super::AuthService;

impl AuthService {
    pub(crate) fn open_api_endpoints(&self) -> Vec<(&'static str, Vec<crate::OpenApiEndpoint>)> {
        self.plugins.open_api_endpoints()
    }

    pub(crate) fn open_api_models(&self) -> Vec<crate::OpenApiModel> {
        self.plugins.open_api_models()
    }

    pub(crate) fn configured_base_path(&self) -> &str {
        self.config.base_path()
    }

    pub(crate) fn open_api_configured_base_url(&self) -> Option<&url::Url> {
        self.config.base_url()
    }

    pub(crate) fn disabled_paths(&self) -> &[String] {
        &self.config.disabled_paths
    }
}
