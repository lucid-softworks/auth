/// Configuration for the pinned enterprise SSO plugin surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoOptions {
    /// Enables the two published DNS domain-verification endpoints and field.
    pub domain_verification: bool,
    /// Maximum providers one user may register. Upstream defaults to ten.
    pub providers_limit: usize,
}

impl Default for SsoOptions {
    fn default() -> Self {
        Self {
            domain_verification: false,
            providers_limit: 10,
        }
    }
}
