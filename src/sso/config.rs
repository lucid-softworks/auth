/// Configuration for the pinned enterprise SSO plugin surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsoOptions {
    /// Enables the two published DNS domain-verification endpoints and field.
    pub domain_verification: bool,
}
