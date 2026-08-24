//! Native OAuth 2.0 and OpenID Connect provider integration.

mod builtin_catalog;
#[cfg(test)]
mod builtin_fixtures;
mod builtin_http;
mod builtins;
pub(crate) mod crypto;
pub(crate) mod google_id_token;
mod provider;
mod provider_data;
mod provider_http;

pub use builtins::{BuiltinProvider, BuiltinProviderKind};
pub use provider::{
    AuthorizationRequest, OAuthProviderConfig, OAuthTokens, OAuthUserInfo, OidcConfig, ProfileMap,
    SocialProvider, TokenEndpointAuth,
};

pub(crate) use provider::authorization_parameter_is_reserved;
pub(crate) use provider_data::{map_profile, parse_token_response};
pub(crate) fn synthetic_issuer(provider_id: &str) -> String {
    format!("local:oauth:{}", encode_uri_component(provider_id))
}

fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_issuer_uses_javascript_encode_uri_component_semantics() {
        assert_eq!(
            synthetic_issuer("custom/oauth provider!"),
            "local:oauth:custom%2Foauth%20provider!"
        );
        assert_eq!(synthetic_issuer("café"), "local:oauth:caf%C3%A9");
    }
}
