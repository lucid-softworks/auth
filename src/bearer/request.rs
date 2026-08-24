use crate::{AuthService, BearerPlugin};
use axum::http::{HeaderMap, header};

pub(crate) fn session_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let plugin = service.plugins().find::<BearerPlugin>()?;
    let authorization = combined_authorization(headers)?;
    let prefix = authorization.get(..7)?;
    if !prefix.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = authorization.get(7..)?.trim();
    if token.is_empty() {
        return None;
    }
    if !token.contains('.') {
        return (!plugin.config().require_signature).then(|| token.to_owned());
    }
    let decoded = if token.contains('%') {
        crate::service::decode_cookie_component(token)
    } else {
        token.to_owned()
    };
    service.verify_bearer_cookie_value(&decoded)
}

fn combined_authorization(headers: &HeaderMap) -> Option<String> {
    let values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!values.is_empty()).then(|| values.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    fn service(require_signature: bool) -> AuthService {
        let mut config = AuthConfig::new([156_u8; 32]).unwrap();
        config
            .add_plugin(BearerPlugin::new(crate::BearerConfig { require_signature }))
            .unwrap();
        AuthService::new(Arc::new(MemoryStore::default()), config)
    }

    #[test]
    fn parser_distinguishes_noop_from_accepted_credentials() {
        let service = service(false);
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bEaReR   opaque  ".parse().unwrap());
        assert_eq!(session_token(&service, &headers), Some("opaque".into()));

        headers.insert(
            header::AUTHORIZATION,
            "Bearer invalid.token".parse().unwrap(),
        );
        assert_eq!(session_token(&service, &headers), None);

        let dotted = service.signed_cookie_value("Selector.Token-Ab_C");
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {dotted}").parse().unwrap(),
        );
        assert_eq!(session_token(&service, &headers), None);

        headers.insert(header::AUTHORIZATION, "Basic opaque".parse().unwrap());
        assert_eq!(session_token(&service, &headers), None);
        assert_eq!(session_token(&self::service(true), &headers), None);
    }
}
