use super::input::TransferQuery;
use crate::{
    AuthService,
    axum::http::{cookie_value, serialize_cookie, with_cookie},
};
use axum::{http::HeaderMap, response::Response};

pub(super) fn configured_transfer_from_request(
    service: &AuthService,
    options: &super::ElectronOptions,
    headers: &HeaderMap,
) -> Option<TransferQuery> {
    let name = format!("{}.transfer_token", options.cookie_prefix);
    transfer_from_request(service, headers, &name)
}

pub(super) fn core_transfer_from_request(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<TransferQuery> {
    transfer_from_request(
        service,
        headers,
        &service.plugin_cookie("transfer_token").name,
    )
}

fn transfer_from_request(
    service: &AuthService,
    headers: &HeaderMap,
    name: &str,
) -> Option<TransferQuery> {
    let value = cookie_value(headers, name)?;
    let value = service.verify_cookie_value(&value)?;
    serde_json::from_str(&value).ok()
}

pub(super) fn set_transfer(
    service: &AuthService,
    options: &super::ElectronOptions,
    payload: &TransferQuery,
    response: Response,
) -> Response {
    let Ok(payload) = serde_json::to_string(payload) else {
        return response;
    };
    with_cookie(
        response,
        serialize_cookie(
            &service.plugin_cookie("transfer_token"),
            &service.signed_cookie_value(&payload),
            Some(options.code_expires_in),
        ),
    )
}

pub(super) fn clear_transfer(service: &AuthService, response: Response) -> Response {
    with_cookie(
        response,
        serialize_cookie(&service.plugin_cookie("transfer_token"), "", Some(0)),
    )
}

pub(super) fn set_redirect(
    service: &AuthService,
    options: &super::ElectronOptions,
    redirect_token: &str,
    response: Response,
) -> Response {
    let mut cookie = service.session_cookie();
    cookie.name = format!("{}.{}", options.cookie_prefix, options.client_id);
    cookie.attributes.http_only = false;
    with_cookie(
        response,
        serialize_cookie(
            &cookie,
            redirect_token,
            Some(options.redirect_cookie_expires_in),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    #[test]
    fn matching_and_nonmatching_hooks_preserve_upstreams_cookie_name_split() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([78; 32]).unwrap(),
        );
        let options = super::super::ElectronOptions {
            cookie_prefix: "desktop".into(),
            ..Default::default()
        };
        let payload = TransferQuery {
            client_id: "electron".into(),
            state: "state".into(),
            code_challenge: "challenge".into(),
        };
        let signed = service.signed_cookie_value(&serde_json::to_string(&payload).unwrap());

        let core = HeaderMap::from_iter([(
            axum::http::header::COOKIE,
            format!("better-auth.transfer_token={signed}")
                .parse()
                .unwrap(),
        )]);
        assert_eq!(
            core_transfer_from_request(&service, &core),
            Some(payload.clone())
        );
        assert!(configured_transfer_from_request(&service, &options, &core).is_none());

        let configured = HeaderMap::from_iter([(
            axum::http::header::COOKIE,
            format!("desktop.transfer_token={signed}").parse().unwrap(),
        )]);
        assert_eq!(
            configured_transfer_from_request(&service, &options, &configured),
            Some(payload)
        );
        assert!(core_transfer_from_request(&service, &configured).is_none());
    }
}
