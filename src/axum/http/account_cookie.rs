use super::{auth_error, chunked_cookie, clear_cookie_store, with_chunked_cookie};
use crate::{AuthService, OAuthAccount};
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

pub(crate) fn account_data_cookie(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    chunked_cookie(headers, &service.account_data_cookie())
}

pub(crate) fn with_account_cookie(
    service: &AuthService,
    headers: &HeaderMap,
    account: OAuthAccount,
    body: impl IntoResponse,
) -> Response {
    if !service.account_cookie_enabled() {
        return body.into_response();
    }
    match service.encode_account_cookie(account) {
        Ok(value) => with_chunked_cookie(
            &service.account_data_cookie(),
            &value,
            Some(service.cookie_cache_max_age()),
            Some(headers),
            body,
        ),
        Err(error) => auth_error(error),
    }
}

pub(crate) fn clear_account_cookie(
    service: &AuthService,
    headers: Option<&HeaderMap>,
    body: impl IntoResponse,
) -> Response {
    clear_cookie_store(&service.account_data_cookie(), headers, body)
}

pub(crate) fn refresh_account_cookie(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: uuid::Uuid,
    body: impl IntoResponse,
) -> Response {
    if !service.account_cookie_enabled() || !service.cookie_cache_enabled() {
        return body.into_response();
    }
    let Some(value) = account_data_cookie(service, headers) else {
        return body.into_response();
    };
    match service.decode_account_cookie(&value) {
        Some(account) if account.user_id == user_id => {
            with_account_cookie(service, headers, account, body)
        }
        _ => clear_account_cookie(service, Some(headers), body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};
    use chrono::Utc;
    use std::sync::Arc;

    fn account(additional_size: usize) -> OAuthAccount {
        let now = Utc::now();
        OAuthAccount {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            issuer: "https://issuer.example.com".into(),
            account_id: "provider-subject".into(),
            provider_id: "provider".into(),
            access_token: Some("encrypted-access".into()),
            refresh_token: Some("encrypted-refresh".into()),
            id_token: Some("encrypted-id".into()),
            access_token_expires_at: Some(now + chrono::Duration::hours(1)),
            refresh_token_expires_at: None,
            scope: Some("openid,email".into()),
            password: None,
            additional_fields: serde_json::Map::from_iter([(
                "fixture".into(),
                serde_json::Value::String("x".repeat(additional_size)),
            )]),
            created_at: now,
            updated_at: now,
        }
    }

    fn service(configure: impl FnOnce(&mut crate::AuthConfig)) -> AuthService {
        let mut config = crate::AuthConfig::new([82; 32]).unwrap();
        config.account.store_account_cookie = true;
        configure(&mut config);
        AuthService::new(Arc::new(crate::MemoryStore::default()), config)
    }

    #[test]
    fn disabled_without_an_explicit_opt_in() {
        let config = crate::AuthConfig::new([82; 32]).unwrap();
        let service = AuthService::new(Arc::new(crate::MemoryStore::default()), config);
        let response = with_account_cookie(
            &service,
            &HeaderMap::new(),
            account(0),
            axum::http::StatusCode::OK,
        );
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );
    }

    #[test]
    fn uses_better_auth_name_scope_and_lifetime() {
        let service = service(|config| {
            config.set_base_url("https://auth.example.com").unwrap();
            config.session.cookie_cache.max_age = chrono::Duration::minutes(7);
            config.cookies.account_data.name = Some("selected-account".into());
            config.cookies.account_data.attributes.path = Some("/api/auth".into());
            config.cookies.account_data.attributes.domain = Some(".example.com".into());
            config.cookies.account_data.attributes.same_site = Some(crate::SameSite::Strict);
        });
        let expected = account(0);
        let response = with_account_cookie(
            &service,
            &HeaderMap::new(),
            expected.clone(),
            axum::http::StatusCode::OK,
        );
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .next()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.starts_with("__Secure-selected-account="));
        assert!(cookie.contains("; HttpOnly; SameSite=Strict; Path=/api/auth"));
        assert!(cookie.contains("; Domain=.example.com; Max-Age=420; Secure"));
        let value = cookie.split_once('=').unwrap().1.split(';').next().unwrap();
        assert_eq!(service.decode_account_cookie(value), Some(expected));
    }

    #[test]
    fn chunks_and_expires_every_stale_piece() {
        let service = service(|_| {});
        let expected = account(12_000);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "better-auth.account_data=old; better-auth.account_data.0=old-zero; better-auth.account_data.9=stale",
            ),
        );
        let response = with_account_cookie(
            &service,
            &headers,
            expected.clone(),
            axum::http::StatusCode::OK,
        );
        let set_cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert!(set_cookies.iter().all(|cookie| cookie.len() <= 4_050));
        for stale in [
            "better-auth.account_data=;",
            "better-auth.account_data.0=;",
            "better-auth.account_data.9=;",
        ] {
            assert!(
                set_cookies
                    .iter()
                    .any(|cookie| cookie.starts_with(stale) && cookie.contains("Max-Age=0")),
                "missing expiration for {stale}"
            );
        }
        let request_cookies = set_cookies
            .iter()
            .filter(|cookie| !cookie.contains("Max-Age=0"))
            .map(|cookie| cookie.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let mut round_trip = HeaderMap::new();
        round_trip.insert(
            header::COOKIE,
            HeaderValue::from_str(&request_cookies).unwrap(),
        );
        let value = account_data_cookie(&service, &round_trip).unwrap();
        assert_eq!(service.decode_account_cookie(&value), Some(expected));
    }
}
