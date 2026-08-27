use axum::{http::header, response::Response};
use url::Url;

pub(in crate::expo) fn handoff_redirect_cookie(
    service: &crate::AuthService,
    request: &crate::PluginRequestContext,
    mut response: Response,
) -> Response {
    if !matches_path(&request.path) {
        return response;
    }
    let Some(location) = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return response;
    };
    if location.contains("/oauth-proxy-callback") {
        return response;
    }
    let Ok(mut redirect) = Url::parse(&location) else {
        return response;
    };
    if matches!(redirect.scheme(), "http" | "https") || !service.trusts_origin(&location) {
        return response;
    }
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    if cookies.is_empty() {
        return response;
    }
    set_cookie_query(&mut redirect, &cookies.join(", "));
    let Some(location) = super::location_header(redirect.as_str()) else {
        return response;
    };
    response.headers_mut().insert(header::LOCATION, location);
    response
}

fn matches_path(path: &str) -> bool {
    path.starts_with("/callback")
        || path.starts_with("/magic-link/verify")
        || path.starts_with("/verify-email")
}

fn set_cookie_query(url: &mut Url, cookie: &str) {
    let mut pairs = Vec::new();
    let mut replaced = false;
    for (name, value) in url.query_pairs() {
        if name == "cookie" {
            if !replaced {
                pairs.push(("cookie".to_owned(), cookie.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((name.into_owned(), value.into_owned()));
        }
    }
    if !replaced {
        pairs.push(("cookie".to_owned(), cookie.to_owned()));
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_query_replaces_the_first_value_and_drops_duplicates() {
        let mut url = Url::parse("oracle:///done?a=1&cookie=old&b=2&cookie=duplicate").unwrap();
        set_cookie_query(&mut url, "session=signed; Path=/");
        assert_eq!(
            url.as_str(),
            "oracle:///done?a=1&cookie=session%3Dsigned%3B+Path%3D%2F&b=2"
        );
    }
}
