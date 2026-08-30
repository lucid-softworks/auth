use super::support;
use axum::response::Response;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;

pub(super) fn additional_params(
    values: Option<&Map<String, Value>>,
) -> Result<Vec<(String, String)>, Box<Response>> {
    const RESERVED: &[&str] = &[
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ];
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    if values.keys().any(|key| RESERVED.contains(&key.as_str())) {
        return Err(Box::new(support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "additionalParams cannot include reserved OAuth parameters: state, client_id, redirect_uri, response_type, code_challenge, code_challenge_method, nonce, scope",
        )));
    }
    values
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| {
                    Box::new(support::error(
                        axum::http::StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "additionalParams values must be strings",
                    ))
                })
        })
        .collect()
}

pub(super) struct Input<'a> {
    pub endpoint: &'a str,
    pub client_id: &'a str,
    pub state: &'a str,
    pub scopes: &'a [String],
    pub redirect_uri: &'a str,
    pub login_hint: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub additional: &'a [(String, String)],
}

pub(super) fn build(input: Input<'_>) -> Result<String, Box<Response>> {
    let mut url = Url::parse(input.endpoint).map_err(|_| {
        Box::new(support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid OIDC configuration. Authorization URL not found.",
        ))
    })?;
    set_query(&mut url, "response_type", "code");
    set_query(&mut url, "client_id", input.client_id);
    set_query(&mut url, "state", input.state);
    if !input.scopes.is_empty() {
        set_query(&mut url, "scope", &input.scopes.join(" "));
    }
    set_query(&mut url, "redirect_uri", input.redirect_uri);
    if let Some(login_hint) = input.login_hint.filter(|hint| !hint.is_empty()) {
        set_query(&mut url, "login_hint", login_hint);
    }
    if let Some(code_verifier) = input.code_verifier {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(code_verifier.as_bytes()));
        set_query(&mut url, "code_challenge_method", "S256");
        set_query(&mut url, "code_challenge", &challenge);
    }
    for (key, value) in input.additional {
        set_query(&mut url, key, value);
    }
    Ok(url.into())
}

fn set_query(url: &mut Url, name: &str, value: &str) {
    let mut found = false;
    let mut pairs = url
        .query_pairs()
        .filter_map(|(key, current)| {
            if key == name {
                if found {
                    return None;
                }
                found = true;
                Some((key.into_owned(), value.to_owned()))
            } else {
                Some((key.into_owned(), current.into_owned()))
            }
        })
        .collect::<Vec<_>>();
    if !found {
        pairs.push((name.into(), value.into()));
    }
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(pairs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_preserve_existing_positions_and_protect_state() {
        let url = build(Input {
            endpoint: "https://idp.example.com/authorize?tenant=one&client_id=old",
            client_id: "client",
            state: "state",
            scopes: &["openid".into(), "email".into()],
            redirect_uri: "https://app.example.com/api/auth/sso/callback/acme",
            login_hint: Some("user@example.com"),
            code_verifier: None,
            additional: &[("tenant".into(), "two".into())],
        })
        .unwrap();
        assert_eq!(
            url,
            "https://idp.example.com/authorize?tenant=two&client_id=client&response_type=code&state=state&scope=openid+email&redirect_uri=https%3A%2F%2Fapp.example.com%2Fapi%2Fauth%2Fsso%2Fcallback%2Facme&login_hint=user%40example.com"
        );
    }
}
