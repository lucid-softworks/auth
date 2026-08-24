use super::{
    AuthorizationRequest, BuiltinProvider, BuiltinProviderKind, OAuthTokens, OAuthUserInfo,
    SocialProvider,
};
use crate::AuthError;
use url::Url;

pub(super) fn authorization_url(
    provider: &BuiltinProvider,
    request: &AuthorizationRequest,
) -> Result<Url, AuthError> {
    let request = if matches!(
        provider.kind,
        BuiltinProviderKind::Paypal | BuiltinProviderKind::Zoom
    ) {
        let mut request = request.clone();
        request.scopes = None;
        request
    } else {
        request.clone()
    };
    let mut url = provider.config.create_authorization_url(&request)?;
    if provider.kind == BuiltinProviderKind::Google
        && !request.additional_params.contains_key("hd")
        && let Some(domain) = provider.config.hosted_domain.as_deref()
        && !domain.is_empty()
    {
        url.query_pairs_mut().append_pair("hd", domain);
    }
    if provider.kind == BuiltinProviderKind::Wechat {
        url.query_pairs_mut().append_pair("lang", "cn");
        url.set_fragment(Some("wechat_redirect"));
    }
    Ok(url)
}

pub(super) async fn exchange_code(
    provider: &BuiltinProvider,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    device_id: Option<&str>,
) -> Result<OAuthTokens, AuthError> {
    if provider.kind == BuiltinProviderKind::Wechat {
        let mut url =
            Url::parse(&provider.config.token_endpoint).map_err(|_| AuthError::OAuthInvalidCode)?;
        url.query_pairs_mut()
            .append_pair("appid", &provider.config.client_id)
            .append_pair(
                "secret",
                provider.config.client_secret.as_deref().unwrap_or_default(),
            )
            .append_pair("code", code)
            .append_pair("grant_type", "authorization_code");
        let value = fetch_json(reqwest::Client::new().get(url)).await?;
        if value.get("errcode").is_some() {
            return Err(AuthError::OAuthInvalidCode);
        }
        return super::parse_token_response(value);
    }
    provider
        .config
        .exchange_code(code, code_verifier, redirect_uri, device_id)
        .await
}

pub(super) async fn refresh_access_token(
    provider: &BuiltinProvider,
    refresh_token: &str,
) -> Result<OAuthTokens, AuthError> {
    if provider.kind == BuiltinProviderKind::Wechat {
        let mut url = Url::parse("https://api.weixin.qq.com/sns/oauth2/refresh_token")
            .map_err(|_| AuthError::OAuthFailedToRefreshToken)?;
        url.query_pairs_mut()
            .append_pair("appid", &provider.config.client_id)
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token);
        return super::parse_token_response(fetch_json(reqwest::Client::new().get(url)).await?)
            .map_err(|_| AuthError::OAuthFailedToRefreshToken);
    }
    provider.config.refresh_access_token(refresh_token).await
}

pub(super) async fn user_info(
    provider: &BuiltinProvider,
    tokens: &OAuthTokens,
    expected_nonce: Option<&str>,
    provider_user: Option<&serde_json::Value>,
) -> Result<OAuthUserInfo, AuthError> {
    if provider.kind == BuiltinProviderKind::Apple {
        return apple_user_info(provider, tokens, expected_nonce, provider_user).await;
    }
    if provider.kind == BuiltinProviderKind::Line
        && let Some(id_token) = tokens.id_token.as_deref()
    {
        let mut request = reqwest::Client::new()
            .post("https://api.line.me/oauth2/v2.1/verify")
            .query(&[
                ("id_token", id_token),
                ("client_id", &provider.config.client_id),
            ]);
        if let Some(nonce) = expected_nonce {
            request = request.query(&[("nonce", nonce)]);
        }
        return super::map_profile(&provider.config, fetch_json(request).await?);
    }
    if let Some(profile) = fetch_profile_override(provider, tokens).await? {
        return super::map_profile(&provider.config, profile);
    }
    let user_info = provider
        .config
        .get_user_info(tokens, expected_nonce, provider_user)
        .await?;
    if provider.kind == BuiltinProviderKind::Google
        && !super::google_id_token::hosted_domain_is_allowed(
            provider.config.hosted_domain.as_deref(),
            user_info
                .profile
                .get("hd")
                .and_then(serde_json::Value::as_str),
        )
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(user_info)
}

async fn apple_user_info(
    provider: &BuiltinProvider,
    tokens: &OAuthTokens,
    expected_nonce: Option<&str>,
    provider_user: Option<&serde_json::Value>,
) -> Result<OAuthUserInfo, AuthError> {
    let mut mapped = provider
        .config
        .get_user_info(tokens, expected_nonce, provider_user)
        .await?;
    if let Some(name) = provider_user.and_then(|user| user.get("name")) {
        let joined = ["firstName", "lastName"]
            .into_iter()
            .filter_map(|field| name.get(field).and_then(serde_json::Value::as_str))
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            mapped.name = joined;
        }
    }
    Ok(mapped)
}

async fn fetch_profile_override(
    provider: &BuiltinProvider,
    tokens: &OAuthTokens,
) -> Result<Option<serde_json::Value>, AuthError> {
    let access_token = match tokens.access_token.as_deref() {
        Some(token) => token,
        None => return Ok(None),
    };
    let client = reqwest::Client::new();
    let request = match provider.kind {
        BuiltinProviderKind::Dropbox => Some(
            client
                .post("https://api.dropboxapi.com/2/users/get_current_account")
                .bearer_auth(access_token),
        ),
        BuiltinProviderKind::Linear => Some(
            client
                .post("https://api.linear.app/graphql")
                .bearer_auth(access_token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(r#"{"query":"query { viewer { id name email avatarUrl active createdAt updatedAt } }"}"#),
        ),
        BuiltinProviderKind::Notion => Some(
            client
                .get("https://api.notion.com/v1/users/me")
                .bearer_auth(access_token)
                .header("Notion-Version", "2022-06-28"),
        ),
        BuiltinProviderKind::Vk => Some(vk_request(&client, provider, access_token)),
        BuiltinProviderKind::Wechat => Some(wechat_request(&client, tokens, access_token)?),
        BuiltinProviderKind::Github => {
            return github_profile(&client, access_token).await.map(Some);
        }
        BuiltinProviderKind::Facebook => {
            return facebook_profile(&client, provider, access_token)
                .await
                .map(Some);
        }
        _ => None,
    };
    match request {
        Some(request) => fetch_json(request).await.map(Some),
        None => Ok(None),
    }
}

fn vk_request(
    client: &reqwest::Client,
    provider: &BuiltinProvider,
    access_token: &str,
) -> reqwest::RequestBuilder {
    client
        .post("https://id.vk.com/oauth2/user_info")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("access_token", access_token)
                .append_pair("client_id", &provider.config.client_id)
                .finish(),
        )
}

fn wechat_request(
    client: &reqwest::Client,
    tokens: &OAuthTokens,
    access_token: &str,
) -> Result<reqwest::RequestBuilder, AuthError> {
    let openid = tokens
        .extra
        .get("openid")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    Ok(client
        .get("https://api.weixin.qq.com/sns/userinfo")
        .query(&[
            ("access_token", access_token),
            ("openid", openid),
            ("lang", "zh_CN"),
        ]))
}

async fn github_profile(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<serde_json::Value, AuthError> {
    let mut profile = fetch_json(
        client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, "lucid-auth"),
    )
    .await?;
    let emails = fetch_json(
        client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, "lucid-auth"),
    )
    .await
    .ok()
    .and_then(|value| value.as_array().cloned())
    .unwrap_or_default();
    apply_github_email(&mut profile, &emails)?;
    Ok(profile)
}

fn apply_github_email(
    profile: &mut serde_json::Value,
    emails: &[serde_json::Value],
) -> Result<(), AuthError> {
    let selected = emails
        .iter()
        .find(|email| email.get("primary").and_then(serde_json::Value::as_bool) == Some(true))
        .or_else(|| emails.first());
    let object = profile
        .as_object_mut()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    if object.get("email").is_none_or(serde_json::Value::is_null)
        && let Some(email) = selected.and_then(|email| email.get("email")).cloned()
    {
        object.insert("email".into(), email);
    }
    let selected_email = object.get("email").and_then(serde_json::Value::as_str);
    let verified = emails.iter().any(|email| {
        email.get("email").and_then(serde_json::Value::as_str) == selected_email
            && email.get("verified").and_then(serde_json::Value::as_bool) == Some(true)
    });
    object.insert("email_verified".into(), verified.into());
    Ok(())
}

async fn facebook_profile(
    client: &reqwest::Client,
    provider: &BuiltinProvider,
    access_token: &str,
) -> Result<serde_json::Value, AuthError> {
    let app_token = format!(
        "{}|{}",
        provider.config.client_id,
        provider.config.client_secret.as_deref().unwrap_or_default()
    );
    let inspection = fetch_json(
        client
            .get("https://graph.facebook.com/debug_token")
            .query(&[
                ("input_token", access_token),
                ("access_token", app_token.as_str()),
            ]),
    )
    .await?;
    let inspected = inspection.get("data").ok_or(AuthError::OAuthInvalidToken)?;
    if inspected
        .get("is_valid")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || inspected.get("app_id").and_then(serde_json::Value::as_str)
            != Some(provider.config.client_id.as_str())
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    let profile = fetch_json(
        client
            .get("https://graph.facebook.com/me?fields=id,name,email,picture")
            .bearer_auth(access_token),
    )
    .await?;
    if profile.get("id").and_then(serde_json::Value::as_str)
        != inspected.get("user_id").and_then(serde_json::Value::as_str)
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(profile)
}

async fn fetch_json(request: reqwest::RequestBuilder) -> Result<serde_json::Value, AuthError> {
    let response = request
        .send()
        .await
        .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
    if !response.status().is_success() {
        return Err(AuthError::OAuthUserInfoUnavailable);
    }
    response
        .json()
        .await
        .map_err(|_| AuthError::OAuthUserInfoUnavailable)
}
