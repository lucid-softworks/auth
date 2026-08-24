use super::{
    BuiltinProviderKind as Kind, OAuthProviderConfig, OidcConfig, ProfileMap, TokenEndpointAuth,
};
use chrono::Duration;

struct ProviderSpec {
    name: &'static str,
    authorization: &'static str,
    token: &'static str,
    user_info: Option<&'static str>,
    issuer: Option<&'static str>,
    scopes: &'static [&'static str],
    subject: &'static [&'static str],
    email: &'static [&'static str],
    name_fields: &'static [&'static str],
    image: &'static [&'static str],
    verified: &'static [&'static str],
    root: Option<&'static str>,
    synthetic_email: Option<&'static str>,
}

pub(super) fn provider_config(
    kind: Kind,
    client_id: String,
    client_secret: Option<String>,
) -> OAuthProviderConfig {
    let spec = provider_spec(kind);
    let issuer = spec.issuer.map(str::to_owned);
    OAuthProviderConfig {
        id: kind.id().into(),
        name: spec.name.into(),
        client_id: client_id.clone(),
        client_secret,
        authorization_endpoint: spec.authorization.into(),
        token_endpoint: spec.token.into(),
        user_info_endpoint: spec.user_info.map(str::to_owned),
        issuer: issuer.clone(),
        scopes: strings(spec.scopes),
        token_endpoint_auth: token_auth(kind),
        authorization_client_id_parameter: client_parameter(kind).into(),
        token_client_id_parameter: client_parameter(kind).into(),
        scope_separator: scope_separator(kind).into(),
        use_pkce: uses_pkce(kind),
        send_code_verifier: sends_code_verifier(kind),
        response_type: if kind == Kind::Apple {
            "code id_token"
        } else {
            "code"
        }
        .into(),
        response_mode: (kind == Kind::Apple).then(|| "form_post".into()),
        oidc: oidc(kind, &client_id, issuer.as_deref()),
        profile: profile_map(kind, &spec),
        disable_implicit_sign_up: false,
        disable_sign_up: false,
        require_email_verification: false,
        hosted_domain: None,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn profile_map(kind: Kind, spec: &ProviderSpec) -> ProfileMap {
    ProfileMap {
        subject: strings(spec.subject),
        issuer: if kind == Kind::Microsoft {
            vec!["/iss".into()]
        } else {
            Vec::new()
        },
        email: strings(spec.email),
        name: strings(spec.name_fields),
        image: strings(spec.image),
        email_verified: strings(spec.verified),
        profile_root: spec.root.map(str::to_owned),
        synthetic_email_domain: spec.synthetic_email.map(str::to_owned),
        join_name_fields: matches!(kind, Kind::Vk | Kind::Zoom),
        require_all_email_verified_fields: kind == Kind::Kakao,
    }
}

fn client_parameter(kind: Kind) -> &'static str {
    match kind {
        Kind::Tiktok => "client_key",
        Kind::Wechat => "appid",
        _ => "client_id",
    }
}

fn scope_separator(kind: Kind) -> &'static str {
    if matches!(kind, Kind::Tiktok | Kind::Wechat) {
        ","
    } else {
        " "
    }
}

fn uses_pkce(kind: Kind) -> bool {
    !matches!(
        kind,
        Kind::Discord
            | Kind::Facebook
            | Kind::Kakao
            | Kind::Linear
            | Kind::Linkedin
            | Kind::Naver
            | Kind::Notion
            | Kind::Reddit
            | Kind::Roblox
            | Kind::Slack
            | Kind::Tiktok
            | Kind::Twitch
            | Kind::Wechat
    )
}

fn sends_code_verifier(kind: Kind) -> bool {
    uses_pkce(kind) && kind != Kind::Paypal
}

fn token_auth(kind: Kind) -> TokenEndpointAuth {
    if matches!(
        kind,
        Kind::Figma | Kind::Notion | Kind::Paypal | Kind::Railway | Kind::Reddit | Kind::Twitter
    ) {
        TokenEndpointAuth::ClientSecretBasic
    } else {
        TokenEndpointAuth::ClientSecretPost
    }
}

fn oidc(kind: Kind, client_id: &str, issuer: Option<&str>) -> Option<OidcConfig> {
    let (jwks, issuers, nonce_fallback, dynamic) = match kind {
        Kind::Apple => (
            "https://appleid.apple.com/auth/keys",
            vec!["https://appleid.apple.com".into()],
            true,
            None,
        ),
        Kind::Facebook => (
            "https://limited.facebook.com/.well-known/oauth/openid/jwks/",
            vec!["https://www.facebook.com".into()],
            false,
            None,
        ),
        Kind::Google => (
            "https://www.googleapis.com/oauth2/v3/certs",
            vec![
                "https://accounts.google.com".into(),
                "accounts.google.com".into(),
            ],
            false,
            None,
        ),
        Kind::Microsoft => (
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            Vec::new(),
            false,
            Some("https://login.microsoftonline.com/{tid}/v2.0".into()),
        ),
        Kind::Paybin => (
            "https://idp.paybin.io/.well-known/jwks.json",
            vec!["https://idp.paybin.io".into()],
            false,
            None,
        ),
        Kind::Twitch => (
            "https://id.twitch.tv/oauth2/keys",
            vec!["https://id.twitch.tv/oauth2".into()],
            false,
            None,
        ),
        _ => return None,
    };
    Some(OidcConfig {
        jwks_url: jwks.into(),
        issuers: if kind == Kind::Google {
            issuers
        } else {
            issuer.map_or(issuers, |value| vec![value.into()])
        },
        audiences: vec![client_id.into()],
        algorithms: vec!["RS256".into()],
        requires_nonce: false,
        nonce_sha256_fallback: nonce_fallback,
        maximum_age: Some(Duration::hours(1)),
        dynamic_issuer_template: dynamic,
    })
}

macro_rules! spec {
    ($name:literal, $auth:literal, $token:literal, $user:expr, $issuer:expr, $scopes:expr, $subject:expr, $email:expr, $names:expr, $image:expr, $verified:expr, $root:expr, $synthetic:expr) => {
        ProviderSpec {
            name: $name,
            authorization: $auth,
            token: $token,
            user_info: $user,
            issuer: $issuer,
            scopes: $scopes,
            subject: $subject,
            email: $email,
            name_fields: $names,
            image: $image,
            verified: $verified,
            root: $root,
            synthetic_email: $synthetic,
        }
    };
}

#[rustfmt::skip]
fn provider_spec(kind: Kind) -> ProviderSpec {
    match kind {
        Kind::Apple => spec!("Apple", "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", None, Some("https://appleid.apple.com"), &["email", "name"], &["/sub"], &["/email"], &["/name"], &[], &["/email_verified"], None, None),
        Kind::Atlassian => spec!("Atlassian", "https://auth.atlassian.com/authorize", "https://auth.atlassian.com/oauth/token", Some("https://api.atlassian.com/me"), None, &["read:jira-user", "offline_access"], &["/account_id"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Cognito => spec!("Cognito", "https://CHANGE-ME.invalid/oauth2/authorize", "https://CHANGE-ME.invalid/oauth2/token", None, None, &["openid", "profile", "email"], &["/sub"], &["/email"], &["/name", "/given_name", "/username"], &["/picture"], &["/email_verified"], None, None),
        Kind::Discord => spec!("Discord", "https://discord.com/api/oauth2/authorize", "https://discord.com/api/oauth2/token", Some("https://discord.com/api/users/@me"), None, &["identify", "email"], &["/id"], &["/email"], &["/global_name", "/username"], &["/image_url"], &["/verified"], None, None),
        Kind::Dropbox => spec!("Dropbox", "https://www.dropbox.com/oauth2/authorize", "https://api.dropboxapi.com/oauth2/token", Some("https://api.dropboxapi.com/2/users/get_current_account"), None, &["account_info.read"], &["/account_id"], &["/email"], &["/name/display_name"], &["/profile_photo_url"], &["/email_verified"], None, None),
        Kind::Facebook => spec!("Facebook", "https://www.facebook.com/v24.0/dialog/oauth", "https://graph.facebook.com/v24.0/oauth/access_token", None, Some("https://www.facebook.com"), &["email", "public_profile"], &["/sub", "/id"], &["/email"], &["/name"], &["/picture/data/url", "/picture"], &["/email_verified"], None, None),
        Kind::Figma => spec!("Figma", "https://www.figma.com/oauth", "https://api.figma.com/v1/oauth/token", Some("https://api.figma.com/v1/me"), None, &["current_user:read"], &["/id"], &["/email"], &["/handle"], &["/img_url"], &[], None, None),
        Kind::Github => spec!("GitHub", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", Some("https://api.github.com/user"), None, &["read:user", "user:email"], &["/id"], &["/email"], &["/name", "/login"], &["/avatar_url"], &["/email_verified"], None, None),
        Kind::Gitlab => spec!("GitLab", "https://gitlab.com/oauth/authorize", "https://gitlab.com/oauth/token", Some("https://gitlab.com/api/v4/user"), None, &["read_user"], &["/id"], &["/email"], &["/name", "/username"], &["/avatar_url"], &["/email_verified"], None, None),
        Kind::Google => spec!("Google", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", None, Some("https://accounts.google.com"), &["email", "profile", "openid"], &["/sub"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Huggingface => spec!("Hugging Face", "https://huggingface.co/oauth/authorize", "https://huggingface.co/oauth/token", Some("https://huggingface.co/oauth/userinfo"), None, &["openid", "profile", "email"], &["/sub"], &["/email"], &["/name", "/preferred_username"], &["/picture"], &["/email_verified"], None, None),
        Kind::Kakao => spec!("Kakao", "https://kauth.kakao.com/oauth/authorize", "https://kauth.kakao.com/oauth/token", Some("https://kapi.kakao.com/v2/user/me"), None, &["account_email", "profile_image", "profile_nickname"], &["/id"], &["/kakao_account/email"], &["/kakao_account/profile/nickname", "/kakao_account/name"], &["/kakao_account/profile/profile_image_url"], &["/kakao_account/is_email_valid", "/kakao_account/is_email_verified"], None, None),
        Kind::Kick => spec!("Kick", "https://id.kick.com/oauth/authorize", "https://id.kick.com/oauth/token", Some("https://api.kick.com/public/v1/users"), None, &["user:read"], &["/user_id"], &["/email"], &["/name"], &["/profile_picture"], &[], Some("/data/0"), None),
        Kind::Line => spec!("LINE", "https://access.line.me/oauth2/v2.1/authorize", "https://api.line.me/oauth2/v2.1/token", Some("https://api.line.me/oauth2/v2.1/userinfo"), Some("https://access.line.me"), &["openid", "profile", "email"], &["/sub"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Linear => spec!("Linear", "https://linear.app/oauth/authorize", "https://api.linear.app/oauth/token", Some("https://api.linear.app/graphql"), None, &["read"], &["/id"], &["/email"], &["/name"], &["/avatarUrl"], &[], Some("/data/viewer"), None),
        Kind::Linkedin => spec!("Linkedin", "https://www.linkedin.com/oauth/v2/authorization", "https://www.linkedin.com/oauth/v2/accessToken", Some("https://api.linkedin.com/v2/userinfo"), None, &["profile", "email", "openid"], &["/sub"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Microsoft => spec!("Microsoft EntraID", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token", None, None, &["openid", "profile", "email", "User.Read", "offline_access"], &["/oid", "/sub"], &["/email", "/preferred_username"], &["/name"], &[], &["/email_verified"], None, None),
        Kind::Naver => spec!("Naver", "https://nid.naver.com/oauth2.0/authorize", "https://nid.naver.com/oauth2.0/token", Some("https://openapi.naver.com/v1/nid/me"), None, &["profile", "email"], &["/id"], &["/email"], &["/name", "/nickname"], &["/profile_image"], &[], Some("/response"), None),
        Kind::Notion => spec!("Notion", "https://api.notion.com/v1/oauth/authorize", "https://api.notion.com/v1/oauth/token", Some("https://api.notion.com/v1/users/me"), None, &[], &["/id"], &["/person/email"], &["/name"], &["/avatar_url"], &[], Some("/bot/owner/user"), None),
        Kind::Paybin => spec!("Paybin", "https://idp.paybin.io/authorize", "https://idp.paybin.io/token", None, Some("https://idp.paybin.io"), &["openid", "email", "profile"], &["/sub"], &["/email"], &["/name", "/preferred_username"], &["/picture"], &["/email_verified"], None, None),
        Kind::Paypal => spec!("PayPal", "https://www.paypal.com/signin/authorize", "https://api-m.paypal.com/v1/oauth2/token", Some("https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1"), None, &[], &["/user_id"], &["/emails/0/value"], &["/name"], &["/profile_photo_url"], &["/verified_account"], None, None),
        Kind::Polar => spec!("Polar", "https://polar.sh/oauth2/authorize", "https://api.polar.sh/v1/oauth2/token", Some("https://api.polar.sh/v1/oauth2/userinfo"), None, &["openid", "profile", "email"], &["/id"], &["/email"], &["/public_name", "/username"], &["/avatar_url"], &["/email_verified"], None, None),
        Kind::Railway => spec!("Railway", "https://backboard.railway.com/oauth/auth", "https://backboard.railway.com/oauth/token", Some("https://backboard.railway.com/oauth/me"), None, &["openid", "email", "profile"], &["/sub"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Reddit => spec!("Reddit", "https://www.reddit.com/api/v1/authorize", "https://www.reddit.com/api/v1/access_token", Some("https://oauth.reddit.com/api/v1/me"), None, &["identity"], &["/id"], &[], &["/name"], &["/icon_img"], &[], None, Some("reddit.invalid")),
        Kind::Roblox => spec!("Roblox", "https://apis.roblox.com/oauth/v1/authorize", "https://apis.roblox.com/oauth/v1/token", Some("https://apis.roblox.com/oauth/v1/userinfo"), None, &["openid", "profile"], &["/sub"], &["/preferred_username"], &["/nickname", "/preferred_username"], &["/picture"], &[], None, None),
        Kind::Salesforce => spec!("Salesforce", "https://login.salesforce.com/services/oauth2/authorize", "https://login.salesforce.com/services/oauth2/token", Some("https://login.salesforce.com/services/oauth2/userinfo"), None, &["openid", "email", "profile"], &["/user_id"], &["/email"], &["/name"], &["/picture"], &["/email_verified"], None, None),
        Kind::Slack => spec!("Slack", "https://slack.com/openid/connect/authorize", "https://slack.com/api/openid.connect.token", Some("https://slack.com/api/openid.connect.userInfo"), None, &["openid", "profile", "email"], &["/https:~1~1slack.com~1user_id", "/sub"], &["/email"], &["/name"], &["/picture", "/https:~1~1slack.com~1user_image_512"], &["/email_verified"], None, None),
        Kind::Spotify => spec!("Spotify", "https://accounts.spotify.com/authorize", "https://accounts.spotify.com/api/token", Some("https://api.spotify.com/v1/me"), None, &["user-read-email"], &["/id"], &["/email"], &["/display_name"], &["/images/0/url"], &[], None, None),
        Kind::Tiktok => spec!("TikTok", "https://www.tiktok.com/v2/auth/authorize", "https://open.tiktokapis.com/v2/oauth/token/", Some("https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,avatar_url_100,avatar_large_url,display_name,bio_description,profile_deep_link,is_verified,follower_count,following_count,likes_count,video_count,username,email"), None, &["user.info.profile"], &["/open_id"], &["/email", "/username"], &["/display_name", "/username"], &["/avatar_large_url"], &["/is_verified"], Some("/data/user"), None),
        Kind::Twitch => spec!("Twitch", "https://id.twitch.tv/oauth2/authorize", "https://id.twitch.tv/oauth2/token", None, Some("https://id.twitch.tv/oauth2"), &["user:read:email", "openid"], &["/sub"], &["/email"], &["/preferred_username"], &["/picture"], &["/email_verified"], None, None),
        Kind::Twitter => spec!("Twitter", "https://x.com/i/oauth2/authorize", "https://api.x.com/2/oauth2/token", Some("https://api.x.com/2/users/me?user.fields=profile_image_url"), None, &["users.read", "tweet.read", "offline.access", "users.email"], &["/id"], &["/email", "/username"], &["/name"], &["/profile_image_url"], &[], Some("/data"), None),
        Kind::Vercel => spec!("Vercel", "https://vercel.com/oauth/authorize", "https://api.vercel.com/login/oauth/token", Some("https://api.vercel.com/login/oauth/userinfo"), None, &[], &["/sub"], &["/email"], &["/name", "/preferred_username"], &["/picture"], &["/email_verified"], None, None),
        Kind::Vk => spec!("VK", "https://id.vk.com/authorize", "https://id.vk.com/oauth2/auth", Some("https://id.vk.com/oauth2/user_info"), None, &["email", "phone"], &["/user_id"], &["/email"], &["/first_name", "/last_name"], &["/avatar"], &[], Some("/user"), None),
        Kind::Wechat => spec!("WeChat", "https://open.weixin.qq.com/connect/qrconnect", "https://api.weixin.qq.com/sns/oauth2/access_token", Some("https://api.weixin.qq.com/sns/userinfo"), None, &["snsapi_login"], &["/unionid", "/openid"], &[], &["/nickname"], &["/headimgurl"], &[], None, Some("wechat.invalid")),
        Kind::Zoom => spec!("Zoom", "https://zoom.us/oauth/authorize", "https://zoom.us/oauth/token", Some("https://api.zoom.us/v2/users/me"), None, &[], &["/id"], &["/email"], &["/first_name", "/last_name", "/display_name"], &["/pic_url"], &["/verified"], None, None),
    }
}
