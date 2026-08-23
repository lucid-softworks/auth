use super::{BuiltinProvider, BuiltinProviderKind as Kind};
use serde_json::json;

const HTTPS_SCHEME: &str = "https://";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const MICROSOFT_ISSUER: &str = "https://login.microsoftonline.com/tenant/v2.0";
const SLACK_USER_ID: &str = "https://slack.com/user_id";

#[test]
fn catalog_matches_better_auth_provider_vocabulary() {
    assert_eq!(Kind::ALL.len(), 35);
    assert_eq!(
        Kind::ALL.map(Kind::id),
        [
            "apple",
            "atlassian",
            "cognito",
            "discord",
            "dropbox",
            "facebook",
            "figma",
            "github",
            "gitlab",
            "google",
            "huggingface",
            "kakao",
            "kick",
            "line",
            "linear",
            "linkedin",
            "microsoft",
            "naver",
            "notion",
            "paybin",
            "paypal",
            "polar",
            "railway",
            "reddit",
            "roblox",
            "salesforce",
            "slack",
            "spotify",
            "tiktok",
            "twitch",
            "twitter",
            "vercel",
            "vk",
            "wechat",
            "zoom",
        ]
    );
}

#[test]
fn every_builtin_has_complete_native_metadata() {
    for kind in Kind::ALL {
        let provider = BuiltinProvider::new(kind, "client", "secret");
        assert_eq!(provider.config.id, kind.id());
        assert!(!provider.config.name.is_empty());
        assert!(
            provider
                .config
                .authorization_endpoint
                .starts_with(HTTPS_SCHEME)
        );
        assert!(provider.config.token_endpoint.starts_with(HTTPS_SCHEME));
        assert!(!provider.config.profile.subject.is_empty());
    }
}

fn profile(kind: Kind, value: serde_json::Value) -> super::OAuthUserInfo {
    BuiltinProvider::new(kind, "client", "secret")
        .map_profile_fixture(value)
        .unwrap()
}

#[test]
fn common_provider_profile_fixtures_match_better_auth() {
    let google = profile(
        Kind::Google,
        json!({"sub":"g1","iss":GOOGLE_ISSUER,"email":"g@example.com","email_verified":true,"name":"G","picture":"g.png"}),
    );
    assert_eq!(
        (google.account_id.as_str(), google.email_verified),
        ("g1", true)
    );

    let github = profile(
        Kind::Github,
        json!({"id":42,"login":"octo","email":"o@example.com","email_verified":true,"avatar_url":"o.png"}),
    );
    assert_eq!(
        (github.account_id.as_str(), github.name.as_str()),
        ("42", "octo")
    );

    let dropbox = profile(
        Kind::Dropbox,
        json!({"account_id":"db1","name":{"display_name":"D B"},"email":"d@example.com","email_verified":true,"profile_photo_url":"d.png"}),
    );
    assert_eq!(
        (dropbox.name.as_str(), dropbox.image.as_deref()),
        ("D B", Some("d.png"))
    );

    let kakao = profile(
        Kind::Kakao,
        json!({"id":7,"kakao_account":{"email":"k@example.com","is_email_valid":true,"is_email_verified":true,"profile":{"nickname":"K","profile_image_url":"k.png"}}}),
    );
    assert!(kakao.email_verified);
}

#[test]
fn nested_provider_profile_fixtures_match_better_auth() {
    let kick = profile(
        Kind::Kick,
        json!({"data":[{"user_id":9,"name":"K","email":"k@example.com","profile_picture":"k.png"}]}),
    );
    assert_eq!(kick.account_id, "9");

    let linear = profile(
        Kind::Linear,
        json!({"data":{"viewer":{"id":"l1","name":"L","email":"l@example.com","avatarUrl":"l.png"}}}),
    );
    assert_eq!(linear.name, "L");

    let notion = profile(
        Kind::Notion,
        json!({"bot":{"owner":{"user":{"id":"n1","name":"N","person":{"email":"n@example.com"},"avatar_url":"n.png"}}}}),
    );
    assert_eq!(notion.email, "n@example.com");

    let naver = profile(
        Kind::Naver,
        json!({"response":{"id":"nv1","nickname":"NV","email":"nv@example.com","profile_image":"nv.png"}}),
    );
    assert_eq!(naver.account_id, "nv1");

    let tiktok = profile(
        Kind::Tiktok,
        json!({"data":{"user":{"open_id":"tt1","username":"tt","display_name":"Tik Tok","email":"tt@example.com","avatar_large_url":"tt.png"}}}),
    );
    assert_eq!(tiktok.name, "Tik Tok");
}

#[test]
fn special_provider_profile_fixtures_match_better_auth() {
    let vk = profile(
        Kind::Vk,
        json!({"user":{"user_id":"vk1","first_name":"V","last_name":"K","email":"vk@example.com","avatar":"vk.png"}}),
    );
    assert_eq!(vk.name, "V K");

    let slack = profile(
        Kind::Slack,
        json!({(SLACK_USER_ID):"s1","email":"s@example.com","email_verified":true,"name":"S","picture":"s.png"}),
    );
    assert_eq!(slack.account_id, "s1");

    let microsoft = profile(
        Kind::Microsoft,
        json!({"oid":"m1","iss":MICROSOFT_ISSUER,"preferred_username":"m@example.com","name":"M"}),
    );
    assert_eq!(microsoft.issuer, MICROSOFT_ISSUER);

    let zoom = profile(
        Kind::Zoom,
        json!({"id":"z1","first_name":"Z","last_name":"M","email":"z@example.com","verified":1}),
    );
    assert_eq!(zoom.name, "Z M");
}

#[test]
fn providers_without_email_use_better_auth_synthetic_domains() {
    let reddit = profile(
        Kind::Reddit,
        json!({"id":"r1","name":"redditor","icon_img":"r.png"}),
    );
    assert_eq!(reddit.email, "r1@reddit.invalid");
    let wechat = profile(
        Kind::Wechat,
        json!({"openid":"w1","nickname":"W","headimgurl":"w.png"}),
    );
    assert_eq!(wechat.email, "w1@wechat.invalid");
}
