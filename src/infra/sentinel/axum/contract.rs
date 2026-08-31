use axum::http::Method;
use serde_json::Value;

const CALLBACK_GET_ROUTES: &[&str] = &["/callback/:id", "/oauth2/callback/:providerId"];
const PROTECTED_ROUTES: &[&str] = &[
    "/sign-in/email",
    "/sign-in/username",
    "/sign-in/email-otp",
    "/sign-in/social",
    "/sign-in/passkey",
    "/sign-in/magic-link",
    "/sign-in/sso",
    "/sign-in/anonymous",
    "/sign-up/email",
    "/forget-password",
    "/request-password-reset",
    "/reset-password",
    "/two-factor/verify-totp",
    "/two-factor/verify-backup-code",
    "/two-factor/verify-otp",
    "/email-otp/send-verification-otp",
    "/phone-number/send-otp",
    "/magic-link/verify",
    "/organization/create",
    "/change-email",
    "/change-password",
    "/set-password",
    "/link-social",
    "/passkey/add-passkey",
];
const BREACHED_PASSWORD_ROUTES: &[&str] = &[
    "/sign-up/email",
    "/change-password",
    "/set-password",
    "/reset-password",
];
const PASSWORD_SIGN_IN_ROUTES: &[&str] = &[
    "/sign-in/email",
    "/sign-in/username",
    "/sign-in/email-otp",
];

pub(super) fn should_identify(method: &Method, path: &str) -> bool {
    method != Method::GET || matches_any_route(path, CALLBACK_GET_ROUTES)
}

pub(super) fn is_dash_route(path: &str) -> bool {
    path == "/dash" || path.starts_with("/dash/")
}

pub(super) fn is_protected(path: &str) -> bool {
    matches_any_route(path, PROTECTED_ROUTES)
}

pub(super) fn checks_breached_password(path: &str) -> bool {
    matches_any_route(path, BREACHED_PASSWORD_ROUTES)
}

pub(super) fn is_password_sign_in(path: &str) -> bool {
    matches_any_route(path, PASSWORD_SIGN_IN_ROUTES)
}

fn matches_any_route(path: &str, routes: &[&str]) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    routes.iter().any(|route| {
        let route_parts: Vec<_> = route.split('/').collect();
        let path_parts: Vec<_> = path.split('/').collect();
        path_parts.len() >= route_parts.len()
            && path_parts
                .iter()
                .zip(route_parts)
                .all(|(actual, expected)| expected.starts_with(':') || actual == &expected)
    })
}

pub(super) fn request_identifier(body: Option<&Value>) -> Option<String> {
    body.and_then(|body| {
        ["email", "phone", "username"]
            .into_iter()
            .find_map(|field| string_field(body, field).map(str::to_owned))
    })
}

pub(super) fn login_identifier<'a>(path: &str, body: &'a Value) -> Option<&'a str> {
    if matches_any_route(path, &["/sign-in/username"]) {
        string_field(body, "username")
    } else {
        string_field(body, "email")
    }
}

pub(super) fn password_to_check(body: Option<&Value>) -> Option<&str> {
    body.and_then(|body| {
        string_field(body, "newPassword").or_else(|| string_field(body, "password"))
    })
}

pub(super) fn string_field<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub(super) fn block_message(reason: Option<&str>) -> &'static str {
    match reason {
        Some("geo_blocked") => "Access from your location is not allowed.",
        Some("bot_detected") => "Automated access is not allowed.",
        Some("suspicious_ip_detected") => {
            "Anonymous connections (VPN, proxy, Tor) are not allowed."
        }
        Some("rate_limited") => "Too many attempts. Please try again later.",
        Some("compromised_password") => {
            "This password has been found in data breaches. Please choose a different password."
        }
        Some("impossible_travel") => "Login blocked due to suspicious location change.",
        _ => "Access denied.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_only_the_published_route_boundaries() {
        assert!(is_protected("/sign-in/email"));
        assert!(is_protected("/sign-in/email/extra"));
        assert!(!is_protected("/sign-in/emailish"));
        assert!(should_identify(&Method::GET, "/callback/github"));
        assert!(!should_identify(&Method::GET, "/session"));
        assert!(should_identify(&Method::POST, "/session"));
        assert!(is_dash_route("/dash/users"));
    }

    #[test]
    fn extracts_published_identifier_and_password_precedence() {
        let body = json!({
            "email": "person@example.com",
            "username": "person",
            "password": "old",
            "newPassword": "new"
        });
        assert_eq!(request_identifier(Some(&body)).as_deref(), Some("person@example.com"));
        assert_eq!(password_to_check(Some(&body)), Some("new"));
    }

    #[test]
    fn maps_exact_block_messages() {
        assert_eq!(block_message(Some("bot_detected")), "Automated access is not allowed.");
        assert_eq!(block_message(Some("unknown")), "Access denied.");
    }
}
