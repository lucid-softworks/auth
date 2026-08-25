use crate::VerificationValue;

const PREFIXES: &[&str] = &[
    "email-verification-otp-",
    "sign-in-otp-",
    "forget-password-otp-",
    "phone-verification-otp-",
];

pub(super) fn capture(verification: &VerificationValue) -> Option<(String, String)> {
    let value = verification.payload_string()?;
    let otp = value.split(':').next()?.to_owned();
    if otp.is_empty() || verification.identifier.is_empty() {
        return None;
    }
    let purpose_prefix = format!("{}:", verification.purpose);
    let mut identifier = verification
        .identifier
        .strip_prefix(&purpose_prefix)
        .unwrap_or(&verification.identifier);
    for prefix in PREFIXES {
        if let Some(stripped) = identifier.strip_prefix(prefix) {
            identifier = stripped;
            break;
        }
    }
    Some((identifier.to_owned(), otp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn projects_payload_before_splitting_and_strips_one_prefix() {
        let verification = VerificationValue {
            purpose: "email-otp".into(),
            identifier: "email-otp:sign-in-otp-user@example.com".into(),
            payload: json!({ "otp": "123456", "attempts": 2 }),
            additional_fields: serde_json::Map::new(),
            expires_at: Utc::now(),
            created_at: Utc::now(),
        };
        assert_eq!(
            capture(&verification),
            Some(("user@example.com".into(), "123456".into()))
        );
    }
}
