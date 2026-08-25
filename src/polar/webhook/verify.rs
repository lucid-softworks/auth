use super::{PolarWebhookError, PolarWebhookEvent};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const TOLERANCE_SECONDS: i64 = 300;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolarWebhookHeaders {
    pub webhook_id: Option<String>,
    pub webhook_timestamp: Option<String>,
    pub webhook_signature: Option<String>,
}

impl PolarWebhookHeaders {
    pub fn new(
        webhook_id: impl Into<String>,
        webhook_timestamp: impl Into<String>,
        webhook_signature: impl Into<String>,
    ) -> Self {
        Self {
            webhook_id: Some(webhook_id.into()),
            webhook_timestamp: Some(webhook_timestamp.into()),
            webhook_signature: Some(webhook_signature.into()),
        }
    }
}

pub fn verify_webhook(
    body_text: &str,
    headers: &PolarWebhookHeaders,
    secret: &str,
) -> Result<PolarWebhookEvent, PolarWebhookError> {
    verify_webhook_at(body_text, headers, secret, chrono::Utc::now().timestamp())
}

pub fn verify_webhook_at(
    body_text: &str,
    headers: &PolarWebhookHeaders,
    secret: &str,
    now_seconds: i64,
) -> Result<PolarWebhookEvent, PolarWebhookError> {
    let id = required(&headers.webhook_id, "webhook-id")?;
    let timestamp_text = required(&headers.webhook_timestamp, "webhook-timestamp")?;
    let signatures = required(&headers.webhook_signature, "webhook-signature")?;
    let timestamp = parse_int(timestamp_text).ok_or(PolarWebhookError::InvalidTimestamp)?;
    if now_seconds.saturating_sub(timestamp) > TOLERANCE_SECONDS {
        return Err(PolarWebhookError::TimestampTooOld);
    }
    if timestamp.saturating_sub(now_seconds) > TOLERANCE_SECONDS {
        return Err(PolarWebhookError::TimestampTooNew);
    }

    let message = format!("{id}.{timestamp}.{body_text}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of every size");
    mac.update(message.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    let matching = signatures
        .split(' ')
        .filter_map(signature_v1)
        .any(|candidate| constant_time_equal(candidate.as_bytes(), expected.as_bytes()));
    if !matching {
        return Err(PolarWebhookError::InvalidSignature);
    }

    let value = serde_json::from_str(body_text).map_err(|_| PolarWebhookError::InvalidPayload)?;
    PolarWebhookEvent::parse(value)
}

fn required<'a>(
    value: &'a Option<String>,
    name: &'static str,
) -> Result<&'a str, PolarWebhookError> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(PolarWebhookError::MissingHeader(name))
}

fn parse_int(value: &str) -> Option<i64> {
    let value = value.trim_start();
    let (negative, value) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let digits = value
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    let parsed = std::str::from_utf8(&digits).ok()?.parse::<i64>().ok()?;
    negative.then_some(-parsed).or(Some(parsed))
}

fn signature_v1(value: &str) -> Option<&str> {
    let mut parts = value.split(',');
    let version = parts.next()?;
    let signature = parts.next()?;
    (version == "v1" && !signature.is_empty()).then_some(signature)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_BODY: &str = concat!(
        "{\"type\":\"member.created\",",
        "\"timestamp\":\"2025-01-01T00:00:00Z\",",
        "\"data\":{\"id\":\"member_1\",",
        "\"created_at\":\"2025-01-01T00:00:00Z\",",
        "\"modified_at\":null,\"customer_id\":\"customer_1\",",
        "\"email\":\"member@example.com\",\"name\":null,",
        "\"external_id\":null,\"role\":\"member\"}}"
    );

    fn signed(body: &str, secret: &str, timestamp: &str) -> PolarWebhookHeaders {
        let id = "evt_123";
        let parsed = parse_int(timestamp).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{id}.{parsed}.{body}").as_bytes());
        let signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        PolarWebhookHeaders::new(id, timestamp, format!("v2,bogus v1,{signature}"))
    }

    #[test]
    fn verifies_literal_secret_raw_text_multiple_signatures_and_parse_int_timestamp() {
        let body = format!(" {VALID_BODY}\n");
        let headers = signed(&body, "whsec_literal", " 1700000000suffix");
        let event = verify_webhook_at(&body, &headers, "whsec_literal", 1_700_000_300).unwrap();
        assert_eq!(event.event_type.as_str(), "member.created");
    }

    #[test]
    fn applies_exact_tolerance_and_rejects_invalid_inputs_before_json() {
        let body = "not json";
        assert!(verify_webhook_at(body, &signed(body, "s", "1000"), "s", 1300).is_err());
        assert_eq!(
            verify_webhook_at(body, &signed(body, "s", "1000"), "s", 1301),
            Err(PolarWebhookError::TimestampTooOld)
        );
        assert_eq!(
            verify_webhook_at(body, &signed(body, "s", "1601"), "s", 1300),
            Err(PolarWebhookError::TimestampTooNew)
        );
        assert_eq!(
            verify_webhook_at("{}", &PolarWebhookHeaders::default(), "s", 0),
            Err(PolarWebhookError::MissingHeader("webhook-id"))
        );
    }

    #[test]
    fn rejects_wrong_secret_and_unsupported_signature_versions() {
        let body = VALID_BODY;
        let mut headers = signed(body, "right", "1000");
        assert_eq!(
            verify_webhook_at(body, &headers, "wrong", 1000),
            Err(PolarWebhookError::InvalidSignature)
        );
        headers.webhook_signature = Some("v2,only".into());
        assert_eq!(
            verify_webhook_at(body, &headers, "right", 1000),
            Err(PolarWebhookError::InvalidSignature)
        );
    }

    #[test]
    fn standard_webhooks_ignores_signature_segments_after_the_second() {
        let body = VALID_BODY;
        let mut headers = signed(body, "right", "1000");
        headers.webhook_signature = headers
            .webhook_signature
            .map(|signature| format!("{signature},ignored"));
        verify_webhook_at(body, &headers, "right", 1000).unwrap();
    }
}
