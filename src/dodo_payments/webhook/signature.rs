use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "whsec_";
const TOLERANCE_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DodoWebhookSignatureError {
    #[error("Secret can't be empty.")]
    EmptySecret,
    #[error("Invalid webhook secret")]
    InvalidSecret,
    #[error("Missing required headers")]
    MissingHeaders,
    #[error("Invalid Signature Headers")]
    InvalidTimestamp,
    #[error("Message timestamp too old")]
    TimestampTooOld,
    #[error("Message timestamp too new")]
    TimestampTooNew,
    #[error("No matching signature found")]
    NoMatchingSignature,
}

pub fn validate_dodo_webhook_signature(
    body: &str,
    webhook_id: Option<&str>,
    webhook_timestamp: Option<&str>,
    webhook_signature: Option<&str>,
    secret: &str,
) -> Result<(), DodoWebhookSignatureError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    validate_at(
        body,
        webhook_id,
        webhook_timestamp,
        webhook_signature,
        secret,
        now,
    )
}

fn validate_at(
    body: &str,
    webhook_id: Option<&str>,
    webhook_timestamp: Option<&str>,
    webhook_signature: Option<&str>,
    secret: &str,
    now: i64,
) -> Result<(), DodoWebhookSignatureError> {
    let key = decode_secret(secret)?;
    let (Some(webhook_id), Some(timestamp), Some(signatures)) =
        (webhook_id, webhook_timestamp, webhook_signature)
    else {
        return Err(DodoWebhookSignatureError::MissingHeaders);
    };
    if webhook_id.is_empty() || timestamp.is_empty() || signatures.is_empty() {
        return Err(DodoWebhookSignatureError::MissingHeaders);
    }
    let timestamp =
        parse_int_prefix(timestamp).ok_or(DodoWebhookSignatureError::InvalidTimestamp)?;
    if now - timestamp > TOLERANCE_SECONDS {
        return Err(DodoWebhookSignatureError::TimestampTooOld);
    }
    if timestamp > now + TOLERANCE_SECONDS {
        return Err(DodoWebhookSignatureError::TimestampTooNew);
    }

    let message = format!("{webhook_id}.{timestamp}.{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| DodoWebhookSignatureError::InvalidSecret)?;
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    for candidate in signatures.split(' ') {
        let mut parts = candidate.split(',');
        let (Some("v1"), Some(signature)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(signature) = STANDARD.decode(signature) else {
            continue;
        };
        let mut verifier = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|_| DodoWebhookSignatureError::InvalidSecret)?;
        verifier.update(message.as_bytes());
        if verifier.verify_slice(&signature).is_ok() && signature.as_slice() == expected.as_slice()
        {
            return Ok(());
        }
    }
    Err(DodoWebhookSignatureError::NoMatchingSignature)
}

pub fn sign_dodo_webhook(
    body: &str,
    webhook_id: &str,
    timestamp: i64,
    secret: &str,
) -> Result<String, DodoWebhookSignatureError> {
    let key = decode_secret(secret)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| DodoWebhookSignatureError::InvalidSecret)?;
    mac.update(format!("{webhook_id}.{timestamp}.{body}").as_bytes());
    Ok(format!(
        "v1,{}",
        STANDARD.encode(mac.finalize().into_bytes())
    ))
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, DodoWebhookSignatureError> {
    if secret.is_empty() {
        return Err(DodoWebhookSignatureError::EmptySecret);
    }
    let secret = secret.strip_prefix(PREFIX).unwrap_or(secret);
    STANDARD
        .decode(secret)
        .map_err(|_| DodoWebhookSignatureError::InvalidSecret)
}

fn parse_int_prefix(value: &str) -> Option<i64> {
    let value = value.trim_start();
    let end = value
        .char_indices()
        .take_while(|(index, character)| {
            character.is_ascii_digit() || (*index == 0 && matches!(character, '+' | '-'))
        })
        .last()
        .map_or(0, |(index, character)| index + character.len_utf8());
    (end > 0).then(|| value[..end].parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_SECRET: &[u8] = b"dodo webhook test secret";

    fn secret() -> String {
        format!("whsec_{}", STANDARD.encode(RAW_SECRET))
    }

    #[test]
    fn standard_webhook_profile_accepts_any_matching_v1_candidate() {
        let signature = sign_dodo_webhook("{\"ok\":true}", "msg_1", 1_000, &secret()).unwrap();
        validate_at(
            "{\"ok\":true}",
            Some("msg_1"),
            Some("1000"),
            Some(&format!("v2,ignored {signature}")),
            &secret(),
            1_000,
        )
        .unwrap();

        validate_at(
            "{\"ok\":true}",
            Some("msg_1"),
            Some("1000"),
            Some(&format!("{signature},ignored")),
            &secret(),
            1_000,
        )
        .unwrap();
    }

    #[test]
    fn five_minute_boundaries_are_inclusive() {
        for timestamp in [700, 1_300] {
            let signature = sign_dodo_webhook("{}", "msg", timestamp, &secret()).unwrap();
            validate_at(
                "{}",
                Some("msg"),
                Some(&timestamp.to_string()),
                Some(&signature),
                &secret(),
                1_000,
            )
            .unwrap();
        }
        assert_eq!(
            validate_at(
                "{}",
                Some("msg"),
                Some("699"),
                Some("v1,x"),
                &secret(),
                1_000
            ),
            Err(DodoWebhookSignatureError::TimestampTooOld)
        );
        assert_eq!(
            validate_at(
                "{}",
                Some("msg"),
                Some("1301"),
                Some("v1,x"),
                &secret(),
                1_000
            ),
            Err(DodoWebhookSignatureError::TimestampTooNew)
        );
    }

    #[test]
    fn parse_int_timestamp_matches_standard_webhooks() {
        let signature = sign_dodo_webhook("{}", "msg", 1_000, &secret()).unwrap();
        validate_at(
            "{}",
            Some("msg"),
            Some("1000suffix"),
            Some(&signature),
            &secret(),
            1_000,
        )
        .unwrap();
    }

    #[test]
    fn standard_webhooks_rejects_unpadded_secrets() {
        assert_eq!(
            validate_at(
                "{}",
                Some("msg"),
                Some("1000"),
                Some("v1,x"),
                "whsec_Zg",
                1_000
            ),
            Err(DodoWebhookSignatureError::InvalidSecret)
        );
    }
}
