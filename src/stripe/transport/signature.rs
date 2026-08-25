use super::{StripeEvent, StripeProviderError};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const DEFAULT_TOLERANCE_SECONDS: i64 = 300;

pub(super) fn construct_event(
    payload: &[u8],
    signature_header: &str,
    secret: &str,
) -> Result<StripeEvent, StripeProviderError> {
    let (timestamp, signatures) = parse_header(signature_header)?;
    if Utc::now().timestamp() - timestamp > DEFAULT_TOLERANCE_SECONDS {
        return Err(StripeProviderError::transport(
            "Timestamp outside the tolerance zone",
        ));
    }
    let mut signed_payload = timestamp.to_string().into_bytes();
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(payload);
    let verified = signatures.iter().any(|signature| {
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(&signed_payload);
        mac.verify_slice(&bytes).is_ok()
    });
    if !verified {
        return Err(StripeProviderError::transport(
            "No signatures found matching the expected signature for payload",
        ));
    }
    serde_json::from_slice(payload)
        .map_err(|error| StripeProviderError::transport(error.to_string()))
}

fn parse_header(header: &str) -> Result<(i64, Vec<&str>), StripeProviderError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for item in header.split(',') {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        match key {
            "t" => timestamp = value.parse().ok(),
            "v1" => signatures.push(value),
            _ => {}
        }
    }
    match (timestamp, signatures.is_empty()) {
        (Some(timestamp), false) => Ok((timestamp, signatures)),
        _ => Err(StripeProviderError::transport(
            "Unable to extract timestamp and signatures from header",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifies_a_v1_signature_and_parses_the_untouched_payload() {
        let payload = serde_json::to_vec(&json!({
            "id": "evt_1",
            "type": "unknown.event",
            "data": { "object": { "raw": true } }
        }))
        .unwrap();
        let timestamp = Utc::now().timestamp();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test").unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(&payload);
        let signature = hex::encode(mac.finalize().into_bytes());
        let event = construct_event(
            &payload,
            &format!("t={timestamp},v0=ignored,v1={signature}"),
            "whsec_test",
        )
        .unwrap();
        assert_eq!(event.event_type, "unknown.event");
        assert_eq!(event.data.object["raw"], true);
    }
}
