use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn sign_commet_webhook(body: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every length");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn validate_commet_webhook_signature(
    body: &str,
    signature: Option<&str>,
    secret: &str,
) -> bool {
    if body.is_empty() || secret.is_empty() {
        return false;
    }
    let Some(signature) = signature else {
        return false;
    };
    let decoded = decode_node_hex(signature);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every length");
    mac.update(body.as_bytes());
    mac.verify_slice(&decoded).is_ok()
}

/// Matches `Buffer.from(value, "hex")`: decoding stops at the first invalid
/// pair and ignores a final unpaired nibble.
fn decode_node_hex(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map_while(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "{\"event\":\"payment.received\"}";
    const SECRET: &str = "commet test secret";

    #[test]
    fn signs_the_untouched_utf8_body() {
        assert_eq!(
            sign_commet_webhook(BODY, SECRET),
            "f2eae3d846aff820289dc40d8bc8c387fba3e2e33b34f70051f8afa10a518fa7"
        );
        assert_ne!(
            sign_commet_webhook("{\"event\": \"payment.received\"}", SECRET),
            sign_commet_webhook(BODY, SECRET)
        );
    }

    #[test]
    fn node_hex_decoding_accepts_uppercase_and_ignored_trailing_input() {
        let signature = sign_commet_webhook(BODY, SECRET);
        for compatible in [
            signature.to_uppercase(),
            format!("{signature}f"),
            format!("{signature}zz"),
            format!("{signature}z0"),
        ] {
            assert!(validate_commet_webhook_signature(
                BODY,
                Some(&compatible),
                SECRET
            ));
        }
    }

    #[test]
    fn rejects_missing_mismatched_and_wrong_length_signatures() {
        let signature = sign_commet_webhook(BODY, SECRET);
        let too_long = format!("{signature}00");
        for invalid in [
            None,
            Some(""),
            Some("zz"),
            Some(&signature[..62]),
            Some(&too_long),
            Some("0058a68c5b4be5af723365c203856a823ae8ac360bc6bf9f66f9b44b324a2d23"),
        ] {
            assert!(!validate_commet_webhook_signature(BODY, invalid, SECRET));
        }
    }

    #[test]
    fn sdk_verify_rejects_empty_payload_or_secret_before_hmac() {
        let signature = sign_commet_webhook("", SECRET);
        assert!(!validate_commet_webhook_signature(
            "",
            Some(&signature),
            SECRET
        ));
        assert!(!validate_commet_webhook_signature(BODY, Some("00"), ""));
    }
}
