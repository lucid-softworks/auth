use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn decode_webhook_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn sign_webhook_text(payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn validate_webhook_signature(payload: &str, signature: Option<&str>, secret: &str) -> bool {
    let Some(signature) = signature else {
        return false;
    };
    constant_time_equal(
        sign_webhook_text(payload, secret).as_bytes(),
        signature.as_bytes(),
    )
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_the_utf8_encoding_of_the_decoded_text_as_lowercase_hex() {
        let payload = "Creem £ café 🦀";
        assert_eq!(
            sign_webhook_text(payload, "whsec_test"),
            "00a36dfa61a06adbdfb9afa911189d87d070d229e9340bffb63fdf791d8ceb2f"
        );
        assert!(validate_webhook_signature(
            payload,
            Some("00a36dfa61a06adbdfb9afa911189d87d070d229e9340bffb63fdf791d8ceb2f"),
            "whsec_test"
        ));
        assert!(!validate_webhook_signature(payload, None, "whsec_test"));
        assert!(!validate_webhook_signature(
            payload,
            Some("E3329F"),
            "whsec_test"
        ));
    }

    #[test]
    fn invalid_utf8_is_replaced_before_signing_like_request_text() {
        let text = decode_webhook_text(b"a\xFFb");
        assert_eq!(text, "a\u{fffd}b");
        assert_ne!(
            sign_webhook_text(&text, "secret"),
            sign_webhook_text("ab", "secret")
        );
    }
}
