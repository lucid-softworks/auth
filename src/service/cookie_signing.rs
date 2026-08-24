use super::{AuthService, HmacSha256};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::Mac as _;

impl AuthService {
    pub fn signed_cookie_value(&self, token: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(token.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        encode_cookie_component(&format!("{token}.{signature}"))
    }

    pub fn verify_cookie_value(&self, value: &str) -> Option<String> {
        let value = decode_cookie_component(value);
        let (token, signature) = value.rsplit_once('.')?;
        let decoded = STANDARD.decode(signature).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.config.secret).ok()?;
        mac.update(token.as_bytes());
        mac.verify_slice(&decoded).ok()?;
        Some(token.to_owned())
    }
}

fn encode_cookie_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn decode_cookie_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(high) = bytes.get(index + 1).and_then(|byte| decode_hex(*byte)) else {
                return value.to_owned();
            };
            let Some(low) = bytes.get(index + 2).and_then(|byte| decode_hex(*byte)) else {
                return value.to_owned();
            };
            decoded.push(high * 16 + low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
