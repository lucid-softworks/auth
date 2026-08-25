use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

pub(super) fn enrollment_token() -> (String, String) {
    let bytes: [u8; 32] = rand::rng().random();
    let plaintext = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&plaintext);
    (plaintext, hash)
}

pub(super) fn hash_token(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
