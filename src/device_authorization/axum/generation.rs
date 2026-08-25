use rand::RngExt as _;

use crate::device_authorization::{DeviceAuthorizationConfig, MAX_GENERATED_CODE_CHARACTERS};

const DEVICE_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const USER_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(super) async fn device_code(
    config: &DeviceAuthorizationConfig,
) -> Result<String, GenerationError> {
    let code = match &config.generate_device_code {
        Some(generator) => generator
            .generate()
            .await
            .map_err(|_| GenerationError::Failed("device"))?,
        None => random_from(DEVICE_ALPHABET, config.device_code_length),
    };
    validate(code, "device")
}

pub(super) async fn user_code(
    config: &DeviceAuthorizationConfig,
) -> Result<String, GenerationError> {
    let code = match &config.generate_user_code {
        Some(generator) => generator
            .generate()
            .await
            .map_err(|_| GenerationError::Failed("user"))?,
        None => random_from(USER_ALPHABET, config.user_code_length),
    };
    validate(code, "user")
}

fn random_from(alphabet: &[u8], length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| alphabet[rng.random_range(0..alphabet.len())] as char)
        .collect()
}

fn validate(code: String, label: &'static str) -> Result<String, GenerationError> {
    if code.chars().count() > MAX_GENERATED_CODE_CHARACTERS {
        return Err(GenerationError::TooLong(label));
    }
    Ok(code)
}

#[derive(Debug)]
pub(super) enum GenerationError {
    TooLong(&'static str),
    Failed(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn defaults_use_the_pinned_lengths_and_alphabets() {
        let config = DeviceAuthorizationConfig::default();
        let device = device_code(&config).await.unwrap();
        let user = user_code(&config).await.unwrap();
        assert_eq!(device.len(), 40);
        assert_eq!(user.len(), 8);
        assert!(device.bytes().all(|byte| DEVICE_ALPHABET.contains(&byte)));
        assert!(user.bytes().all(|byte| USER_ALPHABET.contains(&byte)));
    }
}
